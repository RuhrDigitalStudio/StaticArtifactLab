using System.Text;
using StaticArtifactLab.Core;

namespace StaticArtifactLab.Tests;

public sealed class AnalyzerTests
{
    [Fact]
    public async Task ProveFile_RecordsDigestSelectorAndCompleteCoverage()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("hello.txt", Encoding.UTF8.GetBytes("hello evidence\n"));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        var artifact = Assert.Single(result.Artifacts);
        Assert.Equal("static-artifact-case/v2", result.Schema);
        Assert.Equal(ArtifactKind.Text, artifact.Kind);
        Assert.Equal(0, artifact.Depth);
        Assert.Equal("root", artifact.Selector.Kind);
        Assert.Equal(64, artifact.Sha256.Length);
        Assert.Equal(CaseStatus.Complete, result.Status);
        Assert.Contains(result.Coverage, x => x.Status == CoverageStatus.Analyzed);
    }

    [Fact]
    public async Task ProveDirectory_IsOrdinalAndSkipsSymbolicLinks()
    {
        using var temp = TestData.Temp();
        temp.Write("z.txt", Encoding.UTF8.GetBytes("zulu text"));
        temp.Write("a.txt", Encoding.UTF8.GetBytes("alpha text"));

        var result = await ArtifactAnalyzer.ProveAsync(temp.Path);

        Assert.Equal(["a.txt", "z.txt"], result.Artifacts.Select(x => x.LogicalPath));
    }

    [Fact]
    public async Task OversizedRoot_IsRejectedAndCaseIsPartial()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("large.bin", new byte[20]);
        var options = new AnalysisOptions { Limits = AnalysisLimits.Default with { MaxRootBytes = 10 } };

        var result = await ArtifactAnalyzer.ProveAsync(path, options);

        Assert.Empty(result.Artifacts);
        Assert.Equal(CaseStatus.Partial, result.Status);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.RootTooLarge);
    }

    [Fact]
    public async Task NonFiniteExpansionLimit_IsRejected()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("sample.bin", [1, 2, 3]);
        var options = new AnalysisOptions
        {
            Limits = AnalysisLimits.Default with { MaxExpansionRatio = double.PositiveInfinity },
        };

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => ArtifactAnalyzer.ProveAsync(path, options));
    }

    [Fact]
    public async Task UncInput_IsRejectedBeforeFilesystemAccess()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            ArtifactAnalyzer.ProveAsync(@"\\example.invalid\share\sample.zip"));

        Assert.Contains("network", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RootSymbolicLink_IsNotFollowedWhenPlatformAllowsCreation()
    {
        using var temp = TestData.Temp();
        var target = temp.Write("target.txt", Encoding.UTF8.GetBytes("linked evidence"));
        var link = Path.Combine(temp.Path, "root-link.txt");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        var result = await ArtifactAnalyzer.ProveAsync(link);

        Assert.Empty(result.Artifacts);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.SymbolicLink);
        Assert.Equal(CaseStatus.Partial, result.Status);
    }

    [Fact]
    public async Task DirectoryTraversal_StopsAtArtifactBudget()
    {
        using var temp = TestData.Temp();
        temp.Write("a.txt", Encoding.UTF8.GetBytes("alpha"));
        temp.Write("b.txt", Encoding.UTF8.GetBytes("bravo"));
        temp.Write("c.txt", Encoding.UTF8.GetBytes("charlie"));
        var options = new AnalysisOptions { Limits = AnalysisLimits.Default with { MaxArtifacts = 2 } };

        var result = await ArtifactAnalyzer.ProveAsync(temp.Path, options);

        Assert.Equal(2, result.Artifacts.Count);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.ArtifactLimit);
        Assert.Equal(CaseStatus.Partial, result.Status);
    }

    [Fact]
    public async Task DirectoryTraversal_StopsAtFilesystemNodeBudget()
    {
        using var temp = TestData.Temp();
        temp.Write("a.txt", Encoding.UTF8.GetBytes("alpha"));
        temp.Write("b.txt", Encoding.UTF8.GetBytes("bravo"));
        var options = new AnalysisOptions { Limits = AnalysisLimits.Default with { MaxFilesystemNodes = 2 } };

        var result = await ArtifactAnalyzer.ProveAsync(temp.Path, options);

        Assert.Single(result.Artifacts);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.FilesystemNodeLimit);
        Assert.Equal(CaseStatus.Partial, result.Status);
    }

    [Fact]
    public async Task ZipChild_IsBoundToParentAndSelector()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("bundle.zip", TestData.Zip(("docs/readme.txt", Encoding.UTF8.GetBytes("hello nested evidence"))));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        Assert.Equal(2, result.Artifacts.Count);
        var root = result.Artifacts[0];
        var child = result.Artifacts[1];
        Assert.Equal(root.Id, child.ParentId);
        Assert.Equal(root.Sha256, child.Selector.ParentSha256);
        Assert.Equal("zip-entry", child.Selector.Kind);
        Assert.Equal(0, child.Selector.EntryIndex);
        Assert.Equal("docs/readme.txt", child.Selector.EntryName);
        Assert.Equal("bundle.zip!/docs/readme.txt", child.LogicalPath);
    }

    [Fact]
    public async Task NestedZip_IsTraversedRecursively()
    {
        using var temp = TestData.Temp();
        var inner = TestData.Zip(("payload.txt", Encoding.UTF8.GetBytes("nested payload")));
        var path = temp.Write("outer.zip", TestData.Zip(("inner.zip", inner)));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        Assert.Equal(3, result.Artifacts.Count);
        Assert.Equal(2, result.Artifacts[^1].Depth);
        Assert.Equal("outer.zip!/inner.zip!/payload.txt", result.Artifacts[^1].LogicalPath);
    }

    [Theory]
    [InlineData("../escape.txt")]
    [InlineData("/absolute.txt")]
    [InlineData("C:/absolute.txt")]
    public async Task UnsafeArchivePath_IsReportedAndNotAccepted(string entryName)
    {
        using var temp = TestData.Temp();
        var path = temp.Write("unsafe.zip", TestData.Zip((entryName, Encoding.UTF8.GetBytes("bad path"))));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        Assert.Single(result.Artifacts);
        Assert.Contains(result.Findings, x => x.RuleId == RuleIds.ArchivePathTraversal);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.UnsafeEntryPath);
        Assert.Equal(CaseStatus.Partial, result.Status);
    }

    [Fact]
    public async Task ArchiveEntryLimit_IsVisibleInCoverage()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("many.zip", TestData.Zip(
            ("1.txt", Encoding.UTF8.GetBytes("one")),
            ("2.txt", Encoding.UTF8.GetBytes("two"))));
        var options = new AnalysisOptions { Limits = AnalysisLimits.Default with { MaxEntriesPerArchive = 1 } };

        var result = await ArtifactAnalyzer.ProveAsync(path, options);

        Assert.Equal(2, result.Artifacts.Count);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.EntryLimit);
        Assert.Equal(CaseStatus.Partial, result.Status);
    }

    [Fact]
    public async Task ExpansionRatioLimit_RejectsHighlyCompressedEntry()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("ratio.zip", TestData.Zip(("zeros.bin", new byte[64 * 1024])));
        var options = new AnalysisOptions { Limits = AnalysisLimits.Default with { MaxExpansionRatio = 2 } };

        var result = await ArtifactAnalyzer.ProveAsync(path, options);

        Assert.Single(result.Artifacts);
        Assert.Contains(result.Findings, x => x.RuleId == RuleIds.ExcessiveExpansion);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.ExpansionRatio);
    }

    [Fact]
    public async Task DepthLimit_DoesNotHideSkippedNestedWork()
    {
        using var temp = TestData.Temp();
        var inner = TestData.Zip(("payload.txt", Encoding.UTF8.GetBytes("nested payload")));
        var path = temp.Write("outer.zip", TestData.Zip(("inner.zip", inner)));
        var options = new AnalysisOptions { Limits = AnalysisLimits.Default with { MaxDepth = 1 } };

        var result = await ArtifactAnalyzer.ProveAsync(path, options);

        Assert.Equal(2, result.Artifacts.Count);
        Assert.Contains(result.Coverage, x => x.Reason == CoverageReason.DepthLimit);
        Assert.Equal(CaseStatus.Partial, result.Status);
    }

    [Fact]
    public async Task NestedExecutableAndExtensionMismatch_AreObservations()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("package.zip", TestData.Zip(("photo.txt", [0x4d, 0x5a, 0, 0, 0, 0])));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        Assert.Contains(result.Findings, x => x.RuleId == RuleIds.NestedExecutable);
        Assert.Contains(result.Findings, x => x.RuleId == RuleIds.ExtensionMismatch);
    }

    [Fact]
    public async Task DuplicateContent_IsReportedOnSecondSelector()
    {
        using var temp = TestData.Temp();
        var same = Encoding.UTF8.GetBytes("same content in two entries");
        var path = temp.Write("duplicates.zip", TestData.Zip(("a.txt", same), ("b.txt", same)));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        Assert.Contains(result.Findings, x => x.RuleId == RuleIds.DuplicateContent);
    }

    [Fact]
    public async Task OpaqueHighEntropyData_IsReported()
    {
        using var temp = TestData.Temp();
        var random = new byte[4096];
        new Random(42).NextBytes(random);
        var path = temp.Write("random.bin", random);

        var result = await ArtifactAnalyzer.ProveAsync(path);

        Assert.Contains(result.Findings, x => x.RuleId == RuleIds.HighEntropyOpaque);
    }

    [Fact]
    public async Task PngTrailingBytes_AreMeasured()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("image.png", TestData.MinimalPng(trailingBytes: 7));

        var result = await ArtifactAnalyzer.ProveAsync(path);

        var finding = Assert.Single(result.Findings, x => x.RuleId == RuleIds.PngTrailingData);
        Assert.Equal("7", finding.Evidence["trailingBytes"]);
    }
}
