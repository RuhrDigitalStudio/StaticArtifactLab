using System.Text;
using System.Text.Json;
using StaticArtifactLab.Core;

namespace StaticArtifactLab.Tests;

public sealed class ReportsVerificationReplayTests
{
    [Fact]
    public async Task Json_RoundTripsConcreteCaseAndUsesStableSchema()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("sample.txt", Encoding.UTF8.GetBytes("stable evidence"));
        var original = await ArtifactAnalyzer.ProveAsync(path);

        var json = CaseJson.Serialize(original);
        var restored = CaseJson.Deserialize(json);

        Assert.Equal(original.Schema, restored.Schema);
        Assert.Equal(original.Artifacts[0].Sha256, restored.Artifacts[0].Sha256);
        Assert.StartsWith("{\n  \"schema\": \"static-artifact-case/v2\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Html_EncodesUntrustedNamesAndContainsNoActiveScript()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("report-name.txt", Encoding.UTF8.GetBytes("safe body"));
        var document = await ArtifactAnalyzer.ProveAsync(path);
        document.Artifacts[0] = document.Artifacts[0] with
        {
            Name = "<script>alert(1)</script>.txt",
            LogicalPath = "<script>alert(1)</script>.txt",
        };

        var html = HtmlReportWriter.Write(document);

        Assert.DoesNotContain("<script>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("Content-Security-Policy", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sarif_MapsFindingsAndArtifactLocations()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("wrong.txt", [0x4d, 0x5a, 0, 0]);
        var document = await ArtifactAnalyzer.ProveAsync(path);

        var sarif = SarifReportWriter.Write(document);
        using var parsed = JsonDocument.Parse(sarif);

        Assert.Equal("2.1.0", parsed.RootElement.GetProperty("version").GetString());
        Assert.Contains("sarif-2.1.0", parsed.RootElement.GetProperty("$schema").GetString(), StringComparison.Ordinal);
        var run = parsed.RootElement.GetProperty("runs")[0];
        Assert.Contains(run.GetProperty("results").EnumerateArray(), x =>
            x.GetProperty("ruleId").GetString() == RuleIds.ExtensionMismatch);
    }

    [Fact]
    public async Task Verify_AcceptsUntamperedCaseAndAvailableSource()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("bundle.zip", TestData.Zip(("readme.txt", Encoding.UTF8.GetBytes("verified child"))));
        var document = await ArtifactAnalyzer.ProveAsync(path);

        var result = await CaseVerifier.VerifyAsync(document);

        Assert.True(result.IsValid);
        Assert.Equal(2, result.VerifiedArtifacts);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task Verify_RejectsTamperedIdentityAndMissingParent()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("sample.txt", Encoding.UTF8.GetBytes("evidence"));
        var document = await ArtifactAnalyzer.ProveAsync(path);
        var artifact = document.Artifacts[0];
        document.Artifacts[0] = artifact with { Id = "000000000000000000000000", ParentId = "missing" };

        var result = await CaseVerifier.VerifyAsync(document);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, x => x.Code == "identity-mismatch");
        Assert.Contains(result.Errors, x => x.Code == "missing-parent");
    }

    [Fact]
    public async Task Verify_RejectsChangedRootBytes()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("sample.txt", Encoding.UTF8.GetBytes("original"));
        var document = await ArtifactAnalyzer.ProveAsync(path);
        File.WriteAllText(path, "changed");

        var result = await CaseVerifier.VerifyAsync(document);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, x => x.Code == "source-digest-mismatch");
    }

    [Fact]
    public async Task Replay_MatchesStableInputAndReportsChangedEvidence()
    {
        using var temp = TestData.Temp();
        var path = temp.Write("sample.txt", Encoding.UTF8.GetBytes("original"));
        var document = await ArtifactAnalyzer.ProveAsync(path);

        var matching = await CaseReplayer.ReplayAsync(document);
        File.WriteAllText(path, "changed");
        var changed = await CaseReplayer.ReplayAsync(document);

        Assert.True(matching.IsMatch);
        Assert.False(changed.IsMatch);
        Assert.NotEmpty(changed.Changed);
    }

    [Fact]
    public void Deserialize_RejectsUnknownSchema()
    {
        var error = Assert.Throws<InvalidDataException>(() =>
            CaseJson.Deserialize("{\"schema\":\"future/v9\"}"));

        Assert.Contains("schema", error.Message, StringComparison.OrdinalIgnoreCase);
    }
}
