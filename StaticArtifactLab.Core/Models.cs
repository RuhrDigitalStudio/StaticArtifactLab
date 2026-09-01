using System.Security.Cryptography;
using System.Text;

namespace StaticArtifactLab.Core;

public enum ArtifactKind
{
    Unknown,
    Text,
    Json,
    Xml,
    PowerShell,
    PortableExecutable,
    Elf,
    MachO,
    Zip,
    SevenZip,
    Rar,
    Gzip,
    Pdf,
    Png,
    OleCompound,
}

public enum CaseStatus
{
    Complete,
    Partial,
}

public enum FindingLevel
{
    Note,
    Warning,
    Error,
}

public enum CoverageStatus
{
    Analyzed,
    Skipped,
    Rejected,
}

public enum CoverageReason
{
    None,
    RootTooLarge,
    ArtifactTooLarge,
    TotalByteLimit,
    ArtifactLimit,
    FindingLimit,
    EntryLimit,
    DepthLimit,
    ExpansionRatio,
    UnsafeEntryPath,
    SymbolicLink,
    UnsupportedContainer,
    MalformedContainer,
    UnreadableInput,
}

public static class RuleIds
{
    public const string ExtensionMismatch = "SAL001";
    public const string NestedExecutable = "SAL002";
    public const string ArchivePathTraversal = "SAL003";
    public const string ExcessiveExpansion = "SAL004";
    public const string DuplicateContent = "SAL005";
    public const string HighEntropyOpaque = "SAL006";
    public const string PngTrailingData = "SAL007";
    public const string UnsupportedContainer = "SAL008";
}

public sealed record AnalysisLimits
{
    public static AnalysisLimits Default { get; } = new();

    public long MaxRootBytes { get; init; } = 100L * 1024 * 1024;
    public long MaxArtifactBytes { get; init; } = 100L * 1024 * 1024;
    public long MaxTotalExpandedBytes { get; init; } = 512L * 1024 * 1024;
    public int MaxArtifacts { get; init; } = 5_000;
    public int MaxEntriesPerArchive { get; init; } = 1_000;
    public int MaxDepth { get; init; } = 8;
    public double MaxExpansionRatio { get; init; } = 200;
    public int MaxFindings { get; init; } = 2_000;
}

public sealed record AnalysisOptions
{
    public AnalysisLimits Limits { get; init; } = AnalysisLimits.Default;
}

public sealed record ToolIdentity(
    string Name,
    string Version,
    string RuleSetVersion,
    string Worker);

public sealed record EvidenceSelector
{
    public string Kind { get; init; } = string.Empty;
    public int? RootIndex { get; init; }
    public string? RootName { get; init; }
    public string? SourcePath { get; init; }
    public int? EntryIndex { get; init; }
    public string? EntryName { get; init; }
    public string? ParentSha256 { get; init; }

    public static EvidenceSelector Root(string name, int index, string? sourcePath = null) => new()
    {
        Kind = "root",
        RootIndex = index,
        RootName = name,
        SourcePath = sourcePath,
    };

    public static EvidenceSelector ZipEntry(int index, string name, string parentSha256) => new()
    {
        Kind = "zip-entry",
        EntryIndex = index,
        EntryName = name,
        ParentSha256 = parentSha256,
    };

    public string CanonicalValue() => Kind switch
    {
        "root" => $"root:{RootIndex}:{Escape(RootName)}",
        "zip-entry" => $"zip-entry:{EntryIndex}:{Escape(EntryName)}:{ParentSha256}",
        _ => $"unknown:{Escape(Kind)}",
    };

    private static string Escape(string? value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? string.Empty));
}

public static class ArtifactIdentity
{
    public static string Create(string? parentId, EvidenceSelector selector, long length, string sha256)
    {
        var canonical = string.Join('\n', parentId ?? "root", selector.CanonicalValue(), length.ToString(System.Globalization.CultureInfo.InvariantCulture), sha256);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(digest).ToLowerInvariant()[..24];
    }
}

public sealed record ArtifactRecord
{
    public string Id { get; init; } = string.Empty;
    public string? ParentId { get; init; }
    public int Depth { get; init; }
    public string Name { get; init; } = string.Empty;
    public string LogicalPath { get; init; } = string.Empty;
    public ArtifactKind Kind { get; init; }
    public string MediaType { get; init; } = "application/octet-stream";
    public string Extension { get; init; } = string.Empty;
    public long Length { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public double Entropy { get; init; }
    public bool IsContainer { get; init; }
    public EvidenceSelector Selector { get; init; } = new();
    public SortedDictionary<string, string> Metadata { get; init; } = new(StringComparer.Ordinal);
}

public sealed record FindingRecord
{
    public string RuleId { get; init; } = string.Empty;
    public FindingLevel Level { get; init; }
    public string ArtifactId { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public SortedDictionary<string, string> Evidence { get; init; } = new(StringComparer.Ordinal);
}

public sealed record CoverageRecord
{
    public string? ArtifactId { get; init; }
    public string LogicalPath { get; init; } = string.Empty;
    public string Operation { get; init; } = string.Empty;
    public CoverageStatus Status { get; init; }
    public CoverageReason Reason { get; init; }
    public string Detail { get; init; } = string.Empty;
}

public sealed class CaseDocument
{
    public string Schema { get; set; } = "static-artifact-case/v2";
    public ToolIdentity Tool { get; set; } = new("StaticArtifactLab", "1.0.0-rc.1", "2026.09.01", "sal-worker-v1");
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string InputPath { get; set; } = string.Empty;
    public AnalysisLimits Limits { get; set; } = AnalysisLimits.Default;
    public CaseStatus Status { get; set; } = CaseStatus.Complete;
    public List<ArtifactRecord> Artifacts { get; set; } = [];
    public List<FindingRecord> Findings { get; set; } = [];
    public List<CoverageRecord> Coverage { get; set; } = [];
}

public sealed record FormatMatch(ArtifactKind Kind, string MediaType, bool IsContainer);

public sealed record VerificationIssue(string Code, string Message, string? ArtifactId = null);

public sealed record VerificationResult(
    bool IsValid,
    int VerifiedArtifacts,
    int UnverifiedArtifacts,
    IReadOnlyList<VerificationIssue> Errors);

public sealed record ReplayResult(
    bool IsMatch,
    IReadOnlyList<string> Added,
    IReadOnlyList<string> Removed,
    IReadOnlyList<string> Changed,
    CaseDocument ReplayedCase);
