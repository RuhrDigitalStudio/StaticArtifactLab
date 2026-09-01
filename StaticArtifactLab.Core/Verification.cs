using System.IO.Compression;
using System.Security.Cryptography;

namespace StaticArtifactLab.Core;

public sealed class CaseVerifier
{
    public static async Task<VerificationResult> VerifyAsync(CaseDocument document, VerificationOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        options ??= new VerificationOptions();
        var errors = new List<VerificationIssue>();
        if (!string.Equals(document.Schema, "static-artifact-case/v2", StringComparison.Ordinal))
            errors.Add(new("unsupported-schema", $"Unsupported schema '{document.Schema}'."));

        var byId = new Dictionary<string, ArtifactRecord>(StringComparer.Ordinal);
        foreach (var artifact in document.Artifacts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!byId.TryAdd(artifact.Id, artifact))
                errors.Add(new("duplicate-id", "The artifact ID occurs more than once.", artifact.Id));
            if (!IsSha256(artifact.Sha256))
                errors.Add(new("invalid-digest", "The artifact SHA-256 is not 64 lowercase hexadecimal characters.", artifact.Id));

            var expectedId = ArtifactIdentity.Create(artifact.ParentId, artifact.Selector, artifact.Length, artifact.Sha256);
            if (!string.Equals(expectedId, artifact.Id, StringComparison.Ordinal))
                errors.Add(new("identity-mismatch", "The artifact ID does not match its canonical evidence tuple.", artifact.Id));

            if (artifact.ParentId is not null)
            {
                if (artifact.Selector.Kind != "zip-entry" || artifact.Selector.EntryIndex is null or < 0 || artifact.Selector.EntryName is null)
                    errors.Add(new("invalid-selector", "A nested artifact requires a complete ZIP-entry selector.", artifact.Id));
                if (!byId.TryGetValue(artifact.ParentId, out var parent))
                    errors.Add(new("missing-parent", "The parent artifact is absent or appears after its child.", artifact.Id));
                else
                {
                    if (artifact.Depth != parent.Depth + 1)
                        errors.Add(new("invalid-depth", "Child depth is not parent depth plus one.", artifact.Id));
                    if (!string.Equals(artifact.Selector.ParentSha256, parent.Sha256, StringComparison.Ordinal))
                        errors.Add(new("parent-digest-mismatch", "The selector is not bound to the recorded parent digest.", artifact.Id));
                }
            }
            else if (artifact.Depth != 0)
            {
                errors.Add(new("invalid-root-depth", "A root artifact must have depth zero.", artifact.Id));
            }
            else if (artifact.Selector.Kind != "root" || artifact.Selector.RootIndex is null or < 0 || artifact.Selector.RootName is null)
            {
                errors.Add(new("invalid-selector", "A root artifact requires a complete root selector.", artifact.Id));
            }
        }

        foreach (var finding in document.Findings)
        {
            if (!byId.ContainsKey(finding.ArtifactId))
                errors.Add(new("dangling-finding", "A finding references an artifact that is not present.", finding.ArtifactId));
        }

        foreach (var coverage in document.Coverage)
        {
            if (coverage.ArtifactId is not null && !byId.ContainsKey(coverage.ArtifactId))
                errors.Add(new("dangling-coverage", "A coverage record references an artifact that is not present.", coverage.ArtifactId));
        }

        var expectedStatus = document.Coverage.Any(x => x.Status is CoverageStatus.Skipped or CoverageStatus.Rejected)
            ? CaseStatus.Partial
            : CaseStatus.Complete;
        if (document.Status != expectedStatus)
            errors.Add(new("case-status-mismatch", $"Case status is {document.Status}, but coverage requires {expectedStatus}."));

        if (!AnalysisLimitPolicy.IsValid(document.Limits))
            errors.Add(new("invalid-limits", "One or more recorded analysis limits are outside the accepted range."));

        if (!options.VerifySourceBytes)
            return new VerificationResult(errors.Count == 0, 0, document.Artifacts.Count, errors);

        var verified = 0;
        var unverified = 0;
        var bytesById = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var artifact in document.Artifacts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[]? bytes = null;
            if (artifact.ParentId is null && artifact.Selector.Kind == "root")
            {
                var path = artifact.Selector.SourcePath;
                if (path is not null && PathSafety.IsNetworkPath(path))
                {
                    errors.Add(new("network-source-path", "Network and UNC source paths are not permitted.", artifact.Id));
                    unverified++;
                    continue;
                }

                bool withinInput;
                try
                {
                    withinInput = path is null || PathSafety.IsWithinRecordedInput(document.InputPath, path);
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException)
                {
                    errors.Add(new("invalid-source-path", "The recorded input or source path is invalid.", artifact.Id));
                    unverified++;
                    continue;
                }

                if (!withinInput)
                {
                    errors.Add(new("source-outside-input", "The source path is outside the recorded input boundary.", artifact.Id));
                    unverified++;
                    continue;
                }

                if (path is not null && File.Exists(path))
                {
                    try
                    {
                        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                        {
                            errors.Add(new("source-reparse-point", "A source symbolic link or reparse point is not followed.", artifact.Id));
                            unverified++;
                            continue;
                        }

                        var info = new FileInfo(path);
                        if (info.Length <= document.Limits.MaxRootBytes)
                            bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
                        else
                            errors.Add(new("source-over-limit", "The root source now exceeds the recorded read limit.", artifact.Id));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        errors.Add(new("source-read-failed", ex.Message, artifact.Id));
                    }
                }
            }
            else if (artifact.ParentId is not null && artifact.Selector.Kind == "zip-entry" && bytesById.TryGetValue(artifact.ParentId, out var parentBytes))
            {
                var selected = await ReadZipEntryAsync(parentBytes, artifact.Selector, document.Limits.MaxArtifactBytes, cancellationToken).ConfigureAwait(false);
                if (!selected.Resolved)
                {
                    errors.Add(new("selector-resolution-failed", "The child selector cannot be resolved against the available parent bytes.", artifact.Id));
                    unverified++;
                    continue;
                }

                bytes = selected.Bytes;
            }

            if (bytes is null)
            {
                unverified++;
                continue;
            }

            var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (bytes.LongLength != artifact.Length || !string.Equals(digest, artifact.Sha256, StringComparison.Ordinal))
            {
                errors.Add(new("source-digest-mismatch", "Available source bytes do not match the recorded length and SHA-256.", artifact.Id));
                unverified++;
                continue;
            }

            bytesById[artifact.Id] = bytes;
            verified++;
        }

        return new VerificationResult(errors.Count == 0, verified, unverified, errors);
    }

    private static async Task<SelectorReadResult> ReadZipEntryAsync(byte[] parentBytes, EvidenceSelector selector, long limit, CancellationToken cancellationToken)
    {
        if (selector.EntryIndex is null || selector.EntryName is null)
            return new(false, null);
        try
        {
            using var input = new MemoryStream(parentBytes, writable: false);
            using var archive = new ZipArchive(input, ZipArchiveMode.Read);
            if (selector.EntryIndex < 0 || selector.EntryIndex >= archive.Entries.Count)
                return new(false, null);
            var entry = archive.Entries[selector.EntryIndex.Value];
            if (!string.Equals(entry.FullName.Replace('\\', '/'), selector.EntryName, StringComparison.Ordinal) || entry.Length > limit)
                return new(false, null);
            await using var stream = entry.Open();
            var bytes = await ArtifactAnalyzer.ReadBoundedAsync(stream, limit, cancellationToken).ConfigureAwait(false);
            return new(true, bytes);
        }
        catch (InvalidDataException)
        {
            return new(false, null);
        }
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private sealed record SelectorReadResult(bool Resolved, byte[]? Bytes);
}

public sealed class CaseReplayer
{
    public static async Task<ReplayResult> ReplayAsync(CaseDocument original, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(original);
        if (string.IsNullOrWhiteSpace(original.InputPath))
            throw new InvalidDataException("The case does not record an input path for replay.");
        if (PathSafety.IsNetworkPath(original.InputPath))
            throw new InvalidDataException("Network and UNC input paths cannot be replayed.");

        var replayed = await ArtifactAnalyzer.ProveAsync(original.InputPath, new AnalysisOptions { Limits = original.Limits }, cancellationToken).ConfigureAwait(false);
        var oldArtifacts = original.Artifacts.ToDictionary(x => x.LogicalPath, StringComparer.Ordinal);
        var newArtifacts = replayed.Artifacts.ToDictionary(x => x.LogicalPath, StringComparer.Ordinal);
        var added = newArtifacts.Keys.Except(oldArtifacts.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var removed = oldArtifacts.Keys.Except(newArtifacts.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var changed = oldArtifacts.Keys.Intersect(newArtifacts.Keys, StringComparer.Ordinal)
            .Where(path => !string.Equals(oldArtifacts[path].Sha256, newArtifacts[path].Sha256, StringComparison.Ordinal) ||
                           !string.Equals(oldArtifacts[path].Selector.CanonicalValue(), newArtifacts[path].Selector.CanonicalValue(), StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        return new ReplayResult(added.Length == 0 && removed.Length == 0 && changed.Length == 0, added, removed, changed, replayed);
    }
}
