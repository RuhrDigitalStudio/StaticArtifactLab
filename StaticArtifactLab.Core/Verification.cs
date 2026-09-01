using System.IO.Compression;
using System.Security.Cryptography;

namespace StaticArtifactLab.Core;

public sealed class CaseVerifier
{
    public static async Task<VerificationResult> VerifyAsync(CaseDocument document, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
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
        }

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
                if (path is not null && File.Exists(path))
                {
                    var info = new FileInfo(path);
                    if (info.Length <= document.Limits.MaxRootBytes)
                        bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
                    else
                        errors.Add(new("source-over-limit", "The root source now exceeds the recorded read limit.", artifact.Id));
                }
            }
            else if (artifact.ParentId is not null && artifact.Selector.Kind == "zip-entry" && bytesById.TryGetValue(artifact.ParentId, out var parentBytes))
            {
                bytes = await ReadZipEntryAsync(parentBytes, artifact.Selector, document.Limits.MaxArtifactBytes, cancellationToken).ConfigureAwait(false);
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
                continue;
            }

            bytesById[artifact.Id] = bytes;
            verified++;
        }

        return new VerificationResult(errors.Count == 0, verified, unverified, errors);
    }

    private static async Task<byte[]?> ReadZipEntryAsync(byte[] parentBytes, EvidenceSelector selector, long limit, CancellationToken cancellationToken)
    {
        if (selector.EntryIndex is null || selector.EntryName is null)
            return null;
        try
        {
            using var input = new MemoryStream(parentBytes, writable: false);
            using var archive = new ZipArchive(input, ZipArchiveMode.Read);
            if (selector.EntryIndex < 0 || selector.EntryIndex >= archive.Entries.Count)
                return null;
            var entry = archive.Entries[selector.EntryIndex.Value];
            if (!string.Equals(entry.FullName.Replace('\\', '/'), selector.EntryName, StringComparison.Ordinal) || entry.Length > limit)
                return null;
            await using var stream = entry.Open();
            return await ArtifactAnalyzer.ReadBoundedAsync(stream, limit, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public sealed class CaseReplayer
{
    public static async Task<ReplayResult> ReplayAsync(CaseDocument original, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(original);
        if (string.IsNullOrWhiteSpace(original.InputPath))
            throw new InvalidDataException("The case does not record an input path for replay.");

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
