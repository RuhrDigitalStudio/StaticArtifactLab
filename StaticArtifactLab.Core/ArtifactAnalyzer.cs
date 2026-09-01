using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;

namespace StaticArtifactLab.Core;

public sealed class ArtifactAnalyzer
{
    private const int CopyBufferSize = 64 * 1024;

    public static async Task<CaseDocument> ProveAsync(string inputPath, AnalysisOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        options ??= new AnalysisOptions();
        ValidateLimits(options.Limits);

        var fullPath = Path.GetFullPath(inputPath);
        if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
            throw new FileNotFoundException("The input file or directory does not exist.", fullPath);

        var document = new CaseDocument
        {
            InputPath = fullPath,
            Limits = options.Limits,
        };
        var state = new AnalysisState(document, cancellationToken);

        if (File.Exists(fullPath))
        {
            await AnalyzeRootAsync(fullPath, Path.GetFileName(fullPath), 0, state).ConfigureAwait(false);
        }
        else
        {
            var rootIndex = 0;
            foreach (var file in EnumerateFilesSafely(fullPath, state))
            {
                var relative = Path.GetRelativePath(fullPath, file).Replace('\\', '/');
                if (rootIndex >= document.Limits.MaxArtifacts || document.Artifacts.Count >= document.Limits.MaxArtifacts)
                {
                    state.Coverage(null, relative, "enumerate-roots", CoverageStatus.Skipped, CoverageReason.ArtifactLimit,
                        "Directory traversal stopped at the artifact budget.");
                    break;
                }

                await AnalyzeRootAsync(file, relative, rootIndex, state).ConfigureAwait(false);
                rootIndex++;
            }
        }

        AddDuplicateFindings(state);
        document.Status = document.Coverage.Any(x => x.Status is CoverageStatus.Skipped or CoverageStatus.Rejected)
            ? CaseStatus.Partial
            : CaseStatus.Complete;
        return document;
    }

    private static IEnumerable<string> EnumerateFilesSafely(string root, AnalysisState state)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        state.VisitedFilesystemNodes = 1;
        while (pending.Count > 0)
        {
            state.CancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            var files = new List<string>();
            var directories = new List<string>();
            var limitReached = false;
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (state.VisitedFilesystemNodes >= state.Document.Limits.MaxFilesystemNodes)
                    {
                        limitReached = true;
                        break;
                    }

                    state.VisitedFilesystemNodes++;
                    if ((File.GetAttributes(entry) & FileAttributes.Directory) != 0)
                        directories.Add(entry);
                    else
                        files.Add(entry);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                state.Coverage(null, Path.GetRelativePath(root, directory), "enumerate", CoverageStatus.Skipped, CoverageReason.UnreadableInput, ex.Message);
                continue;
            }
            catch (IOException ex)
            {
                state.Coverage(null, Path.GetRelativePath(root, directory), "enumerate", CoverageStatus.Skipped, CoverageReason.UnreadableInput, ex.Message);
                continue;
            }

            foreach (var file in files.Order(StringComparer.Ordinal))
            {
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                {
                    state.Coverage(null, Path.GetRelativePath(root, file), "enumerate", CoverageStatus.Skipped, CoverageReason.SymbolicLink, "Symbolic links and reparse points are not followed.");
                    continue;
                }

                yield return file;
            }

            if (limitReached)
            {
                state.Coverage(null, Path.GetRelativePath(root, directory), "enumerate", CoverageStatus.Skipped, CoverageReason.FilesystemNodeLimit,
                    $"Filesystem traversal stopped after {state.Document.Limits.MaxFilesystemNodes} nodes.");
                yield break;
            }

            foreach (var child in directories.OrderDescending(StringComparer.Ordinal))
            {
                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0)
                {
                    state.Coverage(null, Path.GetRelativePath(root, child), "enumerate", CoverageStatus.Skipped, CoverageReason.SymbolicLink, "Symbolic links and reparse points are not followed.");
                    continue;
                }

                pending.Push(child);
            }
        }
    }

    private static async Task AnalyzeRootAsync(string path, string logicalPath, int rootIndex, AnalysisState state)
    {
        state.CancellationToken.ThrowIfCancellationRequested();
        var info = new FileInfo(path);
        if (info.Length > state.Document.Limits.MaxRootBytes)
        {
            state.Coverage(null, logicalPath, "read-root", CoverageStatus.Rejected, CoverageReason.RootTooLarge,
                $"Declared length {info.Length} exceeds {state.Document.Limits.MaxRootBytes} bytes.");
            return;
        }

        if (!state.CanAcceptBytes(info.Length))
        {
            state.Coverage(null, logicalPath, "read-root", CoverageStatus.Rejected, CoverageReason.TotalByteLimit, "The total expanded-byte budget is exhausted.");
            return;
        }

        byte[] bytes;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
            bytes = await ReadBoundedAsync(stream, state.Document.Limits.MaxRootBytes, state.CancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            state.Coverage(null, logicalPath, "read-root", CoverageStatus.Rejected, CoverageReason.UnreadableInput, ex.Message);
            return;
        }
        catch (UnauthorizedAccessException ex)
        {
            state.Coverage(null, logicalPath, "read-root", CoverageStatus.Rejected, CoverageReason.UnreadableInput, ex.Message);
            return;
        }
        catch (InvalidDataException ex)
        {
            state.Coverage(null, logicalPath, "read-root", CoverageStatus.Rejected, CoverageReason.RootTooLarge, ex.Message);
            return;
        }

        var selector = EvidenceSelector.Root(logicalPath, rootIndex, path);
        await AnalyzeBytesAsync(bytes, Path.GetFileName(path), logicalPath, null, 0, selector, state).ConfigureAwait(false);
    }

    private static async Task AnalyzeBytesAsync(
        byte[] bytes,
        string name,
        string logicalPath,
        ArtifactRecord? parent,
        int depth,
        EvidenceSelector selector,
        AnalysisState state)
    {
        state.CancellationToken.ThrowIfCancellationRequested();
        if (state.Document.Artifacts.Count >= state.Document.Limits.MaxArtifacts)
        {
            state.Coverage(parent?.Id, logicalPath, "accept-artifact", CoverageStatus.Rejected, CoverageReason.ArtifactLimit, "The artifact-count limit is exhausted.");
            return;
        }

        state.TotalBytes += bytes.LongLength;
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var match = FormatRecognizer.Detect(bytes, name);
        var artifact = new ArtifactRecord
        {
            ParentId = parent?.Id,
            Depth = depth,
            Name = name,
            LogicalPath = logicalPath,
            Kind = match.Kind,
            MediaType = match.MediaType,
            Extension = Path.GetExtension(name).ToLowerInvariant(),
            Length = bytes.LongLength,
            Sha256 = sha256,
            Entropy = CalculateEntropy(bytes),
            IsContainer = match.IsContainer,
            Selector = selector,
        };
        artifact = artifact with { Id = ArtifactIdentity.Create(artifact.ParentId, selector, artifact.Length, artifact.Sha256) };
        state.Document.Artifacts.Add(artifact);
        state.Coverage(artifact.Id, logicalPath, "identify", CoverageStatus.Analyzed, CoverageReason.None, $"Detected {artifact.Kind} from bytes.");

        ApplyRules(artifact, bytes, state);

        if (artifact.Kind == ArtifactKind.Zip)
        {
            await AnalyzeZipAsync(artifact, bytes, state).ConfigureAwait(false);
        }
        else if (artifact.IsContainer)
        {
            state.Finding(RuleIds.UnsupportedContainer, FindingLevel.Note, artifact,
                $"{artifact.Kind} is recognized but recursive parsing is not supported in this release.");
            state.Coverage(artifact.Id, logicalPath, "open-container", CoverageStatus.Skipped, CoverageReason.UnsupportedContainer,
                $"No bounded reader is available for {artifact.Kind}.");
        }
    }

    private static async Task AnalyzeZipAsync(ArtifactRecord parent, byte[] bytes, AnalysisState state)
    {
        if (parent.Depth >= state.Document.Limits.MaxDepth)
        {
            state.Coverage(parent.Id, parent.LogicalPath, "open-container", CoverageStatus.Skipped, CoverageReason.DepthLimit,
                $"Maximum container depth {state.Document.Limits.MaxDepth} reached.");
            return;
        }

        try
        {
            using var buffer = new MemoryStream(bytes, writable: false);
            using var archive = new ZipArchive(buffer, ZipArchiveMode.Read, leaveOpen: false);
            var entries = archive.Entries;
            var acceptedEntries = 0;
            for (var index = 0; index < entries.Count; index++)
            {
                state.CancellationToken.ThrowIfCancellationRequested();
                var entry = entries[index];
                if (IsDirectoryEntry(entry))
                    continue;

                if (acceptedEntries >= state.Document.Limits.MaxEntriesPerArchive)
                {
                    state.Coverage(parent.Id, parent.LogicalPath, "enumerate-entries", CoverageStatus.Skipped, CoverageReason.EntryLimit,
                        $"Only the first {state.Document.Limits.MaxEntriesPerArchive} file entries were considered.");
                    break;
                }

                acceptedEntries++;
                var normalizedName = entry.FullName.Replace('\\', '/');
                var childPath = $"{parent.LogicalPath}!/{normalizedName}";
                if (!IsSafeArchivePath(normalizedName))
                {
                    state.Finding(RuleIds.ArchivePathTraversal, FindingLevel.Warning, parent,
                        "An archive entry uses an absolute or parent-traversing path.", ("entryName", normalizedName), ("entryIndex", index.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                    state.Coverage(parent.Id, childPath, "accept-entry", CoverageStatus.Rejected, CoverageReason.UnsafeEntryPath, "The entry path is unsafe.");
                    continue;
                }

                if (entry.Length > state.Document.Limits.MaxArtifactBytes)
                {
                    state.Coverage(parent.Id, childPath, "read-entry", CoverageStatus.Rejected, CoverageReason.ArtifactTooLarge,
                        $"Declared length {entry.Length} exceeds {state.Document.Limits.MaxArtifactBytes} bytes.");
                    continue;
                }

                var ratio = entry.CompressedLength == 0
                    ? (entry.Length == 0 ? 1 : double.PositiveInfinity)
                    : (double)entry.Length / entry.CompressedLength;
                if (ratio > state.Document.Limits.MaxExpansionRatio)
                {
                    state.Finding(RuleIds.ExcessiveExpansion, FindingLevel.Warning, parent,
                        "An archive entry exceeds the configured expansion ratio.",
                        ("entryName", normalizedName),
                        ("ratio", ratio.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)));
                    state.Coverage(parent.Id, childPath, "read-entry", CoverageStatus.Rejected, CoverageReason.ExpansionRatio,
                        $"Expansion ratio {ratio:0.##}:1 exceeds {state.Document.Limits.MaxExpansionRatio:0.##}:1.");
                    continue;
                }

                if (!state.CanAcceptBytes(entry.Length))
                {
                    state.Coverage(parent.Id, childPath, "read-entry", CoverageStatus.Rejected, CoverageReason.TotalByteLimit, "The total expanded-byte budget is exhausted.");
                    continue;
                }

                byte[] childBytes;
                try
                {
                    await using var entryStream = entry.Open();
                    childBytes = await ReadBoundedAsync(entryStream, state.Document.Limits.MaxArtifactBytes, state.CancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException)
                {
                    var reason = ex.Message.Contains("exceeds", StringComparison.OrdinalIgnoreCase)
                        ? CoverageReason.ArtifactTooLarge
                        : CoverageReason.MalformedContainer;
                    state.Coverage(parent.Id, childPath, "read-entry", CoverageStatus.Rejected, reason, ex.Message);
                    continue;
                }

                var selector = EvidenceSelector.ZipEntry(index, normalizedName, parent.Sha256);
                await AnalyzeBytesAsync(childBytes, Path.GetFileName(normalizedName), childPath, parent, parent.Depth + 1, selector, state).ConfigureAwait(false);
            }

            state.Coverage(parent.Id, parent.LogicalPath, "open-container", CoverageStatus.Analyzed, CoverageReason.None,
                $"Enumerated {entries.Count} ZIP entries.");
        }
        catch (InvalidDataException ex)
        {
            state.Coverage(parent.Id, parent.LogicalPath, "open-container", CoverageStatus.Rejected, CoverageReason.MalformedContainer, ex.Message);
        }
    }

    private static void ApplyRules(ArtifactRecord artifact, byte[] bytes, AnalysisState state)
    {
        var expected = ExpectedKinds(artifact.Extension);
        if (expected.Count > 0 && !expected.Contains(artifact.Kind))
        {
            state.Finding(RuleIds.ExtensionMismatch, FindingLevel.Warning, artifact,
                $"Extension '{artifact.Extension}' does not match detected format {artifact.Kind}.",
                ("extension", artifact.Extension), ("detectedKind", artifact.Kind.ToString()));
        }

        if (artifact.Depth > 0 && artifact.Kind is ArtifactKind.PortableExecutable or ArtifactKind.Elf or ArtifactKind.MachO)
        {
            state.Finding(RuleIds.NestedExecutable, FindingLevel.Warning, artifact,
                "Executable content is nested inside a container.", ("detectedKind", artifact.Kind.ToString()));
        }

        if (artifact.Kind == ArtifactKind.Unknown && artifact.Length >= 1024 && artifact.Entropy >= 7.5)
        {
            state.Finding(RuleIds.HighEntropyOpaque, FindingLevel.Note, artifact,
                "Opaque data has high byte entropy; compression or encryption may be present.",
                ("entropy", artifact.Entropy.ToString("0.000", System.Globalization.CultureInfo.InvariantCulture)));
        }

        if (artifact.Kind == ArtifactKind.Png && TryFindPngEnd(bytes, out var endOffset) && endOffset < bytes.Length)
        {
            state.Finding(RuleIds.PngTrailingData, FindingLevel.Note, artifact,
                "Bytes follow the PNG IEND chunk.", ("trailingBytes", (bytes.Length - endOffset).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
    }

    private static HashSet<ArtifactKind> ExpectedKinds(string extension) => extension switch
    {
        ".txt" or ".md" or ".csv" => [ArtifactKind.Text],
        ".ps1" => [ArtifactKind.PowerShell],
        ".json" => [ArtifactKind.Json],
        ".xml" => [ArtifactKind.Xml],
        ".exe" or ".dll" => [ArtifactKind.PortableExecutable],
        ".elf" => [ArtifactKind.Elf],
        ".zip" or ".jar" or ".nupkg" or ".apk" or ".docx" or ".xlsx" or ".pptx" => [ArtifactKind.Zip],
        ".png" => [ArtifactKind.Png],
        ".pdf" => [ArtifactKind.Pdf],
        ".7z" => [ArtifactKind.SevenZip],
        ".rar" => [ArtifactKind.Rar],
        ".gz" => [ArtifactKind.Gzip],
        _ => [],
    };

    private static bool TryFindPngEnd(ReadOnlySpan<byte> bytes, out int endOffset)
    {
        endOffset = 0;
        if (bytes.Length < 20 || !bytes[..8].SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
            return false;

        var position = 8;
        while (position <= bytes.Length - 12)
        {
            var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(position, 4));
            if (length > int.MaxValue || position + 12L + length > bytes.Length)
                return false;
            var type = bytes.Slice(position + 4, 4);
            position += checked((int)length + 12);
            if (type.SequenceEqual("IEND"u8))
            {
                endOffset = position;
                return true;
            }
        }

        return false;
    }

    private static bool IsDirectoryEntry(ZipArchiveEntry entry) =>
        entry.FullName.EndsWith('/') || string.IsNullOrEmpty(entry.Name);

    internal static bool IsSafeArchivePath(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.StartsWith('/') || name.StartsWith('\\'))
            return false;
        if (name.Length >= 3 && char.IsAsciiLetter(name[0]) && name[1] == ':' && name[2] == '/')
            return false;
        return !name.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(segment => segment == "..");
    }

    internal static async Task<byte[]> ReadBoundedAsync(Stream stream, long limit, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            long total = 0;
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                total += read;
                if (total > limit)
                    throw new InvalidDataException($"Expanded data exceeds the {limit}-byte limit.");
                output.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return output.ToArray();
    }

    private static double CalculateEntropy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
            return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var value in bytes)
            counts[value]++;
        var entropy = 0d;
        foreach (var count in counts)
        {
            if (count == 0)
                continue;
            var probability = (double)count / bytes.Length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy;
    }

    private static void AddDuplicateFindings(AnalysisState state)
    {
        foreach (var group in state.Document.Artifacts.GroupBy(x => x.Sha256, StringComparer.Ordinal).Where(x => x.Count() > 1))
        {
            var first = group.First();
            foreach (var duplicate in group.Skip(1))
            {
                state.Finding(RuleIds.DuplicateContent, FindingLevel.Note, duplicate,
                    "The same content digest appears under another selector.", ("firstArtifactId", first.Id));
            }
        }
    }

    private static void ValidateLimits(AnalysisLimits limits)
    {
        if (limits.MaxRootBytes < 1 || limits.MaxArtifactBytes < 1 || limits.MaxTotalExpandedBytes < 1 ||
            limits.MaxArtifacts < 1 || limits.MaxFilesystemNodes < 1 || limits.MaxEntriesPerArchive < 1 || limits.MaxDepth < 0 ||
            limits.MaxExpansionRatio <= 0 || limits.MaxFindings < 1)
            throw new ArgumentOutOfRangeException(nameof(limits), "All analysis limits must be positive; depth may be zero.");
    }

    private sealed class AnalysisState(CaseDocument document, CancellationToken cancellationToken)
    {
        public CaseDocument Document { get; } = document;
        public CancellationToken CancellationToken { get; } = cancellationToken;
        public long TotalBytes { get; set; }
        public int VisitedFilesystemNodes { get; set; }

        public bool CanAcceptBytes(long length) => length >= 0 && TotalBytes <= Document.Limits.MaxTotalExpandedBytes - length;

        public void Coverage(string? artifactId, string logicalPath, string operation, CoverageStatus status, CoverageReason reason, string detail) =>
            Document.Coverage.Add(new CoverageRecord
            {
                ArtifactId = artifactId,
                LogicalPath = logicalPath,
                Operation = operation,
                Status = status,
                Reason = reason,
                Detail = detail,
            });

        public void Finding(string ruleId, FindingLevel level, ArtifactRecord artifact, string message, params (string Key, string Value)[] evidence)
        {
            if (Document.Findings.Count >= Document.Limits.MaxFindings)
            {
                if (!Document.Coverage.Any(x => x.Reason == CoverageReason.FindingLimit))
                    Coverage(artifact.Id, artifact.LogicalPath, "record-findings", CoverageStatus.Skipped, CoverageReason.FindingLimit, "The finding-count limit is exhausted.");
                return;
            }

            Document.Findings.Add(new FindingRecord
            {
                RuleId = ruleId,
                Level = level,
                ArtifactId = artifact.Id,
                Message = message,
                Evidence = new SortedDictionary<string, string>(evidence.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal), StringComparer.Ordinal),
            });
        }
    }
}
