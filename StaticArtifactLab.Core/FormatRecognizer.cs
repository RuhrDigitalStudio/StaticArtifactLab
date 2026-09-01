using System.Text;

namespace StaticArtifactLab.Core;

public static class FormatRecognizer
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static FormatMatch Detect(ReadOnlySpan<byte> bytes, string name)
    {
        if (StartsWith(bytes, [0x4d, 0x5a]))
            return Match(ArtifactKind.PortableExecutable, "application/vnd.microsoft.portable-executable");
        if (StartsWith(bytes, [0x7f, 0x45, 0x4c, 0x46]))
            return Match(ArtifactKind.Elf, "application/x-elf");
        if (StartsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe]) || StartsWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]))
            return Match(ArtifactKind.MachO, "application/x-mach-binary");
        if (StartsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || StartsWith(bytes, [0x50, 0x4b, 0x05, 0x06]) || StartsWith(bytes, [0x50, 0x4b, 0x07, 0x08]))
            return Match(ArtifactKind.Zip, "application/zip", container: true);
        if (StartsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))
            return Match(ArtifactKind.SevenZip, "application/x-7z-compressed", container: true);
        if (StartsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]))
            return Match(ArtifactKind.Rar, "application/vnd.rar", container: true);
        if (StartsWith(bytes, [0x1f, 0x8b]))
            return Match(ArtifactKind.Gzip, "application/gzip", container: true);
        if (StartsWith(bytes, [0x25, 0x50, 0x44, 0x46]))
            return Match(ArtifactKind.Pdf, "application/pdf");
        if (StartsWith(bytes, [137, 80, 78, 71, 13, 10, 26, 10]))
            return Match(ArtifactKind.Png, "image/png");
        if (StartsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))
            return Match(ArtifactKind.OleCompound, "application/x-ole-storage", container: true);

        if (!TryReadText(bytes, out var text))
            return Match(ArtifactKind.Unknown, "application/octet-stream");

        var trimmed = text.AsSpan().TrimStart();
        if (Path.GetExtension(name).Equals(".ps1", StringComparison.OrdinalIgnoreCase))
            return Match(ArtifactKind.PowerShell, "text/x-powershell");
        if (trimmed.StartsWith("{".AsSpan(), StringComparison.Ordinal) || trimmed.StartsWith("[".AsSpan(), StringComparison.Ordinal))
            return Match(ArtifactKind.Json, "application/json");
        if (trimmed.StartsWith("<?xml".AsSpan(), StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("<".AsSpan(), StringComparison.Ordinal))
            return Match(ArtifactKind.Xml, "application/xml");

        return Match(ArtifactKind.Text, "text/plain");
    }

    private static bool TryReadText(ReadOnlySpan<byte> bytes, out string text)
    {
        text = string.Empty;
        if (bytes.IsEmpty || bytes.Contains((byte)0))
            return false;

        try
        {
            text = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        var controls = text.Count(c => char.IsControl(c) && c is not '\r' and not '\n' and not '\t');
        return controls <= Math.Max(1, text.Length / 100);
    }

    private static bool StartsWith(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> signature) => bytes.StartsWith(signature);

    private static FormatMatch Match(ArtifactKind kind, string mediaType, bool container = false) => new(kind, mediaType, container);
}

