using System.IO.Compression;

namespace StaticArtifactLab.Tests;

internal static class TestData
{
    public static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.SmallestSize);
                using var stream = entry.Open();
                stream.Write(data);
            }
        }

        return output.ToArray();
    }

    public static byte[] MinimalPng(int trailingBytes = 0)
    {
        byte[] png =
        [
            137, 80, 78, 71, 13, 10, 26, 10,
            0, 0, 0, 0, 73, 69, 78, 68,
            174, 66, 96, 130,
        ];

        return trailingBytes == 0 ? png : [.. png, .. Enumerable.Repeat((byte)0x41, trailingBytes)];
    }

    public static TemporaryDirectory Temp() => new();
}

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"static-artifact-lab-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string Write(string relativePath, byte[] bytes)
    {
        var path = System.IO.Path.Combine(Path, relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public void Dispose() => Directory.Delete(Path, recursive: true);
}

