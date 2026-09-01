using System.Text;
using StaticArtifactLab.Core;

namespace StaticArtifactLab.Tests;

public sealed class ModelAndRecognitionTests
{
    [Fact]
    public void ArtifactId_IsDeterministicAndLowercase()
    {
        var selector = EvidenceSelector.Root("sample.bin", 0);
        var first = ArtifactIdentity.Create(null, selector, 3, new string('a', 64));
        var second = ArtifactIdentity.Create(null, selector, 3, new string('a', 64));

        Assert.Equal(first, second);
        Assert.Matches("^[0-9a-f]{24}$", first);
    }

    [Fact]
    public void ArtifactId_ChangesForSelectorParentLengthOrDigest()
    {
        var baseline = ArtifactIdentity.Create(null, EvidenceSelector.Root("a", 0), 3, new string('a', 64));

        Assert.NotEqual(baseline, ArtifactIdentity.Create(null, EvidenceSelector.Root("b", 0), 3, new string('a', 64)));
        Assert.NotEqual(baseline, ArtifactIdentity.Create("parent", EvidenceSelector.Root("a", 0), 3, new string('a', 64)));
        Assert.NotEqual(baseline, ArtifactIdentity.Create(null, EvidenceSelector.Root("a", 0), 4, new string('a', 64)));
        Assert.NotEqual(baseline, ArtifactIdentity.Create(null, EvidenceSelector.Root("a", 0), 3, new string('b', 64)));
    }

    [Theory]
    [InlineData(new byte[] { 0x4d, 0x5a, 0, 0 }, ArtifactKind.PortableExecutable)]
    [InlineData(new byte[] { 0x7f, 0x45, 0x4c, 0x46 }, ArtifactKind.Elf)]
    [InlineData(new byte[] { 0x50, 0x4b, 0x03, 0x04 }, ArtifactKind.Zip)]
    [InlineData(new byte[] { 0x25, 0x50, 0x44, 0x46 }, ArtifactKind.Pdf)]
    [InlineData(new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c }, ArtifactKind.SevenZip)]
    public void Recognizer_UsesMagicBytes(byte[] bytes, ArtifactKind expected)
    {
        Assert.Equal(expected, FormatRecognizer.Detect(bytes, "wrong.txt").Kind);
    }

    [Fact]
    public void Recognizer_DetectsPngJsonXmlPowerShellAndText()
    {
        Assert.Equal(ArtifactKind.Png, FormatRecognizer.Detect(TestData.MinimalPng(), "x.bin").Kind);
        Assert.Equal(ArtifactKind.Json, FormatRecognizer.Detect(Encoding.UTF8.GetBytes("{\"ok\":true}"), "x").Kind);
        Assert.Equal(ArtifactKind.Xml, FormatRecognizer.Detect(Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><x/>"), "x").Kind);
        Assert.Equal(ArtifactKind.PowerShell, FormatRecognizer.Detect(Encoding.UTF8.GetBytes("param($Path)\nGet-Item $Path"), "scan.ps1").Kind);
        Assert.Equal(ArtifactKind.Text, FormatRecognizer.Detect(Encoding.UTF8.GetBytes("ordinary readable text\n"), "x.dat").Kind);
    }

    [Fact]
    public void Recognizer_DoesNotTreatBinaryNulDataAsText()
    {
        Assert.Equal(ArtifactKind.Unknown, FormatRecognizer.Detect([0, 1, 2, 3, 4, 5], "x.txt").Kind);
    }
}

