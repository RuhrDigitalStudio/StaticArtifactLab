using System.Text;
using StaticArtifactLab.Cli;

namespace StaticArtifactLab.Tests;

public sealed class CliTests
{
    [Fact]
    public async Task Prove_WritesAllRequestedReportsAndSummary()
    {
        using var temp = TestData.Temp();
        var input = temp.Write("sample.txt", Encoding.UTF8.GetBytes("CLI evidence"));
        var casePath = Path.Combine(temp.Path, "case.json");
        var htmlPath = Path.Combine(temp.Path, "case.html");
        var sarifPath = Path.Combine(temp.Path, "case.sarif");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApplication.RunAsync(
            ["prove", input, "--case", casePath, "--html", htmlPath, "--sarif", sarifPath], output, error);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(casePath));
        Assert.True(File.Exists(htmlPath));
        Assert.True(File.Exists(sarifPath));
        Assert.Contains("Artifacts: 1", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task Prove_ReturnsPartialExitForVisibleLimit()
    {
        using var temp = TestData.Temp();
        var input = temp.Write("sample.bin", new byte[2 * 1024 * 1024]);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApplication.RunAsync(
            ["prove", input, "--max-root-mib", "1", "--case", Path.Combine(temp.Path, "case.json")], output, error);

        Assert.Equal(2, exitCode);
        Assert.Contains("partial", output.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_ReturnsInvalidExitAfterSourceChanges()
    {
        using var temp = TestData.Temp();
        var input = temp.Write("sample.txt", Encoding.UTF8.GetBytes("original"));
        var casePath = Path.Combine(temp.Path, "case.json");
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await CliApplication.RunAsync(["prove", input, "--case", casePath], output, error));
        File.WriteAllText(input, "changed");

        var exitCode = await CliApplication.RunAsync(["verify", casePath, "--with-sources"], output, error);

        Assert.Equal(3, exitCode);
        Assert.Contains("source-digest-mismatch", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Replay_ReturnsDifferenceExitAndWritesFreshCase()
    {
        using var temp = TestData.Temp();
        var input = temp.Write("sample.txt", Encoding.UTF8.GetBytes("original"));
        var casePath = Path.Combine(temp.Path, "case.json");
        var replayPath = Path.Combine(temp.Path, "replayed.json");
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await CliApplication.RunAsync(["prove", input, "--case", casePath], output, error));
        File.WriteAllText(input, "changed");

        var exitCode = await CliApplication.RunAsync(["replay", casePath, "--out", replayPath], output, error);

        Assert.Equal(4, exitCode);
        Assert.True(File.Exists(replayPath));
        Assert.Contains("Changed: 1", output.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("help", 0)]
    [InlineData("unknown", 1)]
    public async Task HelpAndUnknownCommands_HaveStableExitCodes(string command, int expected)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await CliApplication.RunAsync([command], output, error);

        Assert.Equal(expected, exitCode);
        Assert.Contains("StaticArtifactLab", expected == 0 ? output.ToString() : error.ToString(), StringComparison.Ordinal);
    }
}
