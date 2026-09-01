using System.Xml.Linq;

namespace StaticArtifactLab.Tests;

public sealed class GuiContractTests
{
    [Fact]
    public void MainWindow_ExposesCompleteCaseWorkflow()
    {
        var document = LoadXaml();
        var names = document.Descendants()
            .Attributes(XName.Get("Name", "http://schemas.microsoft.com/winfx/2006/xaml"))
            .Select(x => x.Value)
            .ToHashSet(StringComparer.Ordinal);

        string[] expected =
        [
            "InputPathBox", "BrowseFileButton", "BrowseFolderButton", "ProveButton", "CancelButton",
            "OpenCaseButton", "VerifyButton", "ReplayButton", "ExportCaseButton", "ExportHtmlButton",
            "ExportSarifButton", "ArtifactTree", "FindingsGrid", "CoverageGrid", "EvidencePanel",
            "StatusText", "ArtifactCountText", "FindingCountText", "CoverageCountText", "CaseStatusText",
        ];

        Assert.Empty(expected.Except(names, StringComparer.Ordinal));
    }

    [Fact]
    public void MainWindow_StatesSafetyBoundaryAndEvidenceVocabulary()
    {
        var xaml = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Gui", "MainWindow.xaml"));

        Assert.Contains("Inputs are never executed", xaml, StringComparison.Ordinal);
        Assert.Contains("Selector", xaml, StringComparison.Ordinal);
        Assert.Contains("SHA-256", xaml, StringComparison.Ordinal);
        Assert.Contains("Coverage", xaml, StringComparison.Ordinal);
    }

    private static XDocument LoadXaml() =>
        XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Gui", "MainWindow.xaml"));
}
