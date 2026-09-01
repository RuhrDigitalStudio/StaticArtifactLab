using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using StaticArtifactLab.Core;

namespace StaticArtifactLab.Gui;

public partial class MainWindow : Window, IDisposable
{
    private readonly ObservableCollection<ArtifactNode> _roots = [];
    private CaseDocument? _document;
    private CancellationTokenSource? _operation;

    public MainWindow()
    {
        InitializeComponent();
        ArtifactTree.ItemsSource = _roots;
        Closed += (_, _) => Dispose();
    }

    public void Dispose()
    {
        _operation?.Cancel();
        _operation?.Dispose();
        _operation = null;
        GC.SuppressFinalize(this);
    }

    private void BrowseFileButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose an artifact", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true)
            InputPathBox.Text = dialog.FileName;
    }

    private void BrowseFolderButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose an artifact directory" };
        if (dialog.ShowDialog(this) == true)
            InputPathBox.Text = dialog.FolderName;
    }

    private async void ProveButton_Click(object sender, RoutedEventArgs e)
    {
        var input = InputPathBox.Text.Trim();
        if (!File.Exists(input) && !Directory.Exists(input))
        {
            MessageBox.Show(this, "Choose an existing file or directory.", "Input required", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        await RunBusyAsync("Building bounded evidence case…", async token =>
        {
            var document = await ArtifactAnalyzer.ProveAsync(input, cancellationToken: token);
            ShowDocument(document);
            StatusText.Text = document.Status == CaseStatus.Complete
                ? "Case complete. Review findings and coverage before drawing conclusions."
                : "Case is partial. Coverage records explain what was skipped or rejected.";
        });
    }

    private async void OpenCaseButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open StaticArtifactLab case",
            Filter = "StaticArtifactLab case (*.json)|*.json|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true)
            return;

        await RunBusyAsync("Reading case…", async token =>
        {
            var document = await CaseJson.ReadAsync(dialog.FileName, token);
            ShowDocument(document);
            InputPathBox.Text = document.InputPath;
            StatusText.Text = $"Opened {Path.GetFileName(dialog.FileName)}.";
        });
    }

    private async void VerifyButton_Click(object sender, RoutedEventArgs e)
    {
        if (_document is null)
            return;
        await RunBusyAsync("Verifying selectors and available source bytes…", async token =>
        {
            var result = await CaseVerifier.VerifyAsync(_document, token);
            StatusText.Text = result.IsValid
                ? $"Evidence valid · {result.VerifiedArtifacts} verified · {result.UnverifiedArtifacts} unavailable."
                : $"Evidence invalid · {result.Errors.Count} error(s).";
            var details = result.IsValid
                ? "Every structurally available artifact matched its recorded length and SHA-256."
                : string.Join(Environment.NewLine, result.Errors.Take(12).Select(x => $"{x.Code}: {x.Message}"));
            MessageBox.Show(this, details, result.IsValid ? "Evidence valid" : "Evidence invalid", MessageBoxButton.OK,
                result.IsValid ? MessageBoxImage.Information : MessageBoxImage.Warning);
        });
    }

    private async void ReplayButton_Click(object sender, RoutedEventArgs e)
    {
        if (_document is null)
            return;
        await RunBusyAsync("Replaying the deterministic worker…", async token =>
        {
            var replay = await CaseReplayer.ReplayAsync(_document, token);
            StatusText.Text = replay.IsMatch
                ? "Replay matches the recorded artifact evidence."
                : $"Replay differs · +{replay.Added.Count} −{replay.Removed.Count} ~{replay.Changed.Count}.";
            if (!replay.IsMatch)
            {
                var lines = replay.Added.Select(x => $"+ {x}")
                    .Concat(replay.Removed.Select(x => $"− {x}"))
                    .Concat(replay.Changed.Select(x => $"~ {x}"))
                    .Take(20);
                MessageBox.Show(this, string.Join(Environment.NewLine, lines), "Replay differences", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        });
    }

    private async void ExportCaseButton_Click(object sender, RoutedEventArgs e) =>
        await ExportAsync("Case JSON (*.json)|*.json", ".sal-case.json", document => CaseJson.Serialize(document));

    private async void ExportHtmlButton_Click(object sender, RoutedEventArgs e) =>
        await ExportAsync("HTML report (*.html)|*.html", ".html", document => HtmlReportWriter.Write(document));

    private async void ExportSarifButton_Click(object sender, RoutedEventArgs e) =>
        await ExportAsync("SARIF report (*.sarif)|*.sarif", ".sarif", document => SarifReportWriter.Write(document));

    private void CancelButton_Click(object sender, RoutedEventArgs e) => _operation?.Cancel();

    private void ArtifactTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not ArtifactNode node)
            return;
        var artifact = node.Artifact;
        EvidencePathText.Text = artifact.LogicalPath;
        EvidenceDigestText.Text = artifact.Sha256;
        EvidenceKindText.Text = $"{artifact.Kind} · {artifact.MediaType}";
        EvidenceSizeText.Text = $"{artifact.Length:N0} bytes · {artifact.Entropy:0.000} bits/byte";
        EvidenceSelectorText.Text = artifact.Selector.Kind == "root"
            ? $"root #{artifact.Selector.RootIndex} · {artifact.Selector.RootName}"
            : $"ZIP entry #{artifact.Selector.EntryIndex} · {artifact.Selector.EntryName}";
        EvidenceParentText.Text = artifact.ParentId ?? "root";
    }

    private void ShowDocument(CaseDocument document)
    {
        _document = document;
        _roots.Clear();
        var nodes = document.Artifacts.ToDictionary(x => x.Id, x => new ArtifactNode(x), StringComparer.Ordinal);
        foreach (var artifact in document.Artifacts)
        {
            var node = nodes[artifact.Id];
            if (artifact.ParentId is not null && nodes.TryGetValue(artifact.ParentId, out var parent))
                parent.Children.Add(node);
            else
                _roots.Add(node);
        }

        FindingsGrid.ItemsSource = document.Findings;
        CoverageGrid.ItemsSource = document.Coverage;
        CaseStatusText.Text = document.Status.ToString();
        ArtifactCountText.Text = document.Artifacts.Count.ToString(CultureInfo.InvariantCulture);
        FindingCountText.Text = document.Findings.Count.ToString(CultureInfo.InvariantCulture);
        CoverageCountText.Text = document.Coverage.Count.ToString(CultureInfo.InvariantCulture);
        VerifyButton.IsEnabled = ReplayButton.IsEnabled = ExportCaseButton.IsEnabled = ExportHtmlButton.IsEnabled = ExportSarifButton.IsEnabled = true;
    }

    private async Task ExportAsync(string filter, string suffix, Func<CaseDocument, string> writer)
    {
        if (_document is null)
            return;
        var dialog = new SaveFileDialog
        {
            Title = "Export evidence report",
            Filter = filter,
            FileName = SuggestedFileName(_document, suffix),
            AddExtension = true,
        };
        if (dialog.ShowDialog(this) != true)
            return;
        await WriteAtomicAsync(dialog.FileName, writer(_document));
        StatusText.Text = $"Exported {Path.GetFileName(dialog.FileName)}.";
    }

    private async Task RunBusyAsync(string message, Func<CancellationToken, Task> operation)
    {
        _operation?.Dispose();
        _operation = new CancellationTokenSource();
        SetBusy(true, message);
        try
        {
            await operation(_operation.Token);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Operation cancelled; no partial report was exported.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            StatusText.Text = "Operation failed. The current case was left unchanged.";
            MessageBox.Show(this, ex.Message, "StaticArtifactLab", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false, StatusText.Text);
        }
    }

    private void SetBusy(bool busy, string status)
    {
        StatusText.Text = status;
        BusyIndicator.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.IsEnabled = busy;
        ProveButton.IsEnabled = OpenCaseButton.IsEnabled = !busy;
        if (_document is not null)
            VerifyButton.IsEnabled = ReplayButton.IsEnabled = ExportCaseButton.IsEnabled = ExportHtmlButton.IsEnabled = ExportSarifButton.IsEnabled = !busy;
    }

    private static string SuggestedFileName(CaseDocument document, string suffix)
    {
        var name = Path.GetFileName(document.InputPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return string.IsNullOrWhiteSpace(name) ? $"evidence{suffix}" : $"{name}{suffix}";
    }

    private static async Task WriteAtomicAsync(string path, string content)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidDataException("The export path has no directory.");
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temporary, content, new UTF8Encoding(false));
            File.Move(temporary, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}

public sealed class ArtifactNode(ArtifactRecord artifact)
{
    public ArtifactRecord Artifact { get; } = artifact;
    public string Name => Artifact.Name;
    public string LogicalPath => Artifact.LogicalPath;
    public string Kind => Artifact.Kind.ToString();
    public ObservableCollection<ArtifactNode> Children { get; } = [];
}
