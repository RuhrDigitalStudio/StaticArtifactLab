using System.Globalization;
using System.Text;
using StaticArtifactLab.Core;

namespace StaticArtifactLab.Cli;

internal static class Program
{
    public static Task<int> Main(string[] args) => CliApplication.RunAsync(args, Console.Out, Console.Error);
}

public static class CliApplication
{
    private const int UsageError = 1;
    private const int PartialCase = 2;
    private const int InvalidEvidence = 3;
    private const int ReplayDifference = 4;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (args.Length == 0 || IsHelp(args[0]))
        {
            await output.WriteLineAsync(HelpText()).ConfigureAwait(false);
            return 0;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "prove" => await ProveAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "verify" => await VerifyAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "replay" => await ReplayAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                _ => await UnknownCommandAsync(args[0], error).ConfigureAwait(false),
            };
        }
        catch (OperationCanceledException)
        {
            await error.WriteLineAsync("Analysis cancelled.").ConfigureAwait(false);
            return UsageError;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            await error.WriteLineAsync($"Error: {ex.Message}").ConfigureAwait(false);
            return UsageError;
        }
    }

    private static async Task<int> ProveAsync(string[] args, TextWriter output, CancellationToken cancellationToken)
    {
        var parsed = ParsedArguments.Parse(args, ["case", "html", "sarif", "max-root-mib", "max-artifact-mib", "max-total-mib", "max-artifacts", "max-entries", "max-depth", "max-ratio"]);
        if (parsed.Positionals.Count != 1)
            throw new ArgumentException("prove requires exactly one input file or directory.");

        var limits = BuildLimits(parsed);
        var document = await ArtifactAnalyzer.ProveAsync(parsed.Positionals[0], new AnalysisOptions { Limits = limits }, cancellationToken).ConfigureAwait(false);
        var casePath = parsed.Get("case") ?? DefaultCasePath(parsed.Positionals[0]);
        await AtomicFile.WriteAllTextAsync(casePath, CaseJson.Serialize(document), cancellationToken).ConfigureAwait(false);

        if (parsed.Get("html") is { } htmlPath)
            await AtomicFile.WriteAllTextAsync(htmlPath, HtmlReportWriter.Write(document), cancellationToken).ConfigureAwait(false);
        if (parsed.Get("sarif") is { } sarifPath)
            await AtomicFile.WriteAllTextAsync(sarifPath, SarifReportWriter.Write(document), cancellationToken).ConfigureAwait(false);

        await output.WriteLineAsync($"Case: {Path.GetFullPath(casePath)}").ConfigureAwait(false);
        await output.WriteLineAsync($"Status: {document.Status.ToString().ToLowerInvariant()}").ConfigureAwait(false);
        await output.WriteLineAsync($"Artifacts: {document.Artifacts.Count}").ConfigureAwait(false);
        await output.WriteLineAsync($"Findings: {document.Findings.Count}").ConfigureAwait(false);
        await output.WriteLineAsync($"Coverage records: {document.Coverage.Count}").ConfigureAwait(false);
        return document.Status == CaseStatus.Complete ? 0 : PartialCase;
    }

    private static async Task<int> VerifyAsync(string[] args, TextWriter output, CancellationToken cancellationToken)
    {
        var parsed = ParsedArguments.Parse(args, []);
        if (parsed.Positionals.Count != 1)
            throw new ArgumentException("verify requires exactly one case JSON file.");

        var document = await CaseJson.ReadAsync(parsed.Positionals[0], cancellationToken).ConfigureAwait(false);
        var result = await CaseVerifier.VerifyAsync(document, cancellationToken).ConfigureAwait(false);
        await output.WriteLineAsync($"Valid: {result.IsValid.ToString().ToLowerInvariant()}").ConfigureAwait(false);
        await output.WriteLineAsync($"Verified artifacts: {result.VerifiedArtifacts}").ConfigureAwait(false);
        await output.WriteLineAsync($"Unverified artifacts: {result.UnverifiedArtifacts}").ConfigureAwait(false);
        foreach (var issue in result.Errors)
            await output.WriteLineAsync($"{issue.Code}: {issue.Message} [{issue.ArtifactId ?? "case"}]").ConfigureAwait(false);
        return result.IsValid ? 0 : InvalidEvidence;
    }

    private static async Task<int> ReplayAsync(string[] args, TextWriter output, CancellationToken cancellationToken)
    {
        var parsed = ParsedArguments.Parse(args, ["out", "html", "sarif"]);
        if (parsed.Positionals.Count != 1)
            throw new ArgumentException("replay requires exactly one case JSON file.");

        var original = await CaseJson.ReadAsync(parsed.Positionals[0], cancellationToken).ConfigureAwait(false);
        var result = await CaseReplayer.ReplayAsync(original, cancellationToken).ConfigureAwait(false);
        var outputPath = parsed.Get("out") ?? parsed.Positionals[0] + ".replayed.json";
        await AtomicFile.WriteAllTextAsync(outputPath, CaseJson.Serialize(result.ReplayedCase), cancellationToken).ConfigureAwait(false);
        if (parsed.Get("html") is { } htmlPath)
            await AtomicFile.WriteAllTextAsync(htmlPath, HtmlReportWriter.Write(result.ReplayedCase), cancellationToken).ConfigureAwait(false);
        if (parsed.Get("sarif") is { } sarifPath)
            await AtomicFile.WriteAllTextAsync(sarifPath, SarifReportWriter.Write(result.ReplayedCase), cancellationToken).ConfigureAwait(false);

        await output.WriteLineAsync($"Match: {result.IsMatch.ToString().ToLowerInvariant()}").ConfigureAwait(false);
        await output.WriteLineAsync($"Added: {result.Added.Count}").ConfigureAwait(false);
        await output.WriteLineAsync($"Removed: {result.Removed.Count}").ConfigureAwait(false);
        await output.WriteLineAsync($"Changed: {result.Changed.Count}").ConfigureAwait(false);
        foreach (var path in result.Added)
            await output.WriteLineAsync($"+ {path}").ConfigureAwait(false);
        foreach (var path in result.Removed)
            await output.WriteLineAsync($"- {path}").ConfigureAwait(false);
        foreach (var path in result.Changed)
            await output.WriteLineAsync($"~ {path}").ConfigureAwait(false);
        return result.IsMatch ? 0 : ReplayDifference;
    }

    private static AnalysisLimits BuildLimits(ParsedArguments args) => AnalysisLimits.Default with
    {
        MaxRootBytes = Mebibytes(args, "max-root-mib", AnalysisLimits.Default.MaxRootBytes),
        MaxArtifactBytes = Mebibytes(args, "max-artifact-mib", AnalysisLimits.Default.MaxArtifactBytes),
        MaxTotalExpandedBytes = Mebibytes(args, "max-total-mib", AnalysisLimits.Default.MaxTotalExpandedBytes),
        MaxArtifacts = PositiveInt(args, "max-artifacts", AnalysisLimits.Default.MaxArtifacts),
        MaxEntriesPerArchive = PositiveInt(args, "max-entries", AnalysisLimits.Default.MaxEntriesPerArchive),
        MaxDepth = NonNegativeInt(args, "max-depth", AnalysisLimits.Default.MaxDepth),
        MaxExpansionRatio = PositiveDouble(args, "max-ratio", AnalysisLimits.Default.MaxExpansionRatio),
    };

    private static long Mebibytes(ParsedArguments args, string key, long defaultBytes)
    {
        var value = args.Get(key);
        if (value is null)
            return defaultBytes;
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var mib) || mib <= 0 || mib > long.MaxValue / (1024 * 1024))
            throw new ArgumentException($"--{key} requires a positive integer.");
        return checked(mib * 1024 * 1024);
    }

    private static int PositiveInt(ParsedArguments args, string key, int defaultValue)
    {
        var value = args.Get(key);
        if (value is null)
            return defaultValue;
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number <= 0)
            throw new ArgumentException($"--{key} requires a positive integer.");
        return number;
    }

    private static int NonNegativeInt(ParsedArguments args, string key, int defaultValue)
    {
        var value = args.Get(key);
        if (value is null)
            return defaultValue;
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number < 0)
            throw new ArgumentException($"--{key} requires a non-negative integer.");
        return number;
    }

    private static double PositiveDouble(ParsedArguments args, string key, double defaultValue)
    {
        var value = args.Get(key);
        if (value is null)
            return defaultValue;
        if (!double.TryParse(value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var number) || number <= 0 || double.IsInfinity(number))
            throw new ArgumentException($"--{key} requires a positive invariant-culture number.");
        return number;
    }

    private static string DefaultCasePath(string input) => Path.GetFullPath(input).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + ".sal-case.json";

    private static bool IsHelp(string value) => value is "help" or "--help" or "-h";

    private static async Task<int> UnknownCommandAsync(string command, TextWriter error)
    {
        await error.WriteLineAsync($"StaticArtifactLab: unknown command '{command}'.").ConfigureAwait(false);
        await error.WriteLineAsync("Use 'static-artifact help' for usage.").ConfigureAwait(false);
        return UsageError;
    }

    private static string HelpText() => """
        StaticArtifactLab 1.0-rc — reproducible, offline artifact evidence

        Usage:
          static-artifact prove <input> [--case case.json] [--html report.html] [--sarif report.sarif]
          static-artifact verify <case.json>
          static-artifact replay <case.json> [--out replayed.json] [--html report.html] [--sarif report.sarif]

        Prove limits:
          --max-root-mib <n>       Maximum root file size (default 100)
          --max-artifact-mib <n>   Maximum expanded child size (default 100)
          --max-total-mib <n>      Total expanded-byte budget (default 512)
          --max-artifacts <n>      Accepted artifact budget (default 5000)
          --max-entries <n>        Entries considered per ZIP (default 1000)
          --max-depth <n>          Nested container depth (default 8)
          --max-ratio <n>          Maximum expansion ratio (default 200)

        Exit codes: 0 success, 1 usage/I/O, 2 partial coverage,
                    3 invalid evidence, 4 replay difference.

        Inputs are never executed. Reports can contain sensitive paths and strings.
        """;

    private sealed class ParsedArguments
    {
        private ParsedArguments(List<string> positionals, Dictionary<string, string> options)
        {
            Positionals = positionals;
            Options = options;
        }

        public List<string> Positionals { get; }
        private Dictionary<string, string> Options { get; }

        public string? Get(string key) => Options.GetValueOrDefault(key);

        public static ParsedArguments Parse(string[] args, IReadOnlyCollection<string> allowedOptions)
        {
            var positionals = new List<string>();
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var index = 0; index < args.Length; index++)
            {
                var current = args[index];
                if (!current.StartsWith("--", StringComparison.Ordinal))
                {
                    positionals.Add(current);
                    continue;
                }

                var key = current[2..];
                if (!allowedOptions.Contains(key, StringComparer.Ordinal))
                    throw new ArgumentException($"Unknown option '--{key}'.");
                if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException($"Option '--{key}' requires a value.");
                if (!options.TryAdd(key, args[++index]))
                    throw new ArgumentException($"Option '--{key}' was supplied more than once.");
            }

            return new ParsedArguments(positionals, options);
        }
    }

    private static class AtomicFile
    {
        public static async Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken)
        {
            var fullPath = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(fullPath) ?? throw new ArgumentException("Output path has no directory.", nameof(path));
            Directory.CreateDirectory(directory);
            var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
            try
            {
                await File.WriteAllTextAsync(temporaryPath, content, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
                File.Move(temporaryPath, fullPath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    File.Delete(temporaryPath);
            }
        }
    }
}
