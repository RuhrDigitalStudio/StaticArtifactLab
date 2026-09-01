using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StaticArtifactLab.Core;

public static class CaseJson
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static string Serialize(CaseDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        // Stable LF output keeps signed cases and review diffs identical across platforms.
        return JsonSerializer.Serialize(document, Options).Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    public static CaseDocument Deserialize(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        CaseDocument document;
        try
        {
            document = JsonSerializer.Deserialize<CaseDocument>(json, Options)
                ?? throw new InvalidDataException("The case document is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("The case document is not valid JSON.", ex);
        }

        if (!string.Equals(document.Schema, "static-artifact-case/v2", StringComparison.Ordinal))
            throw new InvalidDataException($"Unsupported case schema '{document.Schema}'.");
        return document;
    }

    public static async Task<CaseDocument> ReadAsync(string path, CancellationToken cancellationToken = default)
    {
        var json = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        return Deserialize(json);
    }

    public static Task WriteAsync(string path, CaseDocument document, CancellationToken cancellationToken = default) =>
        File.WriteAllTextAsync(path, Serialize(document), new UTF8Encoding(false), cancellationToken);

    internal static JsonSerializerOptions CreateOptions() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}

public static class HtmlReportWriter
{
    public static string Write(CaseDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        static string E(object? value) => WebUtility.HtmlEncode(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);

        var html = new StringBuilder();
        html.AppendLine("<!doctype html>");
        html.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.AppendLine("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">");
        html.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        html.AppendLine("<title>StaticArtifactLab evidence case</title>");
        html.AppendLine("<style>body{font:15px system-ui;margin:2rem;color:#18202b;background:#f6f7f9}main{max-width:1200px;margin:auto}h1,h2{color:#10243e}.card{background:#fff;border:1px solid #d9dee7;border-radius:10px;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:.55rem;border-bottom:1px solid #e4e7ec;vertical-align:top}code{word-break:break-all}.warning,.error{font-weight:700}.warning{color:#8a4b00}.error{color:#a00018}.muted{color:#596474}</style></head><body><main>");
        html.Append("<h1>StaticArtifactLab evidence case</h1><p class=\"muted\">Schema ").Append(E(document.Schema)).Append(" · Worker ").Append(E(document.Tool.Worker)).AppendLine("</p>");
        html.Append("<section class=\"card\"><h2>Summary</h2><p>Status: <strong>").Append(E(document.Status)).Append("</strong> · Artifacts: ").Append(document.Artifacts.Count).Append(" · Findings: ").Append(document.Findings.Count).Append(" · Coverage records: ").Append(document.Coverage.Count).AppendLine("</p></section>");

        html.AppendLine("<section class=\"card\"><h2>Artifacts</h2><table><thead><tr><th>Path</th><th>Kind</th><th>Bytes</th><th>SHA-256</th><th>Selector</th></tr></thead><tbody>");
        foreach (var artifact in document.Artifacts)
        {
            html.Append("<tr><td>").Append(E(artifact.LogicalPath)).Append("</td><td>").Append(E(artifact.Kind)).Append("</td><td>").Append(artifact.Length).Append("</td><td><code>").Append(E(artifact.Sha256)).Append("</code></td><td>").Append(E(artifact.Selector.Kind)).AppendLine("</td></tr>");
        }
        html.AppendLine("</tbody></table></section>");

        html.AppendLine("<section class=\"card\"><h2>Findings</h2><table><thead><tr><th>Rule</th><th>Level</th><th>Artifact</th><th>Observation</th></tr></thead><tbody>");
        foreach (var finding in document.Findings)
        {
            html.Append("<tr><td>").Append(E(finding.RuleId)).Append("</td><td class=\"").Append(E(finding.Level.ToString().ToLowerInvariant())).Append("\">").Append(E(finding.Level)).Append("</td><td><code>").Append(E(finding.ArtifactId)).Append("</code></td><td>").Append(E(finding.Message)).AppendLine("</td></tr>");
        }
        html.AppendLine("</tbody></table></section>");

        html.AppendLine("<section class=\"card\"><h2>Coverage</h2><table><thead><tr><th>Path</th><th>Operation</th><th>Status</th><th>Reason</th><th>Detail</th></tr></thead><tbody>");
        foreach (var coverage in document.Coverage)
        {
            html.Append("<tr><td>").Append(E(coverage.LogicalPath)).Append("</td><td>").Append(E(coverage.Operation)).Append("</td><td>").Append(E(coverage.Status)).Append("</td><td>").Append(E(coverage.Reason)).Append("</td><td>").Append(E(coverage.Detail)).AppendLine("</td></tr>");
        }
        html.AppendLine("</tbody></table></section></main></body></html>");
        return html.ToString();
    }
}

public static class SarifReportWriter
{
    public static string Write(CaseDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var artifactPaths = document.Artifacts.ToDictionary(x => x.Id, x => x.LogicalPath, StringComparer.Ordinal);
        var run = new
        {
            tool = new
            {
                driver = new
                {
                    name = document.Tool.Name,
                    version = document.Tool.Version,
                    informationUri = "https://github.com/RuhrDigitalStudio/StaticArtifactLab",
                    rules = document.Findings.Select(x => x.RuleId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Select(x => new { id = x }).ToArray(),
                },
            },
            results = document.Findings.Select(finding => new
            {
                ruleId = finding.RuleId,
                level = finding.Level switch { FindingLevel.Error => "error", FindingLevel.Warning => "warning", _ => "note" },
                message = new { text = finding.Message },
                locations = new[]
                {
                    new { physicalLocation = new { artifactLocation = new { uri = artifactPaths.GetValueOrDefault(finding.ArtifactId, finding.ArtifactId) } } },
                },
                properties = new { artifactId = finding.ArtifactId, evidence = finding.Evidence },
            }).ToArray(),
        };
        var payload = new Dictionary<string, object?>
        {
            ["version"] = "2.1.0",
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["runs"] = new[] { run },
        };
        return JsonSerializer.Serialize(payload, CaseJson.CreateOptions());
    }
}
