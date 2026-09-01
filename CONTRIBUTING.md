# Contributing

StaticArtifactLab favors evidence that can be reproduced over clever guesses.
A contribution should make the tool easier to audit, safer on hostile input, or
more explicit about work it did not perform.

## Development setup

Install the .NET 8 SDK, clone the repository, then run:

```powershell
dotnet restore StaticArtifactLab.slnx
dotnet build StaticArtifactLab.slnx -c Release --no-restore
dotnet test StaticArtifactLab.Tests/StaticArtifactLab.Tests.csproj -c Release --no-build
dotnet format StaticArtifactLab.slnx --verify-no-changes --no-restore
```

The build treats analyzer warnings as errors.

## Adding a reader or rule

Start with a failing test. Include ordinary files, malformed input, the exact
boundary, and one byte beyond it. A container reader must define a maximum
expanded size, item count, recursion depth, and total work budget before it is
enabled by default.

Rules should report observable evidence. Avoid names such as `malicious` or
`safe`; use wording such as “executable content is nested inside a container.”
If analysis is skipped or rejected, add a coverage reason rather than returning
an empty result.

Comments should explain a security boundary, binary-format decision, or
non-obvious invariant. They should not narrate straightforward assignments.

## Pull requests

Keep changes focused and describe:

- the user problem;
- the evidence added or changed;
- worst-case bytes, items, depth, and memory;
- tests for malformed and oversized input;
- case-format or compatibility impact;
- screenshots for visible WPF changes.

Do not commit samples from real incidents, secrets, generated reports with
private paths, or binaries without documented redistribution rights.
