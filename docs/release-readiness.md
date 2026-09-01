# Release readiness: 1.0.0-rc.1

This file records the checks for the first public release candidate. Results
must be replaced with a fresh run after any code change.

## Required checks

- [x] Release build succeeds with zero warnings and errors.
- [x] All 43 tests pass in Release configuration.
- [x] `dotnet format --verify-no-changes` passes.
- [x] `git diff --check` passes.
- [x] Case JSON, HTML, and SARIF smoke outputs parse successfully.
- [x] `verify` succeeds for unchanged nested source bytes.
- [x] `replay` matches unchanged input and reports a changed input.
- [x] Windows x64 self-contained CLI and GUI packages publish.
- [x] Linux x64 self-contained CLI package publishes.
- [x] Published CLI completes a nested ZIP smoke run.
- [x] Published GUI starts, responds, exposes the workflow controls, and closes.
- [x] Versioned screenshot contains no personal path or incident data.
- [x] Staged files contain no secrets, build output, or unexpected binaries.

## Verification record

Recorded on 2026-09-01 from commit `155a4e0` plus the staged release files:

- `dotnet build StaticArtifactLab.slnx -c Release`: zero warnings, zero errors;
- 43 passed tests, zero failed or skipped;
- format verification and whitespace checks passed;
- self-contained publishes completed for CLI `win-x64` and `linux-x64`, and
  GUI `win-x64`;
- the published Windows CLI analyzed a nested ZIP as 3 artifacts, 2 findings,
  and 4 coverage records with complete status;
- case schema was `static-artifact-case/v2`, SARIF version was `2.1.0`, HTML
  contained the restrictive CSP, and the input SHA-256 was unchanged;
- published `verify` checked 3 of 3 artifacts with no unavailable evidence;
- published `replay` reported zero added, removed, or changed paths;
- the published GUI was responsive and exposed 71 automation elements after
  its lazy tabs were materialized, including Evidence, Findings, and Coverage;
- `docs/images/gui-overview-final.png` was visually reviewed and contains only
  neutral test names.

## Maintainer decisions before a public tag

- Confirm that MIT is the intended repository license.
- Enable GitHub private vulnerability reporting.
- Create the public `RuhrDigitalStudio/StaticArtifactLab` repository.
- Push the reviewed branch and tag `v1.0.0-rc.1` only after the checks above are
  current.
