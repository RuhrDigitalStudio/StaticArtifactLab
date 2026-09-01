# Changelog

All notable changes are documented here. Versions follow Semantic Versioning.

## [1.0.0-rc.1] - 2026-09-01

### Added

- deterministic `static-artifact-case/v2` evidence model;
- byte-based recognition for executable, archive, document, image, script, and
  text formats;
- bounded recursive ZIP-compatible container traversal;
- root and ZIP-entry selectors bound to SHA-256 content records;
- seven evidence rules for mismatches, nesting, path traversal, expansion,
  duplicates, entropy, and PNG trailing data;
- explicit analyzed, skipped, and rejected coverage records;
- structural and source-byte verification;
- deterministic worker replay with added, removed, and changed paths;
- standalone HTML and SARIF 2.1 exports;
- `prove`, `verify`, and `replay` CLI workflows with stable exit codes;
- Windows WPF evidence workbench with artifact tree, findings, coverage,
  verification, replay, cancellation, and report export;
- adversarial boundary, report safety, CLI, and GUI contract tests.

[1.0.0-rc.1]: https://github.com/RuhrDigitalStudio/StaticArtifactLab/releases/tag/v1.0.0-rc.1
