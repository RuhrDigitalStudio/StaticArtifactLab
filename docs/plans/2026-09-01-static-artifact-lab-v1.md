# StaticArtifactLab 1.0 design

## Purpose

StaticArtifactLab turns an unknown file or directory into a reproducible,
offline evidence case. It is intended for defenders, incident responders, and
software maintainers who need to understand what was actually inspected before
they decide what an artifact means.

It complements the other RuhrDigitalStudio tools:

- Detector explains suspicious code and imported runtime evidence.
- BinDiff compares two binaries.
- PixelSteg packages and recovers user data in PNG images.
- StaticArtifactLab records a bounded artifact tree and proves how each child
  was obtained from its parent.

It never executes an input, loads an input assembly, follows a symbolic link,
or contacts a network service.

## User workflows

### Prove

`static-artifact prove <input>` creates a case-v2 JSON document. A root is
bound to its source path, length, and SHA-256. A nested child is bound to its
parent artifact, a typed selector, and its own length and SHA-256. Supported
selectors in 1.0 are filesystem roots and ZIP entry indices/names.

The worker recognizes common executable, archive, document, image, and text
formats by bytes rather than trusting extensions. ZIP, JAR, NuGet, APK, and
OOXML packages share the same bounded archive reader.

### Verify

`static-artifact verify <case>` validates the schema, stable artifact IDs,
parent/selector relationships, bounds, root files when supplied, and report
integrity. Verification distinguishes invalid evidence from evidence that
cannot be checked because source bytes are unavailable.

### Replay

`static-artifact replay <case>` re-runs the current deterministic worker over
the recorded roots and reports added, removed, or changed artifact evidence.
It does not pretend that results from different rule versions are identical.

## Bounded analysis

Defaults are deliberately conservative and always recorded in the case:

- 100 MiB maximum root file size
- 100 MiB maximum expanded artifact size
- 512 MiB total expanded bytes
- 5,000 accepted artifacts
- 20,000 filesystem nodes considered
- 1,000 entries per archive
- 8 container levels
- 200:1 maximum expansion ratio
- 2,000 findings

Rejected or skipped work becomes a coverage record with a machine-readable
reason. Partial analysis must never look complete.

## Findings

Findings are observations, not verdicts. The initial rules cover:

- extension and detected-format mismatch
- executable content nested in a container
- archive path traversal and absolute paths
- encrypted or unsupported archive entries
- excessive expansion ratio or declared size
- duplicate content under multiple selectors
- high-entropy opaque data
- trailing data after a PNG end marker

Every finding references one artifact and states its rule, level, message, and
evidence properties. SARIF maps the same records without inventing extra facts.

## Case format

`static-artifact-case/v2` uses stable property ordering and ordinal sorting.
Artifact IDs are the first 24 lowercase hexadecimal characters of the SHA-256
over the canonical parent/selector/content tuple. Cases include tool version,
rule-set version, UTC creation time, limits, roots, artifacts, findings,
coverage, and aggregate status.

Timestamps are excluded from comparison in replay. HTML output is encoded and
uses no remote assets or active script.

## Architecture

- `StaticArtifactLab.Core`: models, format recognition, bounded traversal,
  rules, stable serialization, verification, replay, HTML and SARIF writers.
- `StaticArtifactLab.Cli`: `prove`, `verify`, and `replay` commands.
- `StaticArtifactLab.Gui`: Windows WPF workbench over the same core API.
- `StaticArtifactLab.Tests`: unit, adversarial-boundary, serialization,
  report-safety, CLI-contract, and deterministic replay tests.

## Delivery sequence

1. Establish case model, canonical IDs, and validation tests.
2. Add byte recognition and root traversal with strict file limits.
3. Add bounded ZIP traversal and selector provenance.
4. Add evidence rules, coverage, safe reports, verification, and replay.
5. Add CLI, then the WPF workbench.
6. Publish documentation, screenshot, CI, release workflow, and run the full
   release-readiness audit.

## Explicit non-goals

The project is not an antivirus, sandbox, detonation service, disassembler,
decompiler, signature authority, or forensic proof of origin. It does not
claim that a clean report means a file is safe.
