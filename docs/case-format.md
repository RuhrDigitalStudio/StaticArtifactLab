# Case v2 format

`static-artifact-case/v2` is the stable evidence document written by
StaticArtifactLab 1.x. JSON property names use camel case and enum values use
lower camel case. Writers use UTF-8 without a byte-order mark and LF line
endings.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema` | Exact value `static-artifact-case/v2`. |
| `tool` | Tool, semantic version, rule-set version, and fixed worker ID. |
| `createdUtc` | Time the run began; excluded from replay comparison. |
| `inputPath` | Absolute file or directory used for replay. |
| `limits` | Every resource bound applied by the worker. |
| `status` | `complete` or `partial`. |
| `artifacts` | Roots followed by accepted children in deterministic traversal order. |
| `findings` | Evidence-linked observations. |
| `coverage` | Successful, skipped, and rejected operations. |

## Artifact evidence

Each artifact contains:

- `id`: 24 lowercase hexadecimal characters derived from the canonical tuple;
- `parentId`: absent for a root, otherwise the already-recorded parent ID;
- `depth`, `name`, and `logicalPath`;
- detected `kind`, `mediaType`, original extension, and container flag;
- byte `length`, lowercase SHA-256, and Shannon byte entropy;
- a typed `selector`;
- optional, ordinally sorted format metadata.

The canonical ID input is four LF-separated values:

```text
parent-id or "root"
canonical selector
decimal byte length
lowercase SHA-256
```

SHA-256 is computed over that UTF-8 text; the first 24 lowercase hexadecimal
characters become the artifact ID. The ID is a stable reference, not a security
substitute for the full content digest.

## Selectors

### Root

A root selector has `kind: "root"`, the deterministic `rootIndex`, a
`rootName`, and the `sourcePath` used to read it. Directory inputs assign
indices during deterministic ordinal directory traversal.

Case loading never reads `sourcePath`. Source verification is an explicit
operation, stays within `inputPath`, and rejects UNC paths and reparse points.

### ZIP entry

A ZIP selector has `kind: "zip-entry"`, `entryIndex`, normalized `entryName`,
and `parentSha256`. Verification opens the recorded parent bytes, locates that
exact ordinal/name pair, applies the recorded size bound, and re-hashes the
expanded child.

Unsafe absolute or parent-traversing entry names are never accepted as
artifacts. They appear as a finding and rejected coverage instead.

## Coverage

Coverage is part of the evidence, not debug logging. Each record has a logical
path, operation, status, reason, detail, and optional artifact ID.

`analyzed` means the named operation completed. `skipped` means a supported
workflow was intentionally not attempted. `rejected` means bytes or structure
violated a bound or validity rule. Any skipped or rejected record makes the
case `partial`.

## Compatibility

Readers must reject unknown schema identifiers. New optional fields may be
added within v2, but fields that change selector meaning, canonical IDs, or
verification require a new schema. Rule-set changes use `tool.ruleSetVersion`;
worker changes use `tool.worker`.
