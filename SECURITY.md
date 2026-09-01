# Security policy

## Supported versions

Security fixes are applied to the latest tagged 1.x release. Version
`1.0.0-rc.1` is a release candidate and should be evaluated before it is
used in an incident workflow.

## Analysis invariants

StaticArtifactLab is designed around a small set of rules that must survive
feature work:

- input files are opened read-only;
- input code is never executed and input .NET assemblies are never loaded;
- analysis performs no network requests;
- UNC paths are rejected, and loading a case never authorizes its source paths;
- source-byte verification is an explicit action limited to the recorded local
  input boundary;
- archive entries are not written to disk;
- filesystem reparse points and symbolic links are not followed;
- root, child, total-byte, entry, depth, artifact, ratio, and finding limits are
  checked before more work is accepted;
- skipped and rejected work is recorded as coverage;
- HTML output encodes evidence text and loads no active or remote content;
- a finding is never presented as a malware or safety verdict.

Pull requests that weaken one of these properties need a written threat-model
update and adversarial tests.

## Untrusted inputs

The parser still consumes attacker-controlled bytes. Run it with the lowest
filesystem privileges that can read the evidence. Keep source material outside
shared or auto-executed locations, and review generated reports before sharing
them. JSON and SARIF intentionally contain names, paths, hashes, and findings.

StaticArtifactLab does not create a forensic chain of custody, authenticate an
artifact, validate a code signature, or prove that a quiet file is safe.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Include
the affected version, a minimal non-sensitive reproducer, expected bound, actual
behavior, and whether confidentiality, integrity, or availability is affected.
Do not attach live malware or confidential investigation material to a public
issue.
