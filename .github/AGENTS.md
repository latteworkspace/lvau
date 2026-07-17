# CI and Release Instructions

These rules add to the repository-level `AGENTS.md`.

- Pin third-party Actions to reviewed full commit SHAs and leave the upstream
  major-version comment. Let Dependabot surface updates for review.
- Set workflow/job `permissions` to the minimum needed and use
  `persist-credentials: false` unless a reviewed step genuinely needs Git
  credentials.
- Use `--locked`; run fmt, Clippy with `-D warnings`, tests, self-test, and an
  encryption roundtrip before release. Keep Linux, Windows, and macOS CLI smoke
  coverage.
- A release is tag-only. Do not add an unguarded `workflow_dispatch` path or
  create a release from an arbitrary branch.
- Validate SemVer tag, every workspace crate version, and `CHANGELOG.md` before
  building. Asset names, README instructions, and site metadata must agree.
- Preserve checksums, CycloneDX SBOM generation, and GitHub artifact
  attestations. A checksum is not a signature; do not describe it as one.
- Never print or persist secrets. Cloud deploy workflows require protected
  environments, pinned host identity, temporary owner-only secret files,
  health checks, and rollback.
- Do not push tags, publish releases, or deploy without explicit authorization.

Parse workflow YAML and run `actionlint` when available after edits. Shellcheck
all embedded or referenced shell scripts.
