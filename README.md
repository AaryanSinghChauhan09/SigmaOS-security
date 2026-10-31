# SigmaOS-security

Part of the SigmaOS multi-repository architecture.

## Principles
- MODULARITY: Single responsibility per repository
- LOOSE COUPLING: Minimal dependencies between repos
- INTERFACE SEGREGATION: Clear, focused public APIs
- DETERMINISTIC TESTING: Comprehensive test coverage

## Password and entropy boundaries

PAM stores Argon2id hashes in PHC string format with a fresh 16-byte salt from
the host operating system's entropy source. Password verification uses the
parameters encoded with each hash. On `target_os = "none"`, entropy requests
return an error until a SigmaOS platform RNG is connected; the code never falls
back to a predictable seed.

The `PamUser.password_hash` field now contains the encoded PHC string instead
of a fixed 32-byte placeholder hash. Existing in-memory user records must be
recreated; there is no persisted account store in this component.

GitHub Actions checks out the private `SigmaOS-kernel` path dependency. Configure
the repository secret `SIGMAOS_REPO_TOKEN` with read access to that repository
for the Rust validation workflow to run.

## License
SPDX-License-Identifier: GPL-3.0-or-later

## Copyright
Copyright (C) 2026 SigmaOS Project
