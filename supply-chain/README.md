# Mirage supply chain

This directory holds the [`cargo-vet`](https://mozilla.github.io/cargo-vet/)
configuration and audits for the Mirage dependency graph.

## Why

Every cryptographic crate Mirage depends on runs inside the same address
space as live key material. A malicious or buggy dependency update can
silently:

- leak session keys through logs / telemetry,
- weaken a primitive (non-constant-time branch, reduced-round variant),
- remove zeroization on drop,
- introduce an RNG that is not cryptographically secure.

Exact version pinning (see `Cargo.toml` R14/R18) stops surprises from
patch-version drift but does not tell a reviewer whether the *current*
version was safe to begin with. That is `cargo-vet`'s job.

## Files

| File                 | Purpose                                                |
|----------------------|--------------------------------------------------------|
| `config.toml`        | import sources, policy, temporary exemptions           |
| `audits.toml`        | audits performed by Mirage maintainers                 |
| `imports.lock`       | (generated) hashes of imported third-party audit sets  |

## Workflow

First-time bootstrap (one-time per checkout):

```sh
cargo install cargo-vet --locked
cargo vet                       # prints unaudited crates
cargo vet regenerate exemptions # populate the initial exemption list
```

Day-to-day:

```sh
# after adding a new crate or bumping a version
cargo vet                       # will flag the new/changed crate as unaudited
cargo vet certify <crate> <version>
#   ... walk through the audit checklist, add a `notes =` rationale ...
git add supply-chain/audits.toml
```

CI (not yet wired; see `.github/workflows/ci.yml` TODO):

```sh
cargo vet check                 # fails if unaudited crates reach the graph
```

## Audit checklist

For any crate entering `audits.toml` under the `crypto-primitive`
criterion, the reviewer must record answers in the `notes` field to:

1. **Spec reference.** Which RFC / standard does this implement?
2. **Constant-time branches.** Any `if secret { .. } else { .. }`,
   `match secret` on non-`subtle` types, or indexing by secret-derived
   values? If so, is it documented as intentional (e.g. AEAD final-tag
   comparison via `subtle::ConstantTimeEq`)?
3. **Zeroization.** Do secret types implement `Zeroize + Drop` or use
   `Zeroizing<T>` wrappers? Are stack spills documented?
4. **RNG source.** If the crate generates randomness, what trait bound
   does it require? `OsRng` / `ChaCha20Rng` are OK; `rand::thread_rng`
   without justification is not.
5. **`unsafe` usage.** What fraction of the crate is `unsafe`? Is each
   block justified by a SAFETY comment? Any `transmute`, raw-pointer
   arithmetic on secret buffers, or FFI to C primitives?
6. **Panics.** Do any hot paths panic on adversary-controlled input?
   Panics in a server process are DoS vectors.

A `safe-to-deploy`-only audit (non-crypto) requires 1, 5, 6.

## Policy

`config.toml` sets `criteria = "safe-to-deploy"` on every crate in the
production dependency path. Dev-dependencies (proptest, criterion, etc.)
are allowed `safe-to-run` only - they must not compromise the build
host but are not trusted with runtime key material.

Imports from Mozilla, Google, Bytecode Alliance, ISRG, and Zcash are
trusted; those orgs maintain their own review processes and pulling in
their audits saves duplicate work on widely-used crates.
