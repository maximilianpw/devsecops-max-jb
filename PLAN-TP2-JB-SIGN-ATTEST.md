<!-- Source : https://p.maximilian.pw/LjlP9yue1Maf1LjH-Nlwsg ; récupéré le 2026-10-29. -->

# TP2 — Person B: distributed cache, cosign signing, SBOM attestation, admission gate


Repo: `maximilianpw/devsecops-max-jb`. Base: `main` at `f00d13b` (PRs #8–#10 merged, last release `v1.1.0`).
Branch: `feat/tp2-sign-attest`. **This PR merges second.** Start now, then rebase on Person A's `feat/tp2-sbom-vex` once it is merged.


## Context: what already exists (do not redo)


- `docker-bake.hcl`: `app` targets (amd64 + arm64) and `app-ci` (one platform). The variable `CACHE_REF` enables `cache-from`/`cache-to` `type=registry,mode=max`, but **CI currently sets it to `""`** (`scripts/ci/build_variant.sh`) to avoid cache poisoning. The README (§8 "Caches et limites") documents that choice.

- `.github/workflows/ci.yaml`:


- `build-<arch>` (reusable workflow `tp2-build.yaml`, native runners) → `dist/image.tar` + outputs `image-id`, `archive-sha256`, `artifact-id`, `platform`, `run-attempt`;

- `scan-<arch>` (`tp2-scan.yaml`) → Dive, Trivy;

- aggregators `BuildKit + Dive`, `Trivy`, `Compose + pytest` (**required checks**, keep these names);

- `release` (tags `vX.Y.Z` only, `packages: write`) → `scripts/ci/publish_index.sh`: `crane push` of each verified archive to a staging ref, checks, `imagetools create` of the index, then tags `X.Y.Z`, `X.Y`, `X` on the **index digest**. Output `digest` = index digest;

- `verify-publication` → anonymous pull and smoke test on both archs.




- No rebuild at publication time: the bits that were tested are the bits that get published. **Keep this design** and justify it in the README against the brief's wording, which says "exécution déclarative du build multi-plateforme vers ghcr.io".

- Tools are installed by `scripts/ci/install_tools.sh` (pinned version + SHA256, no third-party actions). `check_pinning.py` enforces SHA pinning of actions.

- The release has **never been run for TP2** (no `v1.2.0` tag).




## Interface contract with Person A (what you receive)


- Artifact `sbom-<arch>-<run_attempt>` containing `sbom.cdx.json` and `sbom.spdx.json`, generated from the verified `dist/image.tar` of that arch.

- Output `needs.scan-<arch>.outputs.sbom-artifact-id` in `ci.yaml`.

- Format to attest: CycloneDX JSON.

- In `install_tools.sh` A adds `syft`/`grype` and you add `cosign`, one `case` line per tool.




**Until A merges**, generate a local SBOM (`syft scan docker-archive:dist/image.tar -o cyclonedx-json=sbom.cdx.json`) to develop and test your scripts.


## Decisions taken (defaults; tell Max if you disagree)


- **Keyless** signing via GitHub Actions OIDC (Fulcio + Rekor). No repo secret and no `cosign.pub`; the identity configuration is documented in the README.

- Publish validated archives with `crane`, no `bake --push`.

- Registry cache enabled **only for trusted refs** (push to `main` / tags).




## Tasks


### 1. Distributed cache on ephemeral runners (brief C)


- Per-arch refs that never collide with release tags: `ghcr.io/maximilianpw/devsecops-max-jb:buildcache-amd64` / `-arm64` (the `CACHE_REF` validation in `docker-bake.hcl` already rejects `CACHE_REF == IMAGE:TAG`).

- `cache-from` on every build (the package is public, so anonymous read works). `cache-to` (`mode=max`) **only** when `github.event_name == 'push'` (main or tag). Pass a boolean input to `tp2-build.yaml` and only log in to GHCR when it is true.

- `packages: write` only on the jobs that write the cache. Note that `permissions` does not accept expressions, so the token logs in to GHCR only when the input is true. Explain in the README why a PR, including one from a same-repo branch, never writes to the cache.

- Extend the leak audit: the secret must not appear in the blobs exported to the registry. A local `type=local,mode=max` export is already audited; add an audit of the registry cache, for example with `crane export` / `crane pull` of the cache manifest, then `audit_secret.py`.

- Update README §8 "Caches et limites", which currently says "La CI ne l'utilise pas".




### 2. Signing by digest (brief F)


- Pin Cosign in `install_tools.sh` (version + SHA256 of the official `cosign-linux-amd64` binary). Note: **Cosign v3 defaults to the new bundle format (OCI referrers)**. Check that `verify`, `verify-attestation` and `download attestation` behave as expected with the pinned version, and document the version.

- `release` job: add `id-token: write` on this job only.

- `publish_index.sh` must also output `amd64_digest` and `arm64_digest`, the per-platform manifest digests that are already computed.

- After the tags are set and verified: `cosign sign --yes --recursive "$REPOSITORY@$index_digest"`. This signs the index and each platform manifest. **Never sign a tag.**




### 3. SBOM attestation (brief F)


- In `release`, download A's SBOM artifacts by `artifact-id`. Checking the artifact identity follows the same principle as `image_archive.py verify` for archives.

- Check that each SBOM describes the right image: the CycloneDX `metadata.component` or the source matches the expected image ID / digest. Pick the most reliable check and test it.

- For each arch: `cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$REPOSITORY@$arch_digest"`.

- Signing and attestation happen **in the same job** as publication, or in a dependent job with `id-token: write`. That choice determines the identity used by `verify` (see the pitfall below).




### 4. Final admission gate (pipeline step 6)


New `admission` job in `ci.yaml`: `needs: release`, `permissions: {}` (public reads only), **no** `continue-on-error`, no `|| true`.


```sh
ID="https://github.com/maximilianpw/devsecops-max-jb/.github/workflows/ci.yaml@refs/tags/vX.Y.Z"
ISSUER="https://token.actions.githubusercontent.com"
cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" "$REPOSITORY@$DIGEST"
for d in "$AMD64_DIGEST" "$ARM64_DIGEST"; do
  cosign verify-attestation --type cyclonedx --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" "$REPOSITORY@$d"
done

```



- Also compare the attested predicate (component count) with the CI artifact SBOM.

- Make `verify-publication` depend on `admission`, since there is no point running an unsigned image.

- **Identity pitfall:** if signing happens in a **reusable** workflow, the certificate SAN is that workflow's path (`job_workflow_ref`), not `ci.yaml`. Keep signing in `ci.yaml`, or adjust `--certificate-identity`.




### 5. Tests before merging


- Locally: `docker run -d -p 5001:5000 registry:2` and `cosign generate-key-pair` (key mode, test only). Validate the push → sign → attest → verify logic. Keyless can only be exercised in real CI.

- Unit/failure-path tests (`tests/test_ci_failure_paths.py`): a wrong identity fails, a missing attestation fails, an SBOM from another arch is rejected, and a missing digest output stops the release before any signing.

- `flake8`, `pytest -m "not integration"`, `check_pinning.py --require-tp2` all pass locally.

- PR CI green with the 5 required checks unchanged. The release, signing and admission jobs only run on tags, so they are skipped on the PR, as before.




### 6. README


New §10 "Vérification publique (évaluateur)":


- full reference `ghcr.io/maximilianpw/devsecops-max-jb:1.2.0@sha256:<index-digest>` (placeholder until PR-C);

- exact commands for the grader, with no credentials:


```sh
cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" ghcr.io/maximilianpw/devsecops-max-jb@sha256:…
cosign verify-attestation --type cyclonedx --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" ghcr.io/…@sha256:<amd64>
# SBOM extraction (adapt to the bundle format of the pinned version)
cosign verify-attestation … | jq -r .payload | base64 -d | jq .predicate > sbom-from-registry.cdx.json
docker buildx imagetools inspect ghcr.io/maximilianpw/devsecops-max-jb:1.2.0

```



- an explanation of keyless OIDC (Fulcio, Rekor, why no `cosign.pub`), and why signing targets the digest and not the mutable tag;

- update the pipeline description in §6 (new jobs, permissions per job).




## Definition of done


- [ ]  Rebased on A's merged PR, with no regression in A's gates.

- [ ]  Registry cache active on push only, and the PR path never writes.

- [ ]  `release` signs the index (recursively) and attests both platforms, by digest only.

- [ ]  `admission` job is independent and blocking, and `verify-publication` depends on it.

- [ ]  Failure-path tests added; PR CI green.

- [ ]  README §10 written (placeholders for the digest).




## Afterwards (PR-C, with Person A, after both merges)


- Agree on and push the `v1.2.0` tag (this publishes to GHCR).

- Check that release → admission → verify-publication are all green, and note the run URL and index digest.

- Run `docker buildx imagetools inspect` (amd64 + arm64) and the §10 commands **from a machine without a GHCR login**, then paste the real output into the README.

- A commits the root SBOMs from the release artifact. You fill in the real digest in §10 and the evidence table in §8.
