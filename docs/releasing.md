# Releasing and verifying a release

A FortressGD release publishes three things, all from `.github/workflows/release.yml` on a `v*` tag (DESIGN.md §18.4):

- **Build images** on GHCR: `ghcr.io/salaryman-inc/fortressgd-build`, one per supported Godot tag and platform. Each holds a Godot tree compiled against a placeholder, so `templates build` only recompiles the project's generated file and relinks. An image holds no secret and no key.
- **The CLI's wheel and sdist.** Both carry `fortressgd/images.lock.json`, which pins each build image by `@sha256:` digest. `templates build` pulls the pinned digest and nothing else, unless you pass `--image` yourself.
- **`images.lock.json`**, also as a release asset. The `build-templates` GitHub Action fetches it when it runs at a release tag, because a git checkout of the tag cannot contain digests that only exist after the tag is built.

The workflow attests provenance for every image, the wheel, the sdist and the lock with `actions/attest-build-provenance`.

## Installing a release

Install the wheel from the release, not from a git tag. A git install has no lock, so it compiles each build image on your machine the first time (35 to 45 minutes per platform on a GitHub-hosted runner):

```bash
pip install "fortressgd[fast] @ https://github.com/salaryman-inc/FortressGD/releases/download/v0.2.0/fortressgd-0.2.0-py3-none-any.whl"
```

`fortressgd doctor` reports, for each platform the project builds, whether the pinned image is pulled.

## Verifying what you downloaded

[`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify) checks that a file or image was built by this repository's release workflow from a release tag. It fails on a tampered or foreign file.

The wheel:

```bash
gh attestation verify fortressgd-0.2.0-py3-none-any.whl --repo salaryman-inc/FortressGD \
  --signer-workflow salaryman-inc/FortressGD/.github/workflows/release.yml --source-ref refs/tags/v0.2.0
```

A build image, by the digest in `images.lock.json`:

```bash
gh attestation verify oci://ghcr.io/salaryman-inc/fortressgd-build@sha256:<digest> --repo salaryman-inc/FortressGD \
  --signer-workflow salaryman-inc/FortressGD/.github/workflows/release.yml --source-ref refs/tags/v0.2.0
```

To use no prebuilt toolchain at all, build with `fortressgd templates build --from-source`. It compiles all of Godot in a fresh container from the patches in the package.

## Cutting a release (maintainers)

1. On `main`, set the version in `fortressgd/core/version.py` and in `fortressgd/plugin/addons/fortressgd/plugin.cfg`. Merge it.
2. Create the tag on that commit and push it: `git tag v0.2.0 && git push origin v0.2.0`. Only repository admins can create, move or delete `v*` tags (see below).
3. The release workflow checks that the tag matches the version, then builds and pushes the four build images in parallel (about 45 minutes). Then it writes the lock, builds the wheel and sdist with the lock inside, and attests everything. Finally it creates a **draft** release with the wheel, the sdist and `images.lock.json` attached.
4. Read the draft. Check that the job summary lists four image digests, then publish it. The `build-templates` Action can't fetch the lock from a draft, so until you publish, it builds images on the runner.

On the first release, open the `fortressgd-build` package on GHCR and set its visibility to **public**. A package that `GITHUB_TOKEN` creates starts out private, and users can't pull a private image. The images carry `org.opencontainers.image.source`, so the package is linked to this repository, and later releases push to it with `GITHUB_TOKEN`.

If a release run fails, fix the cause on `main` and release a new patch version. Do not move the tag: the ruleset blocks it, and anything already pushed or attested points at the old commit.

## The tag ruleset

`.github/rulesets/release-tags.json` restricts creating, updating and deleting `refs/tags/v*` to repository admins. Creating a tag is what publishes, so this protects the release. An admin applies it once:

```bash
gh api --method POST repos/salaryman-inc/FortressGD/rulesets --input .github/rulesets/release-tags.json
```

To change it later, update the file, then `PUT` it to `repos/salaryman-inc/FortressGD/rulesets/<id>` (`gh api repos/salaryman-inc/FortressGD/rulesets` lists the ids).
