# Managing the project secret

FortressGD's source is public. The only thing an attacker does not have is your project's 32-byte secret. Everything the toolchain derives — the AES key, the pack magic and index layout, the mangled names, the pack-signing key — comes from it. Treat it like a signing key.

## Rules

- Generate it with `fortressgd secret generate`. Do not type, copy from an example, or derive it from a password.
- Never commit it. `fortressgd init` suggests a `.gitignore` entry for `.fortressgd.secret`.
- Never put it under `res://`, in `export_presets.cfg`, in a workflow file, or in a CI variable that is not marked secret.
- Keep the file at mode `0600`.

`fortressgd doctor` fails when:

- the secret file can be read by group or others (fix with `chmod 600 .fortressgd.secret`);
- the secret is a repeating pattern such as `00…`, `ff…`, `deadbeef…`, or `0123456789abcdef…`;
- the secret has fewer than 16 distinct byte values, which CSPRNG output practically never does.

A missing secret is a warning, so `doctor` still works on a fresh project before you generate one.

## Where to keep it

The CLI reads, in order: `--secret-file` (default `.fortressgd.secret` in the project root), then the `FORTRESSGD_SECRET` environment variable. The editor plugin uses the same order.

For anything beyond a single developer machine, keep the canonical copy in a managed store and hand it to FortressGD through `FORTRESSGD_SECRET` for the length of one command:

```bash
# AWS Secrets Manager
FORTRESSGD_SECRET="$(aws secretsmanager get-secret-value --secret-id mygame/fortressgd \
  --query SecretString --output text)" fortressgd export --preset Linux

# Google Secret Manager
FORTRESSGD_SECRET="$(gcloud secrets versions access latest --secret=fortressgd)" \
  fortressgd export --preset Linux

# 1Password CLI
FORTRESSGD_SECRET="$(op read 'op://Build/FortressGD/secret')" fortressgd export --preset Linux
```

In GitHub Actions, store it as an encrypted **Actions secret** and pass it as `${{ secrets.FORTRESSGD_SECRET }}`. Do not use a repository variable, an environment variable defined in the workflow file, or a matrix value: those appear in the run metadata. See [`ci.md`](ci.md) for what the template-build Action does to keep the secret out of logs and caches.

Keep an offline backup. A lost secret cannot be recovered, and without it you cannot build a template that loads your shipped packs or reproduce a mangling map.

## Key epochs: a new pack key per release line

Rotation (below) replaces everything the secret derives. To limit what one extracted pack key opens without rotating, bump `[production].key_epoch` in `.fortressgd.toml` for a new release line:

1. Set `key_epoch = N` (any integer above the last one you shipped) and commit it.
2. Rebuild templates (`fortressgd templates build`, or the Action with `key_epoch: "N"`). Their names gain `-eN`.
3. Export and ship as usual.

Only the pack AES key changes. The secret, `secret_hash`, mangled names, the pack format and the signing key stay the same, so CI secrets need no update and source maps stay comparable. Packs made for one epoch do not load in templates for another: a patch or DLC pack must use the epoch of the game it is loaded into. Keep old epochs' templates if you still build patches for those releases.

## Rotation runbook

Rotate when the secret may have leaked (it appeared in a log, a commit, a screenshot, an artifact, or a departed team member's machine) or when `doctor` reports it as weak.

What changes: the derived AES key, the pack dialect, the mangled names, the pack-signing key, and `secret_hash`. Packs and executables built with the old secret will **not** load in templates built with the new one, and the new templates will not load old packs. That is intended: a leaked secret must stop opening new builds.

1. **Back up the old secret** somewhere offline. You need it to read old source maps and to rebuild old releases.
2. **Generate the new secret.**
   ```bash
   fortressgd secret generate --force
   chmod 600 .fortressgd.secret
   fortressgd doctor
   ```
   If you use a managed store, write the new value there and update the Actions secret.
3. **Rebuild templates** for every Godot version and platform you ship. The cache key includes `secret_hash`, so old cache entries are not reused.
   ```bash
   fortressgd templates build
   fortressgd templates list
   ```
   Delete cache entries for the old `secret_hash` (from `~/.cache/fortressgd/templates/` and from the Actions cache) once nothing needs them.
4. **Re-export and verify** every release target.
   ```bash
   fortressgd export --preset Linux
   fortressgd verify build/game.pck
   ```
5. **Ship the whole build.** The executable and every pack must come from the same secret. Patch-only updates that ship a new pack against an old executable will not load.
6. **Revoke the old value** in every store and CI secret that held it.

If the old secret leaked, assume builds made with it can be decrypted with stock tools and that the pack layout is known. Rotation protects future builds, not ones already shipped.
