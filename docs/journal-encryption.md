# Local activity journal encryption

Activity history is encrypted by the application before disk writes. This covers
user and privileged Endpoint Security workflow journals, network connection
history, network summary checkpoints, development diagnostics, and the experimental
agent-egress proxy's audit segments. It does not encrypt all application storage:
policy/decision databases, inventory caches, screenshots, explicitly exported
history, and pre-existing backup/snapshot copies are separate stores.

## Keys and records

Native records use CryptoKit AES-256-GCM with a fresh random nonce per record.
The version and journal purpose are authenticated. Each stored line is
`boxcop.encrypted.v1:` followed by Base64 of nonce, ciphertext and authentication
tag. Checkpoints use one such envelope. Historical `.jsonl` and `.json` filenames
remain, but the contents are no longer plaintext JSON. Unencrypted `health.json`
contains only writer/retention counters, not activity content.

A separate random 256-bit key per effective UID and journal purpose lives in macOS
Keychain (`local.boxcop.journal-encryption.v1`). User processes use their default
Keychain; root services explicitly use the System Keychain. No keys are written
beside native journals, passed as command arguments, or included in exports.
Normal writers prohibit authentication prompts. Unavailable/locked keys cause
persistence failure, surfaced through existing health reporting, with no plaintext
fallback. An already-open writer retains its key in memory until process exit.
The first successful write provisions a missing key; reads never create one.

The unprivileged experimental proxy has only a root-owned RSA-2048 public key.
Each record uses a fresh AES-256-GCM key, wrapped with RSA-OAEP-SHA256, and the
`boxcop.agent.encrypted.v1:` envelope. Its root-owned private key file is itself
AES-GCM encrypted using the privileged helper's Keychain key. The VM installer
provisions these files through the installed helper before starting the proxy.
Reinstalling preserves the existing key. Loss of Keychain keys (or the wrapped
proxy private key) makes the associated history unreadable; there is no recovery
backdoor. Back up the appropriate Keychain and encrypted history together.

This protects journal contents when files are copied without the keys. It does
not promise protection against a compromised running app or administrator, conceal
file sizes/timing, or provide an append-only tamper-proof audit chain. Retention
and record deletion remain possible. Disk encryption is a complementary layer.

## Existing history and retention

Writers migrate existing plaintext files before appending. Migration checks file
ownership/type/permissions, writes only ciphertext into private temporary files,
and replaces originals atomically. Interrupted migration can be retried; encrypted
files are not encrypted again. On failure, original files remain for recovery and
the writer does not append plaintext. Start each updated writer to migrate its
history; an inactive diagnostic log is migrated when logging is next enabled.
Old snapshots/backups and previously freed disk blocks are not securely erased.

New writes count ciphertext bytes against rotation limits. Base64 overhead means
fewer events fit in the same byte budget. Existing native segments may temporarily
expand to twice their configured limit during migration, returning to the normal
bound through rotation. Network summaries have a 24 MiB ciphertext limit to retain
the existing 12 MiB conservative content budget. Proxy legacy segments may expand
to 8 MiB each during migration, then rotate under the normal 1 MiB limit.

## Explicit plaintext export and replay

Pause/drain the relevant collector first. Run the originating installed executable
as the journal's owner (root for privileged journals). The output directory must
not already exist. Keychain may request authorization for an explicit export,
particularly if using a different executable/signature from the original writer.

```sh
/Applications/BoxCop.app/Contents/MacOS/BoxCop --export-journal workflow \
  "$HOME/Library/Application Support/BoxCop/workflows" \
  "$HOME/Desktop/workflow-export"
python3 tools/workflows/replay.py "$HOME/Desktop/workflow-export"
```

Use the executable name present in your build (older lab bundles use
`BoxCop.app/Contents/MacOS/BoxCop`). Supported purposes are `workflow`,
`network`, `network-summary`, `development`, and `agent-egress`. Source can be a
journal directory or a single file. Workflow exports include `health.json` so
replay retains loss/eviction evidence. Exports authenticate all selected records
before writing plaintext, use directories 0700/files 0600, and refuse to overwrite
an existing destination. Wrong keys, corruption and truncated encrypted records
fail export; preserve the originals for investigation. Exported plaintext must be
handled as sensitive data. Raw encrypted journals are deliberately rejected by
the Python replay/reconstruction tools.

The portable Linux core fails closed for encrypted persistence: it has no macOS
Keychain/CryptoKit backend. Pure model/replay tests still run there; encrypted
persistence tests run on macOS. Tests use injected ephemeral keys and an isolated
temporary Keychain, without creating production journal keys.

Implementation references: [Apple AES.GCM](https://developer.apple.com/documentation/cryptokit/aes/gcm)
and [Keychain authentication context](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext).
