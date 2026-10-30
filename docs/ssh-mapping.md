# SSH keys

Use `--ssh-map ssh-map.json` to select KeePass entries explicitly and migrate supported keys as native SSH items:

```json
[
  {
    "group": "Work/Servers",
    "fields": {
      "privateKey": "Private Key",
      "publicKey": "Public Key"
    }
  }
]
```

Group paths match exactly. Instead of `group`, a rule can select a marked template by its UUID using `template`, or a
custom field using `"field": { "name": "Type", "value": "SSH" }`. An entry must match at most one rule. Entry titles
alone do not select SSH conversion.

`privateKey` is required. `publicKey` and `keyFingerprint` are optional; supplied values must match the private key.
Unencrypted RSA and Ed25519 keys in OpenSSH or PEM format are supported. The public key and SHA256 fingerprint are
derived from the private key. Encrypted, malformed, unsupported or mismatched keys stay in login items with a warning.
The original private key is retained as a hidden field; oversized source values are retained as attachments. Existing
native SSH items are preserved if their replacement source key cannot be converted.

Before writing native SSH items, kp2bw checks the CLI, server capability and organization policies. Missing or ambiguous
policy information stops the migration before writes. Use the same CLI profile you normally use for migration.

Unchanged reruns preserve item IDs and revisions. Key changes update the existing item, while manual Bitwarden edits
remain protected by the normal update rules. `KP2BW_SSH_MAP` is the environment-variable equivalent of `--ssh-map`.
