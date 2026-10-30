# KeePass entry templates

Use `kp2bw vault.kdbx --map-templates` to migrate entries made from a KeePass entry template as native Bitwarden cards,
identities or secure notes. The default remains login items. `KP2BW_MAP_TEMPLATES=true` enables the same option.

An entry must carry `_etm_template_uuid` pointing to a template in the database marked `_etm_template=1`. Ordinary entry
names, icons and groups do not determine its type. Template definitions themselves are omitted when mapping is enabled.
The standard Keepass2Android template UUIDs work with translated titles. Other templates recognize the titles Credit
Card, Card, ID Card, Identity, Passport, Secure Note, Note and Notes, ignoring capitalization and punctuation. Unknown
templates retain the ordinary login conversion.

Card fields recognize number/card number/card no, CVV/CVC/code/security code, owner/cardholder/name, brand/type, expiry
month and expiry year. Expiry/expiration/valid thru/valid until accept `MM/YY` or `MM/YYYY`; two-digit years mean
2000–2099. Card numbers allow spaces and hyphens. Identity fields recognize the native field names, including spaced
variants such as First Name and Passport Number, plus ZIP/ZIP Code, Telephone and Social Security Number. A generic
ID-card Number or full Name remains a custom field because neither uniquely identifies a native identity field. A
KeePass entry's expiry metadata remains metadata; it is not guessed to be the expiry of a payment card.

Unrecognized, invalid and conflicting fields remain custom fields. Partial cards and identities are allowed. PIN remains
a custom field with its source protection setting. Username, password, TOTP and URLs that have no native destination are
retained together in a `KeePass login data` JSON custom field, hidden when it contains a password or TOTP. Entries with
passkeys remain logins. A type change that would discard a Bitwarden-side passkey is rejected.

## Custom or translated templates

Pass `--template-map mapping.json` together with `--map-templates`, or set `KP2BW_TEMPLATE_MAP` to the JSON file path.
Each key is the template entry's UUID (hex or hyphenated); each rule selects a type and optional exact source-field
names.

```json
{
  "00000000-0000-0000-0000-000000000001": {
    "type": "identity",
    "fields": {
      "Voornaam": "firstName",
      "Achternaam": "lastName",
      "Paspoortnummer": "passportNumber"
    }
  }
}
```

Types are `card`, `identity` and `secureNote`. Card destinations are `cardholderName`, `brand`, `number`, `expMonth`,
`expYear` and `code`. Identity destinations are `title`, `firstName`, `middleName`, `lastName`, `address1`, `address2`,
`address3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`
and `licenseNumber`. Secure notes use the entry's notes and have no additional mapped fields.

The override still requires a real template reference. It does not classify arbitrary entries or silently consume fields
that cannot be converted. Native fields participate in change detection and manual-edit protection. Keep mapping enabled
on subsequent migrations; disabling it preserves existing native items.
