# Guarda Wallet Forensic Plugin

## Overview

The Guarda Wallet plugin analyses Android artifacts created by `com.crypto.multiwallet`. It was developed and validated using Guarda Wallet version 3.0.86 on Android 11.

Its primary evidence source is the React Native `RKStorage` SQLite database. The plugin can identify the persisted backup object, use an internal backup credential already present in the evidence, decrypt a compatible backup in memory, validate recovered English BIP-39 mnemonics and present the resulting wallets in a structured ALEAPP report.

## Scope

The plugin processes the following declared artifacts when present:

```text
com.crypto.multiwallet/
├── databases/RKStorage
├── files/*/backup*.txt
├── files/mmkv/mmkv.default
├── files/mmkv/mmkv.default.crc
├── shared_prefs/com.crypto.multiwallet_preferences.xml
├── shared_prefs/react-native-device-info.xml
├── shared_prefs/WebViewChromiumPrefs.xml
└── app_webview/Default/Cookies
```

It can also process a JSON export whose filename identifies it as an `RKStorage` export.

`RKStorage` is the main source of wallet evidence. The remaining files provide supporting metadata and application context.

## Processing workflow

```text
Locate RKStorage
      ↓
Open SQLite read-only
      ↓
Enumerate tables and candidate records
      ↓
Decode nested JSON values
      ↓
Locate the Guarda backup object
      ↓
Recover internal masterPassword, if present
      ↓
Decrypt compatible encryptedData in memory
      ↓
Validate mnemonic and parse wallet records
      ↓
Generate HTML and TSV reports
```

### 1. Database access

The database is opened using SQLite read-only mode. The plugin records the source path, file size and SHA-256 hash and does not intentionally create or modify database records.

The parser does not depend on one fixed table name. It enumerates the available tables and examines likely key/value records and textual or binary columns. This allows the same workflow to tolerate small storage-schema differences while keeping the analysis focused on `RKStorage`.

### 2. JSON detection

React Native persistence can store JSON as strings nested inside other JSON objects. The parser therefore decodes container values recursively and searches for objects containing fields such as:

```text
backup
encryptedData
masterPassword
data
walletsByUuids
```

Diagnostic rows report the detected tables, columns and record counts. They are intended to show whether the database was opened and whether a backup structure was recognised.

### 3. Backup decryption

Compatible Guarda backups use an OpenSSL/CryptoJS-style payload with a `Salted__` header. The plugin performs:

- Base64 decoding;
- extraction of the salt and ciphertext;
- OpenSSL-compatible `EVP_BytesToKey` derivation using MD5;
- AES-256-CBC decryption;
- PKCS#7 padding removal;
- UTF-8 JSON parsing.

Decryption is attempted only when the internal `backup.masterPassword` is present in the acquired evidence. The plugin does not assume that the application unlock password is equivalent to this internal value, and it does not perform password guessing or brute force.

Plaintext is processed in memory and is not written as a separate decrypted backup file by the plugin.

### 4. Mnemonic validation

Recovered English mnemonics are checked against the official 2,048-word BIP-39 English list. Validation includes:

- Unicode NFKD normalisation;
- supported BIP-39 word count;
- word-list membership;
- entropy/checksum reconstruction;
- checksum comparison.

A successful result means that the words and checksum form a valid English BIP-39 mnemonic. It does not independently prove ownership of any blockchain assets.

### 5. Wallet parsing

When plaintext wallet data is available, the plugin reports, where present:

- wallet UUID or identifier;
- currency and wallet title;
- public address;
- visible balance;
- private-key fields;
- derivation metadata;
- subwallets or token wallets;
- token contract identifiers;
- backup version, UUID and update time.

The summary deduplicates logical wallets that appear both in plaintext state and in the decrypted copy. The detailed table retains provenance so that an examiner can identify the source of each value.

## Interpretation of application state

The validated evidence contained two acquisitions of the same application version.

| Application state | Observed result |
| --- | --- |
| Closed | The encrypted backup object was identified, but the internal `masterPassword` was unavailable. No wallet plaintext was recovered by the plugin. |
| Open | The internal `masterPassword` and wallet state were present. The encrypted backup was decrypted successfully and its contents were parsed. |

This difference supports the conclusion that application state at acquisition time can materially affect recoverable evidence. It should not be generalised to every Guarda version or Android configuration without additional testing.

## Validated output

The open-state test report contained:

- 10 top-level wallets;
- 9 subwallets;
- 9 unique public addresses;
- 9 token contracts;
- one visible non-zero balance;
- a valid English BIP-39 mnemonic;
- recovered wallet key material;
- successful in-memory backup decryption.

The closed-state report identified the encrypted backup but did not complete decryption. Neither report produced a parsing error.

These numbers are properties of the test dataset, not constants in the plugin.

## Report sections

The HTML output includes:

1. application and package identification;
2. wallet, address and token counts;
3. non-zero balance summary;
4. `RKStorage` parser status;
5. mnemonic and BIP-39 validation result;
6. wallet table with identifiers, addresses, balances and key fields;
7. relevant source files;
8. decryption status and evidence-handling warning;
9. a detailed provenance table.

The TSV export contains the same detailed records in a format suitable for filtering and further review.

## Limitations

- The plugin was validated against Guarda Wallet 3.0.86 and may require revision for later schemas or cryptographic formats.
- It does not acquire memory or bypass Android security controls.
- It does not crack passwords.
- It cannot decrypt the closed-state backup unless the required internal value is present in the supplied evidence set.
- Reported balances are locally persisted values and may not represent the current blockchain state.
- A missing value may reflect encryption, application state, version differences or unsupported storage rather than true absence.

## Evidence handling

The generated output may expose sufficient material to control a wallet. Treat the HTML and TSV reports as sensitive evidence.

Do not publish:

- real mnemonic phrases;
- private keys;
- internal `masterPassword` values;
- raw `RKStorage` databases;
- encrypted backup blobs;
- authentication cookies;
- complete ALEAPP reports from the real device.

For publications and repository examples, use synthetic evidence or screenshots in which sensitive values have been fully removed.

## Concise explanation for an oral defence

> The plugin opens the Guarda `RKStorage` database in read-only mode, identifies the persisted backup structure and checks whether the internal backup credential is present in the acquired evidence. When available, it decrypts the CryptoJS-compatible backup in memory, validates any recovered English mnemonic using the BIP-39 word list and checksum, and reports the wallets, identifiers, addresses, balances and key fields together with their source provenance.
