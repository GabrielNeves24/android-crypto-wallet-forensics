# android-crypto-wallet-forensics

ALEAPP plugins for the forensic analysis of Android cryptocurrency wallet artifacts.

This repository accompanies the master's dissertation **Forensic Analysis of Cryptocurrency Wallets on Android**, developed at the Polytechnic of Leiria. It contains independent parsers for Guarda Wallet and Monerujo evidence acquired from an authorised Android device.

## Included plugins

| Plugin | Android package | Tested version | Main purpose |
| --- | --- | --- | --- |
| `guarda_wallet.py` | `com.crypto.multiwallet` | 3.0.86 | Parse `RKStorage`, recover the internal backup credential when present, decrypt compatible Guarda backups, validate English BIP-39 mnemonics, and report wallets, addresses, balances and key material. |
| `monerujo_wallet.py` | `com.m2049r.xmrwallet` | 4.1.7 “Exolix” | Report wallet-file metadata, SharedPreferences, remote nodes and RingDB artifacts, and identify valid public Monero address candidates when available in plaintext. |

The plugins are kept separate because the applications use different storage formats and require different forensic processing.

## Repository structure

```text
android-crypto-wallet-forensics/
├── README.md
├── plugins/
│   ├── guarda_wallet.py
│   └── monerujo_wallet.py
└── docs/
    ├── guarda-wallet.md
    └── monerujo.md
```

## Requirements

- A current Python 3 installation supported by ALEAPP.
- ALEAPP with support for `__artifacts_v2__` plugins.
- PyCryptodome for Guarda backup decryption. The plugin can use `cryptography` as a fallback.
- A lawfully acquired Android filesystem or application-level extraction.

The Monerujo plugin has no additional Python dependency. Keccak support from PyCryptodome is used when available to verify Monero address checksums.

## Installation

1. Copy each Python file from `plugins/` into the ALEAPP artifacts directory used by the local installation.
2. Start ALEAPP and confirm that the following artifacts are listed:
   - **Crypto Multiwallet Guarda Wallet**
   - **Monerujo Monero Wallet FS Root Safe**
3. Select the Android extraction and run the relevant artifact.
4. Review the generated HTML summary and TSV export together with the source-file paths.

Keep the two plugin files independent. They may be enabled in the same ALEAPP execution, but each plugin produces its own report.

## Forensic approach

The plugins follow a targeted and reproducible workflow:

1. Process only declared application artifacts.
2. Preserve the original source path in every reported record.
3. Calculate SHA-256 hashes for relevant files.
4. Open SQLite evidence in read-only mode.
5. Parse known data structures without modifying the source evidence.
6. Separate observed values from derived or validated results.
7. Report limitations explicitly when protected data cannot be recovered.

These plugins support artifact interpretation after acquisition. They do not replace evidence acquisition, chain-of-custody documentation or independent examiner verification.

## Limitations

- Results are based on the tested application versions and Android 11 evidence.
- Future application updates may change paths, schemas or cryptographic formats.
- Guarda decryption is attempted only when a compatible internal `backup.masterPassword` is already present in the acquired evidence. The plugin does not crack or guess user passwords.
- The Monerujo plugin does not decrypt `.keys` files and does not recover seed phrases, private spend keys or private view keys.
- A value not reported by a plugin must not automatically be interpreted as absent from the device.

See [Guarda Wallet documentation](docs/guarda-wallet.md) and [Monerujo documentation](docs/monerujo.md) for implementation details and interpretation guidance.

## Responsible use

This project is intended for academic research, incident response and authorised digital-forensic examinations. Users are responsible for ensuring that acquisition and analysis are lawful and properly authorised.

## Development disclosure

The research design, evidence acquisition, validation and interpretation were conducted by Gabriel Vieira Neves. Generative AI assistance was used during code development, restructuring, documentation and language review, as disclosed in the dissertation.
