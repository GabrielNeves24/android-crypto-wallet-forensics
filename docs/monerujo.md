# Monerujo Forensic Plugin

## Overview

The Monerujo plugin analyses Android filesystem artifacts created by `com.m2049r.xmrwallet`. It was developed and validated using Monerujo version 4.1.7 “Exolix” on Android 11.

The plugin focuses on artifact identification and metadata extraction. It reports wallet containers, application preferences, configured remote nodes and shared RingDB files. It can identify public Monero addresses exposed in readable data, but it does not decrypt Monerujo `.keys` files.

## Scope

The plugin processes the following application paths:

```text
com.m2049r.xmrwallet/
├── files/wallets/*
├── files/monero/.shared-ringdb/*
└── shared_prefs/*.xml
```

Typical artifacts include:

```text
files/wallets/<wallet-name>
files/wallets/<wallet-name>.keys
files/monero/.shared-ringdb/data.mdb
files/monero/.shared-ringdb/lock.mdb
shared_prefs/com.m2049r.xmrwallet_preferences.xml
shared_prefs/LoginActivity.xml
shared_prefs/nodes.xml
shared_prefs/selected_node.xml
shared_prefs/notice.xml
shared_prefs/PREFS_ONBOARDING.xml
```

## Processing workflow

```text
Locate Monerujo artifacts
      ↓
Hash wallet and RingDB files
      ↓
Parse SharedPreferences XML
      ↓
Extract configured and selected nodes
      ↓
Identify wallet and .keys containers
      ↓
Scan readable data for public addresses
      ↓
Validate candidate address structure
      ↓
Generate HTML and TSV reports
```

### 1. SharedPreferences

Android SharedPreferences files are parsed as XML. The plugin reports stored names, values and XML value types.

Where a known epoch-millisecond value is encountered, the plugin also reports the derived UTC timestamp. Derived timestamps are labelled separately from original values.

### 2. Remote nodes

Configured and selected Monero nodes are extracted from preference values containing the expected endpoint structure. The report distinguishes:

- `Configured Node`: a node available in the stored node list;
- `Selected Node`: the node selected by the application when the evidence was acquired.

The endpoint, port, network and label are reported when available. These values describe local application configuration and do not prove that a connection to every listed node occurred.

### 3. Wallet files

For wallet-related files, the plugin records:

- filename;
- file size;
- SHA-256 hash;
- artifact classification;
- original source path.

A file ending in `.keys` is classified as a Monero wallet key container. The plugin does not attempt to decrypt it and does not claim to recover a mnemonic, private spend key or private view key.

The corresponding wallet cache file may also be large and binary. It is treated as supporting wallet evidence, not as plaintext proof of secret-key recovery.

### 4. Shared RingDB

Files under `.shared-ringdb` are reported as LMDB-related RingDB artifacts. Readable identifiers such as ring or blackball database names may be extracted from printable strings.

These identifiers support the existence and use of Monero wallet infrastructure but are not wallet private keys and should not be interpreted as transaction attribution by themselves.

### 5. Public-address detection

Readable strings are scanned for Monero Base58 candidates with standard or integrated address lengths. Each candidate is then:

- decoded using Monero block-based Base58 rules;
- checked for a known mainnet, testnet or stagenet prefix;
- checked against the embedded checksum when Keccak-256 support is available.

The report labels these results as possible public Monero addresses. A valid public address does not reveal the private spend key or private view key.

## Validated output

The validated test report contained 51 records and no parsing errors. It identified:

- one encrypted `.keys` wallet container;
- the associated wallet cache file;
- 25 SharedPreferences entries;
- 15 configured node endpoints;
- one selected node;
- two Shared RingDB files;
- two readable RingDB identifiers.

No public Monero address was found in the accessible plaintext artifacts. This is a valid negative finding and is consistent with the `.keys` container remaining encrypted.

These numbers describe the test evidence and are not fixed plugin expectations.

## Report sections

The HTML output includes:

1. application and package identification;
2. number of identified wallet containers;
3. public-address recovery status;
4. selected node and configured-node count;
5. RingDB summary;
6. identified wallet files;
7. relevant files analysed;
8. explicit statement that `.keys` decryption was not performed;
9. a detailed provenance table.

The TSV export contains the detailed records for filtering and independent verification.

## Limitations

- The plugin was validated against Monerujo 4.1.7 “Exolix”. Later versions may change file formats or paths.
- It does not decrypt `.keys` files.
- It does not recover a mnemonic, private spend key or private view key.
- It does not parse the complete internal wallet-cache or LMDB structures.
- Printable-string scanning can only identify values present in readable form.
- Node configuration does not prove actual network communication.
- The absence of a reported public address does not prove that no wallet address exists.

## Evidence handling

Although the plugin does not recover Monero private keys, the extracted files and report can still contain sensitive operational information, including wallet names, configured nodes, preferences and device paths.

Do not publish real wallet files, `.keys` containers, complete application extractions or unsanitised ALEAPP reports. Use synthetic or fully anonymised examples in a public repository.

## Concise explanation for an oral defence

> The plugin identifies Monerujo wallet containers and calculates their hashes, parses the application's SharedPreferences, extracts configured and selected remote nodes, and records the shared RingDB artifacts. It also checks readable data for structurally valid public Monero addresses. The encrypted `.keys` file is preserved and reported as evidence, but it is not decrypted and no seed or private key is claimed as recovered.
