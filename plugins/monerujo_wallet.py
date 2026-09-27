# VERSION: 2026-07-08-MONERUJO-CRYPTOWALLET

__artifacts_v2__ = {
    "monerujo_xmrwallet_fs_root_safe": {
        "name": "Monerujo Monero Wallet FS Root Safe",
        "description": "Parses Monerujo (com.m2049r.xmrwallet) Android artifacts. Writes an HTML report summary before the detailed table, then extracts shared preferences, remote nodes, selected node, wallet file metadata, shared ringdb metadata, and possible public Monero addresses.",
        "author": "Gabriel Neves / ChatGPT",
        "creation_date": "2026-06-30",
        "last_update_date": "2026-07-08",
        "requirements": "none",
        "category": "Cryptocurrency",
        "notes": "Does not decrypt .keys wallet files and does not extract private spend/view keys or seed phrases. Reports only metadata, preferences, remote nodes, ringdb identifiers, and public-address candidates.",
        # ALEAPP path matching can be relative to the selected folder.
        # Keep both package-root patterns and direct patterns so the artifact works when the user selects:
        #   1) a full Android extraction containing data/data/com.m2049r.xmrwallet
        #   2) a parent folder containing com.m2049r.xmrwallet
        #   3) the com.m2049r.xmrwallet folder itself
        "paths": (
            "*/data/data/com.m2049r.xmrwallet/shared_prefs/*.xml",
            "*/data/data/com.m2049r.xmrwallet/files/wallets/*",
            "*/data/data/com.m2049r.xmrwallet/files/monero/.shared-ringdb/*",
            "*/com.m2049r.xmrwallet/shared_prefs/*.xml",
            "*/com.m2049r.xmrwallet/files/wallets/*",
            "*/com.m2049r.xmrwallet/files/monero/.shared-ringdb/*",
            "*/shared_prefs/*.xml",
            "*/files/wallets/*",
            "*/files/monero/.shared-ringdb/*",
            "shared_prefs/*.xml",
            "files/wallets/*",
            "files/monero/.shared-ringdb/*",
        ),
        "output_types": ["html", "tsv"],
        "artifact_icon": "coins",
        "function": "monerujo_xmrwallet",
    }
}

import csv
import datetime
import hashlib
from html import escape as html_escape
import os
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

try:
    from scripts.ilapfuncs import artifact_processor, logfunc, tsv
    from scripts.artifact_report import ArtifactHtmlReport
except Exception:
    ArtifactHtmlReport = None

    def artifact_processor(func):
        return func

    def logfunc(message):
        print(message)

    def tsv(report_folder, data_headers, data_list, tsvname, source_file=None):
        # Standalone fallback used only when the plugin is executed outside ALEAPP.
        pass


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MONERO_ADDRESS_RE = re.compile(
    r"(?<![1-9A-HJ-NP-Za-km-z])([1-9A-HJ-NP-Za-km-z]{95}|[1-9A-HJ-NP-Za-km-z]{106})(?![1-9A-HJ-NP-Za-km-z])"
)

# Known network prefixes after Monero base58 decoding.
# Mainnet: 18 standard, 19 integrated, 42 subaddress.
# Testnet: 53 standard, 54 integrated, 63 subaddress.
# Stagenet: 24 standard, 25 integrated, 36 subaddress.
MONERO_PREFIXES = {
    18: ("Mainnet", "Standard address"),
    19: ("Mainnet", "Integrated address"),
    42: ("Mainnet", "Subaddress"),
    53: ("Testnet", "Standard address"),
    54: ("Testnet", "Integrated address"),
    63: ("Testnet", "Subaddress"),
    24: ("Stagenet", "Standard address"),
    25: ("Stagenet", "Integrated address"),
    36: ("Stagenet", "Subaddress"),
}

# Monero base58 encodes 8-byte blocks into 11 chars, with a smaller final block.
ENCODED_BLOCK_SIZES = {0: 0, 1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 6: 9, 7: 10, 8: 11}
DECODED_BLOCK_SIZES = {v: k for k, v in ENCODED_BLOCK_SIZES.items() if v}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _extract_ascii_strings(data, min_len=4):
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}"
    return [x.decode("utf-8", errors="replace") for x in re.findall(pattern, data)]


def _parse_android_xml(path):
    rows = []
    try:
        root = ET.parse(path).getroot()
    except Exception as ex:
        rows.append(("Parse Error", pathlib.Path(path).name, str(ex), "", path))
        return rows

    for elem in root:
        item_type = elem.tag
        name = elem.attrib.get("name", "")
        if item_type == "string":
            value = elem.text or ""
        elif item_type == "set":
            value = "; ".join([child.text or "" for child in elem])
        else:
            value = elem.attrib.get("value", "")

        rows.append(("Shared Preference", name, value, item_type, path))

        if name == "ONBOARDING_SHOWN" and str(value).isdigit():
            try:
                dt = datetime.datetime.fromtimestamp(int(value) / 1000, datetime.timezone.utc)
                rows.append(("Timestamp", "ONBOARDING_SHOWN UTC", dt.isoformat(), "Derived from Android epoch-ms value", path))
            except Exception:
                pass

        node_info = _parse_node_value(value)
        if node_info:
            host, port, network, label = node_info
            node_type = "Selected Node" if pathlib.Path(path).name == "selected_node.xml" else "Configured Node"
            rows.append((node_type, label or host, f"{host}:{port}", f"network={network}", path))

    return rows


def _parse_node_value(value):
    if not isinstance(value, str) or "/" not in value or ":" not in value:
        return None
    parts = value.split("/")
    if len(parts) < 2:
        return None
    endpoint = parts[0]
    network = parts[1] if len(parts) > 1 else ""
    label = parts[2] if len(parts) > 2 else ""
    if ":" not in endpoint:
        return None
    host, port = endpoint.rsplit(":", 1)
    if not host or not port.isdigit():
        return None
    return host, port, network, label


def _monero_b58_decode_block(block):
    value = 0
    for char in block:
        value = value * 58 + BASE58_ALPHABET.index(char)

    decoded_size = DECODED_BLOCK_SIZES.get(len(block))
    if decoded_size is None:
        raise ValueError("Invalid Monero base58 block size")

    max_value = 256 ** decoded_size
    if value >= max_value:
        raise ValueError("Decoded block overflows expected size")

    return value.to_bytes(decoded_size, "big")


def _monero_b58_decode(address):
    decoded = bytearray()
    full_blocks = len(address) // 11
    last_block_size = len(address) % 11

    for i in range(full_blocks):
        decoded.extend(_monero_b58_decode_block(address[i * 11:(i + 1) * 11]))

    if last_block_size:
        decoded.extend(_monero_b58_decode_block(address[full_blocks * 11:]))

    return bytes(decoded)


def _keccak_256(data):
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        try:
            from Cryptodome.Hash import keccak
            k = keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()
        except Exception:
            return None


def _classify_monero_address(address):
    # Regex already checks base58 chars and typical lengths. Decode adds another sanity check.
    try:
        decoded = _monero_b58_decode(address)
    except Exception:
        return "Invalid Monero base58 candidate"

    prefix = decoded[0] if decoded else None
    network, address_type = MONERO_PREFIXES.get(prefix, ("Unknown network/prefix", f"prefix={prefix}"))

    checksum_status = "checksum not verified"
    digest = _keccak_256(decoded[:-4])
    if digest is not None:
        checksum_status = "checksum OK" if digest[:4] == decoded[-4:] else "checksum FAILED"

    return f"{network} / {address_type} / decoded_len={len(decoded)} / {checksum_status}"


def _find_monero_addresses_in_text(text):
    results = []
    seen = set()
    for match in MONERO_ADDRESS_RE.finditer(text or ""):
        address = match.group(1)
        if address in seen:
            continue
        seen.add(address)
        results.append((address, _classify_monero_address(address)))
    return results


def _scan_file_for_addresses(path):
    rows = []
    try:
        data = pathlib.Path(path).read_bytes()
    except Exception:
        return rows

    # Search readable strings in binary files, and full decoded text in XML/text files.
    strings = _extract_ascii_strings(data, min_len=8)
    text = "\n".join(strings)
    if pathlib.Path(path).suffix.lower() in (".xml", ".txt", ".json", ".log"):
        text += "\n" + _safe_read_text(path)

    for address, classification in _find_monero_addresses_in_text(text):
        rows.append(("Possible Public Monero Address", address, classification, "Regex/base58 scan; not a private key", path))
    return rows


def _parse_wallet_or_ringdb_file(path):
    rows = []
    p = pathlib.Path(path)
    try:
        size = p.stat().st_size
        sha = _sha256(path)
    except Exception as ex:
        rows.append(("File Error", p.name, str(ex), "", path))
        return rows

    rows.append(("File Metadata", p.name, f"{size} bytes", f"sha256={sha}", path))

    name_lower = p.name.lower()
    if name_lower.endswith(".keys"):
        rows.append(("Wallet Keys File", p.name, "Monero wallet key container present", "Encrypted/binary; plugin does not decrypt or extract seed/private keys", path))
    elif p.name in ("data.mdb", "lock.mdb") or ".shared-ringdb" in str(p):
        rows.append(("RingDB File", p.name, "Shared ring database artifact present", "LMDB-related file used by Monero wallet/ring data", path))

    try:
        data = p.read_bytes()
    except Exception:
        data = b""

    for s in _extract_ascii_strings(data, min_len=8):
        if s.startswith(("rings-", "blackballs", "blackballs2-")):
            rows.append(("RingDB Identifier", p.name, s, "Readable string extracted from LMDB file", path))

    rows.extend(_scan_file_for_addresses(path))
    return rows



def _monero_explorer_url(address):
    addr = str(address or "").strip()
    if not addr:
        return ""
    return f"https://xmrchain.net/search?value={addr}"


def _html_link(label, url):
    label = html_escape(str(label or ""))
    url = html_escape(str(url or ""), quote=True)
    if not url:
        return label
    return f'<a href="{url}" target="_blank">{label}</a>'


def _build_monerujo_top_html(rows, processed_sources):
    wallet_files = [r for r in rows if r[0] == "Wallet Keys File"]
    address_rows = [r for r in rows if r[0] == "Possible Public Monero Address"]
    selected_nodes = [r for r in rows if r[0] == "Selected Node"]
    configured_nodes = [r for r in rows if r[0] == "Configured Node"]
    ringdb_files = [r for r in rows if r[0] == "RingDB File"]
    ringdb_ids = [r for r in rows if r[0] == "RingDB Identifier"]
    prefs = [r for r in rows if r[0] == "Shared Preference"]
    source_names = sorted({pathlib.Path(s).name for s in processed_sources if s})

    unique_nodes = []
    seen_nodes = set()
    for r in selected_nodes + configured_nodes:
        endpoint = r[2]
        if endpoint and endpoint not in seen_nodes:
            seen_nodes.add(endpoint)
            unique_nodes.append(endpoint)

    wallet_items = []
    if address_rows:
        for idx, r in enumerate(address_rows, 1):
            address = r[1]
            wallet_items.append(
                f"<li><strong>{idx} - XMR</strong> <code>{html_escape(address)}</code> "
                f"({_html_link('open explorer', _monero_explorer_url(address))}; {html_escape(r[2])})</li>"
            )
    elif wallet_files:
        for idx, r in enumerate(wallet_files, 1):
            wallet_items.append(
                f"<li><strong>{idx} - XMR</strong> file <code>{html_escape(r[1])}</code> "
                f"(.keys container encrypted; public address not found in plaintext)</li>"
            )
    else:
        wallet_items.append("<li>No Monerujo wallet file was found in the processed artifacts.</li>")

    selected_node_txt = "Not found"
    if selected_nodes:
        selected_node_txt = "; ".join(f"{html_escape(r[1])}: <code>{html_escape(r[2])}</code>" for r in selected_nodes[:3])

    node_items = "".join(f"<li><code>{html_escape(x)}</code></li>" for x in unique_nodes[:16])
    if len(unique_nodes) > 16:
        node_items += f"<li>+{len(unique_nodes) - 16} additional node(s)</li>"

    ringdb_txt = "Not found"
    if ringdb_ids:
        ringdb_txt = "; ".join(f"<code>{html_escape(r[2])}</code>" for r in ringdb_ids[:3])
    elif ringdb_files:
        ringdb_txt = f"{len(ringdb_files)} RingDB file(s) present"

    source_items = "".join(f"<li><code>{html_escape(x)}</code></li>" for x in source_names[:12])
    if len(source_names) > 12:
        source_items += f"<li>+{len(source_names) - 12} additional file(s)</li>"

    return f"""
<div style="border:1px solid #cccccc; border-radius:8px; padding:14px; margin:12px 0 18px 0; background:#f8f9fa;">
  <h3 style="margin-top:0;">Application Forensic Summary</h3>
  <p><strong>Analyzed application:</strong> Monerujo / Monero Wallet</p>
  <p><strong>Android package:</strong> <code>com.m2049r.xmrwallet</code></p>
  <p><strong>Number of wallets:</strong> {len(wallet_files) if wallet_files else len(address_rows)}</p>
  <p><strong>Public Monero address:</strong> {'found' if address_rows else 'not found in accessible artifacts'}</p>
  <p><strong>Selected remote node:</strong> {selected_node_txt}</p>
  <p><strong>Configured nodes:</strong> {len(unique_nodes)}</p>
  <p><strong>Shared RingDB:</strong> {ringdb_txt}</p>

  <h4>Identified wallets</h4>
  <ol>
    {''.join(wallet_items)}
  </ol>

  <h4>Configured Monero nodes</h4>
  <ul>
    {node_items or '<li>No configured node found.</li>'}
  </ul>

  <h4>Relevant files analyzed</h4>
  <ul>
    {source_items or '<li>No relevant file was processed.</li>'}
  </ul>

  <p><strong>Extracted preferences:</strong> {len(prefs)} SharedPreferences entries.</p>
  <p><strong>Sensitive data:</strong> the plugin does not decrypt the <code>.keys</code> file and does not output the seed, private spend key, or private view key.</p>
</div>
"""


def _write_monerujo_html_report(report_folder, detailed_rows, source_path, top_html):
    artifact_name = __artifacts_v2__["monerujo_xmrwallet_fs_root_safe"]["name"]
    description = __artifacts_v2__["monerujo_xmrwallet_fs_root_safe"]["description"]
    if ArtifactHtmlReport is None:
        return
    report = ArtifactHtmlReport(artifact_name)
    report.start_artifact_report(report_folder, artifact_name, description)
    report.add_script()
    report.write_raw_html(top_html)
    data_headers = ("Artifact Type", "Name", "Value", "Notes", "Source File")
    report.write_artifact_data_table(data_headers, detailed_rows, source_path)
    report.end_artifact_report()


def monerujo_xmrwallet(files_found, report_folder, seeker, wrap_text):
    data_list = []
    processed_sources = []

    for file_found in files_found:
        path = str(file_found)
        if not os.path.isfile(path):
            continue

        processed_sources.append(path)
        suffix = pathlib.Path(path).suffix.lower()

        if suffix == ".xml":
            data_list.extend(_parse_android_xml(path))
            data_list.extend(_scan_file_for_addresses(path))
        else:
            data_list.extend(_parse_wallet_or_ringdb_file(path))

    # Remove duplicate rows while preserving order.
    detailed_rows = []
    seen = set()
    for row in data_list:
        key = tuple(row)
        if key in seen:
            continue
        seen.add(key)
        detailed_rows.append(row)

    data_headers = ("Artifact Type", "Name", "Value", "Notes", "Source File")
    source_path = "\n".join(processed_sources)

    if detailed_rows:
        logfunc(f"Found {len(detailed_rows):,} records for Monerujo Monero Wallet FS Root Safe")
        top_html = _build_monerujo_top_html(detailed_rows, processed_sources)
        _write_monerujo_html_report(report_folder, detailed_rows, source_path, top_html)
        tsv(report_folder, data_headers, detailed_rows, "Monerujo Monero Wallet FS Root Safe")
    else:
        logfunc("No data found for Monerujo Monero Wallet FS Root Safe")

    return data_headers, detailed_rows, source_path



def _collect_files_from_path(input_path):
    input_path = pathlib.Path(input_path)
    if input_path.is_file():
        return [str(input_path)]

    patterns = [
        "**/com.m2049r.xmrwallet/shared_prefs/*.xml",
        "**/com.m2049r.xmrwallet/files/wallets/*",
        "**/com.m2049r.xmrwallet/files/monero/.shared-ringdb/*",
        "**/data/data/com.m2049r.xmrwallet/shared_prefs/*.xml",
        "**/data/data/com.m2049r.xmrwallet/files/wallets/*",
        "**/data/data/com.m2049r.xmrwallet/files/monero/.shared-ringdb/*",
    ]

    files = []
    for pattern in patterns:
        files.extend([str(p) for p in input_path.glob(pattern) if p.is_file()])

    # Also support running directly against the package root folder.
    if input_path.name == "com.m2049r.xmrwallet":
        for rel in ["shared_prefs/*.xml", "files/wallets/*", "files/monero/.shared-ringdb/*"]:
            files.extend([str(p) for p in input_path.glob(rel) if p.is_file()])

    return sorted(set(files))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python monerujo_xmrwallet.py <extracted_android_folder_or_package_folder> [output.csv]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else "monerujo_xmrwallet_report.csv"

    files = _collect_files_from_path(input_path)
    headers, rows, source_path = monerujo_xmrwallet(files, ".", None, False)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"Processed files: {len(files)}")
    print(f"Rows written: {len(rows)}")
    print(f"Output: {output_csv}")
