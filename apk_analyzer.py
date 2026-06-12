"""
Core APK analysis logic.
An APK is a ZIP file — we extract it, parse the binary manifest,
inspect certificates, and collect all metadata.
"""
import hashlib
import json
import os
import re
import shutil
import struct
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from axml_parser import parse_manifest

WORK_DIR = Path(__file__).parent / "workspace"
WORK_DIR.mkdir(exist_ok=True)


# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _human_size(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


# ──────────────────────────────────────────────────────────────────────────────
# Certificate parsing
# ──────────────────────────────────────────────────────────────────────────────

def _parse_certificates(apk_path: Path) -> list[dict]:
    certs = []
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.serialization import pkcs7

        with zipfile.ZipFile(apk_path) as zf:
            sig_files = [n for n in zf.namelist()
                         if n.startswith('META-INF/') and
                         (n.endswith('.RSA') or n.endswith('.DSA') or n.endswith('.EC'))]
            for sig_file in sig_files:
                raw = zf.read(sig_file)
                try:
                    # PKCS#7 / CMS SignedData
                    loaded = pkcs7.load_der_pkcs7_certificates(raw)
                    for cert in loaded:
                        certs.append(_cert_info(cert, sig_file))
                except Exception:
                    pass

            # v2/v3 signing block lives outside the ZIP — skip for now
    except ImportError:
        pass
    return certs


def _cert_info(cert, source: str) -> dict:
    from cryptography.hazmat.primitives import hashes
    try:
        subject   = cert.subject.rfc4514_string()
        issuer    = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
        not_after  = cert.not_valid_after_utc.isoformat()  if hasattr(cert, 'not_valid_after_utc')  else str(cert.not_valid_after)
        serial    = str(cert.serial_number)
        der       = cert.public_bytes(
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER)
        sha1_fp   = ':'.join(f'{b:02X}' for b in
                             cert.fingerprint(__import__('cryptography.hazmat.primitives.hashes',
                                                          fromlist=['SHA1']).SHA1()))
        sha256_fp = ':'.join(f'{b:02X}' for b in cert.fingerprint(hashes.SHA256()))
        algo      = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'unknown'
    except Exception as e:
        return {'source': source, 'error': str(e)}

    return {
        'source': source,
        'subject': subject,
        'issuer': issuer,
        'serial': serial,
        'notBefore': not_before,
        'notAfter': not_after,
        'signatureAlgorithm': algo,
        'sha1Fingerprint': sha1_fp,
        'sha256Fingerprint': sha256_fp,
    }


# ──────────────────────────────────────────────────────────────────────────────
# DEX header info
# ──────────────────────────────────────────────────────────────────────────────

def _parse_dex_header(data: bytes) -> dict:
    """Extract class/method/field counts from DEX header."""
    if len(data) < 112:
        return {}
    try:
        magic   = data[:8]
        if not magic.startswith(b'dex\n'):
            return {}
        version = magic[4:7].decode('ascii', errors='replace')
        # Offsets per DEX spec (little-endian u32)
        def u32(off): return struct.unpack_from('<I', data, off)[0]
        return {
            'dexVersion': version,
            'stringCount': u32(56),
            'typeCount':   u32(64),
            'protoCount':  u32(72),
            'fieldCount':  u32(80),
            'methodCount': u32(88),
            'classCount':  u32(96),
        }
    except Exception:
        return {}


# ──────────────────────────────────────────────────────────────────────────────
# Strings from resources.arsc (best-effort)
# ──────────────────────────────────────────────────────────────────────────────

def _extract_printable_strings(data: bytes, min_len: int = 5) -> list[str]:
    """Fast regex-based printable string extractor. Caps input at 5 MB."""
    chunk = data[:5_000_000]
    pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',200}')
    seen: set[str] = set()
    result: list[str] = []
    for m in pattern.finditer(chunk):
        s = m.group().decode('ascii', errors='replace')
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Main analyzer
# ──────────────────────────────────────────────────────────────────────────────

def analyze_apk(apk_path: Path) -> dict:
    """
    Full APK analysis. Returns a dict saved as analysis.json in the workspace.
    """
    apk_id = str(uuid.uuid4())
    work   = WORK_DIR / apk_id
    work.mkdir(parents=True)

    # Copy APK into workspace
    dest_apk = work / apk_path.name
    shutil.copy2(apk_path, dest_apk)

    extracted = work / 'extracted'
    extracted.mkdir()

    result: dict = {
        'id':        apk_id,
        'filename':  apk_path.name,
        'fileSize':  apk_path.stat().st_size,
        'fileSizeHuman': _human_size(apk_path.stat().st_size),
        'sha256':    _sha256(apk_path),
        'md5':       _md5(apk_path),
        'analyzedAt': datetime.now(timezone.utc).isoformat(),
        'manifest':  {},
        'permissions': [],
        'components': {},
        'files':     [],
        'dex':       [],
        'nativeLibs': [],
        'assets':    [],
        'certificates': [],
        'strings':   [],
        'errors':    [],
    }

    # ── Extract ZIP ───────────────────────────────────────────────────────────
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            zf.extractall(extracted)

            all_files = []
            for info in zf.infolist():
                entry = {
                    'path':          info.filename,
                    'size':          info.file_size,
                    'compressedSize': info.compress_size,
                    'sizeHuman':     _human_size(info.file_size),
                    'compressType':  info.compress_type,
                }
                all_files.append(entry)
            result['files'] = all_files

    except Exception as e:
        result['errors'].append(f'ZIP extraction: {e}')
        _save(work, result)
        return result

    # ── Manifest ─────────────────────────────────────────────────────────────
    manifest_path = extracted / 'AndroidManifest.xml'
    if manifest_path.exists():
        try:
            manifest_data = parse_manifest(manifest_path.read_bytes())
            result['manifest']     = manifest_data
            result['permissions']  = manifest_data.get('permissions', [])
            result['components']   = {
                'activities': manifest_data.get('activities', []),
                'services':   manifest_data.get('services', []),
                'receivers':  manifest_data.get('receivers', []),
                'providers':  manifest_data.get('providers', []),
            }
        except Exception as e:
            result['errors'].append(f'Manifest parsing: {e}')
    else:
        result['errors'].append('AndroidManifest.xml not found in APK')

    # ── DEX files ─────────────────────────────────────────────────────────────
    for dex_file in sorted(extracted.glob('*.dex')):
        try:
            header = _parse_dex_header(dex_file.read_bytes())
            header['name'] = dex_file.name
            header['size'] = dex_file.stat().st_size
            header['sizeHuman'] = _human_size(dex_file.stat().st_size)
            result['dex'].append(header)
        except Exception as e:
            result['errors'].append(f'DEX {dex_file.name}: {e}')

    # ── Native libraries ──────────────────────────────────────────────────────
    lib_dir = extracted / 'lib'
    if lib_dir.is_dir():
        for so_file in sorted(lib_dir.rglob('*.so')):
            rel = so_file.relative_to(extracted)
            result['nativeLibs'].append({
                'path': str(rel),
                'abi':  rel.parts[1] if len(rel.parts) > 1 else 'unknown',
                'name': so_file.name,
                'size': so_file.stat().st_size,
                'sizeHuman': _human_size(so_file.stat().st_size),
            })

    # ── Assets ────────────────────────────────────────────────────────────────
    assets_dir = extracted / 'assets'
    if assets_dir.is_dir():
        for asset in sorted(assets_dir.rglob('*')):
            if asset.is_file():
                rel = asset.relative_to(extracted)
                result['assets'].append({
                    'path': str(rel),
                    'name': asset.name,
                    'size': asset.stat().st_size,
                    'sizeHuman': _human_size(asset.stat().st_size),
                    'ext': asset.suffix.lower(),
                })

    # ── Certificates ─────────────────────────────────────────────────────────
    try:
        result['certificates'] = _parse_certificates(apk_path)
    except Exception as e:
        result['errors'].append(f'Certificate parsing: {e}')

    # ── Strings (from resources.arsc — printable runs) ────────────────────────
    arsc = extracted / 'resources.arsc'
    if arsc.exists():
        try:
            raw = arsc.read_bytes()
            strings = _extract_printable_strings(raw, min_len=5)
            # Filter noise: keep strings with letters and reasonable length
            filtered = [s for s in strings
                        if any(c.isalpha() for c in s) and len(s) <= 200]
            result['strings'] = filtered[:2000]  # cap at 2000
        except Exception as e:
            result['errors'].append(f'String extraction: {e}')

    _save(work, result)
    return result


def _save(work: Path, result: dict):
    with open(work / 'analysis.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────────────────────────────────────
# Workspace queries
# ──────────────────────────────────────────────────────────────────────────────

def list_apks() -> list[dict]:
    apks = []
    for analysis_file in WORK_DIR.glob('*/analysis.json'):
        try:
            with open(analysis_file, encoding='utf-8') as f:
                data = json.load(f)
            apks.append({
                'id':          data.get('id'),
                'filename':    data.get('filename'),
                'fileSize':    data.get('fileSize'),
                'fileSizeHuman': data.get('fileSizeHuman'),
                'analyzedAt':  data.get('analyzedAt'),
                'package':     data.get('manifest', {}).get('package', ''),
                'versionName': data.get('manifest', {}).get('versionName', ''),
            })
        except Exception:
            pass
    return sorted(apks, key=lambda x: x.get('analyzedAt', ''), reverse=True)


def load_analysis(apk_id: str) -> dict | None:
    path = WORK_DIR / apk_id / 'analysis.json'
    if not path.exists():
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def delete_apk(apk_id: str) -> bool:
    work = WORK_DIR / apk_id
    if work.exists():
        shutil.rmtree(work)
        return True
    return False


def get_extracted_file(apk_id: str, file_path: str) -> Path | None:
    """Return Path to an extracted file, or None if not found / path escape."""
    base = WORK_DIR / apk_id / 'extracted'
    target = (base / file_path).resolve()
    if not str(target).startswith(str(base.resolve())):
        return None  # path traversal guard
    return target if target.exists() and target.is_file() else None
