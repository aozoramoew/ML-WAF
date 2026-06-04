"""
File Security Middleware

Validates uploaded files against:
  - Magic bytes vs declared extension (MIME type spoofing)
  - Dangerous file type blocklist
  - EICAR test string detection
  - Embedded script detection (PHP/JSP/ASP in image files)
  - File size limits
"""

import os
import re
from typing import Optional

MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', '10'))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Magic bytes → MIME type
MAGIC_SIGNATURES = {
    b'\xff\xd8\xff':         'image/jpeg',
    b'\x89PNG\r\n\x1a\n':   'image/png',
    b'GIF87a':               'image/gif',
    b'GIF89a':               'image/gif',
    b'%PDF-':                'application/pdf',
    b'PK\x03\x04':          'application/zip',
    b'\x1f\x8b\x08':        'application/gzip',
    b'BM':                   'image/bmp',
    b'RIFF':                 'audio/wav',   # or video/avi
    b'\x00\x00\x01\x00':    'image/x-icon',
    b'\x4d\x5a':            'application/exe',  # MZ header — PE executable
    b'\x7fELF':             'application/elf',  # Linux ELF executable
    b'#!':                   'text/x-shellscript',
    b'<?php':               'text/x-php',
    b'<%':                   'text/x-jsp',
}

# Extensions considered dangerous regardless of content
DANGEROUS_EXTENSIONS = {
    '.php', '.php3', '.php4', '.php5', '.phtml', '.phar',
    '.asp', '.aspx', '.asa', '.asax', '.ashx', '.asmx',
    '.jsp', '.jspx', '.jsw', '.jsv',
    '.exe', '.dll', '.bat', '.cmd', '.sh', '.bash', '.zsh',
    '.ps1', '.vbs', '.vbe', '.js', '.jse',
    '.htaccess', '.htpasswd',
    '.py', '.rb', '.pl', '.cgi',
}

# EICAR test string (antivirus test)
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Embedded PHP/script patterns in file content
EMBEDDED_SCRIPT_PATTERNS = [
    re.compile(rb'<\?php', re.I),
    re.compile(rb'<\?=', re.I),
    re.compile(rb'<%@?\s*page', re.I),
    re.compile(rb'<asp:', re.I),
    re.compile(rb'eval\s*\(', re.I),
    re.compile(rb'exec\s*\(', re.I),
    re.compile(rb'system\s*\(', re.I),
    re.compile(rb'shell_exec\s*\(', re.I),
    re.compile(rb'Runtime\.getRuntime', re.I),
]


def _detect_magic(data: bytes) -> Optional[str]:
    for sig, mime in MAGIC_SIGNATURES.items():
        if data[:len(sig)] == sig:
            return mime
    return None


def _ext_from_filename(filename: str) -> str:
    name = filename.lower()
    # Handle double extensions like .jpg.php
    parts = name.split('.')
    return f'.{parts[-1]}' if len(parts) > 1 else ''


def scan_file(filename: str, content: bytes) -> dict:
    """
    Scan an uploaded file.

    Args:
        filename: Original file name from upload
        content:  Raw file bytes

    Returns:
        dict with block (bool), reason (str), details (dict)
    """
    ext = _ext_from_filename(filename)
    size = len(content)

    # ── 1. Size check ─────────────────────────────────────────────────
    if size > MAX_FILE_SIZE_BYTES:
        return {
            'block': True,
            'reason': f'File too large: {size/1024/1024:.1f} MB > {MAX_FILE_SIZE_MB} MB limit',
            'details': {'filename': filename, 'size': size, 'check': 'size_limit'},
        }

    # ── 2. Dangerous extension ────────────────────────────────────────
    if ext in DANGEROUS_EXTENSIONS:
        return {
            'block': True,
            'reason': f'Dangerous file type: {ext}',
            'details': {'filename': filename, 'extension': ext, 'check': 'extension_block'},
        }

    # ── 3. EICAR test string ──────────────────────────────────────────
    if EICAR in content:
        return {
            'block': True,
            'reason': 'EICAR antivirus test string detected (simulated malware)',
            'details': {'filename': filename, 'check': 'eicar'},
        }

    # ── 4. Detect real MIME type ──────────────────────────────────────
    detected_mime = _detect_magic(content)
    if detected_mime in ('application/exe', 'application/elf', 'text/x-shellscript',
                         'text/x-php', 'text/x-jsp'):
        return {
            'block': True,
            'reason': f'Executable / script content detected (magic bytes): {detected_mime}',
            'details': {'filename': filename, 'detected_mime': detected_mime, 'check': 'magic_bytes'},
        }

    # ── 5. Check for embedded scripts (polyglot files) ────────────────
    for pattern in EMBEDDED_SCRIPT_PATTERNS:
        if pattern.search(content[:8192]):   # Check first 8 KB
            return {
                'block': True,
                'reason': f'Embedded script/code detected in file content',
                'details': {'filename': filename, 'check': 'embedded_script'},
            }

    # ── 6. Double extension check (.jpg.php) ──────────────────────────
    name_lower = filename.lower()
    for dext in DANGEROUS_EXTENSIONS:
        if dext in name_lower and not name_lower.endswith(dext):
            return {
                'block': True,
                'reason': f'Double extension attack detected: {filename}',
                'details': {'filename': filename, 'check': 'double_extension'},
            }

    return {
        'block': False,
        'reason': f'File passed all security checks',
        'details': {
            'filename': filename,
            'size': size,
            'detected_mime': detected_mime or 'unknown',
            'extension': ext,
        },
    }


def check(request_data: dict) -> dict:
    """
    Check request for file upload attempts.
    Returns block=False for non-upload requests.
    """
    files = request_data.get('files', [])
    if not files:
        return {'block': False, 'reason': 'No file upload in request'}

    for f in files:
        result = scan_file(
            filename=f.get('filename', 'unknown'),
            content=f.get('content', b''),
        )
        if result['block']:
            result['attack_type'] = 'malicious_upload'
            return result

    return {'block': False, 'reason': f'{len(files)} file(s) passed security scan'}
