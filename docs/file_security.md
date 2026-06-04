# `file_security.py` — File Security Middleware

## Overview

`file_security.py` is **Stage 5** of the WAF pipeline. It provides dedicated protection for file upload endpoints. It scans uploaded files in memory before they are saved to disk or processed by the application, mitigating remote code execution (RCE) via web shells and malware uploads.

---

## Security Checks

The module runs uploaded files through six distinct security checks:

### 1. Size Limit
Enforces a hard maximum file size (default 10 MB, configurable via `MAX_FILE_SIZE_MB`).

### 2. Dangerous Extension Blocklist
Blocks execution-capable extensions outright, regardless of their content (e.g., `.php`, `.jsp`, `.exe`, `.sh`, `.bat`, `.py`).

### 3. EICAR Test String
Detects the standard EICAR antivirus test string, which is useful for verifying that the WAF's file scanning is actively working during penetration tests.

### 4. Magic Byte (MIME) Detection
Attackers often rename a malicious PHP script to `image.jpg` to bypass extension filters. This check reads the first few bytes (the "magic bytes" or file signature) to determine the true nature of the file. If the file claims to be a JPEG but its magic bytes identify it as an ELF executable or a PHP script, it is blocked.

### 5. Embedded Script Detection (Polyglot Files)
Advanced attackers create "polyglot" files—for example, a perfectly valid GIF image that *also* contains PHP code (`<?php system($_GET['cmd']); ?>`) embedded in its EXIF metadata. This check scans the first 8 KB of the raw file content for common script execution patterns (`<?php`, `<%@ page`, `eval(`, etc.) and blocks the upload if any are found.

### 6. Double Extension Attack
Blocks files attempting to bypass simple filters by using double extensions (e.g., `shell.jpg.php` or `shell.php.jpg`).

---

## Integration in the Pipeline

The module only engages if the incoming request contains multipart file data. It provides a specialized layer of defense that the generic ML models and IPS regexes cannot easily handle (since scanning entire binary file bodies with regex or ML is computationally prohibitive).

---

## open-appsec Equivalent

open-appsec includes advanced Anti-Virus and Threat Extraction blades for file uploads. While open-appsec can connect to external SandBlast threat emulation engines for zero-day malware detonation, this Python module replicates the essential, high-speed, local checks (magic byte validation, extension blocking, and polyglot detection) to secure file upload vectors.
