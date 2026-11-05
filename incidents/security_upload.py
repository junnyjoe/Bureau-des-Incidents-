import hashlib
import os
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

DANGEROUS_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
    ".py", ".pyc", ".sh", ".bash", ".exe", ".dll", ".so",
    ".bat", ".cmd", ".ps1", ".vbs", ".html", ".htm", ".xhtml",
    ".js", ".mjs", ".jsp", ".jspx", ".asp", ".aspx", ".svg",
    ".cgi", ".pl", ".jar", ".war", ".htaccess", ".config",
}

ALLOWED_EXTENSIONS = {
    ".txt": "text/plain",
    ".log": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}


def detect_magic_type(header: bytes, ext: str) -> str:
    """
    Examine magic byte signatures to prevent MIME-type spoofing and Polyglot attacks.
    """
    if header.startswith(b"%PDF-"):
        return "application/pdf"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "image/gif"
    if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WEBP":
        return "image/webp"

    # Text / log / json / csv validation: must not contain binary null bytes
    if ext in {".txt", ".log", ".csv", ".json"}:
        if b"\x00" in header:
            raise ValidationError(_("File appears to contain binary content disguised as text."))
        try:
            header.decode("utf-8")
            return ALLOWED_EXTENSIONS.get(ext, "text/plain")
        except UnicodeDecodeError:
            try:
                header.decode("latin-1")
                return ALLOWED_EXTENSIONS.get(ext, "text/plain")
            except Exception:
                raise ValidationError(_("Invalid text encoding."))

    raise ValidationError(_("File header does not match expected signature for extension '%(ext)s'."), params={"ext": ext})


def validate_and_process_upload(uploaded_file):
    """
    Strict validation of uploaded evidence files:
    1. Size limit enforcement (<= 5 MB).
    2. Extension allowlist and dangerous extension denylist.
    3. Magic bytes inspection against spoofed MIME headers.
    4. Cryptographic SHA-256 digest computation for forensic integrity.
    """
    if uploaded_file.size > MAX_FILE_SIZE:
        raise ValidationError(
            _("File size exceeds 5 MB limit (file size: %(size).1f MB)."),
            params={"size": uploaded_file.size / (1024 * 1024)},
        )

    _, ext = os.path.splitext(uploaded_file.name.lower())
    if ext in DANGEROUS_EXTENSIONS:
        raise ValidationError(
            _("File extension '%(ext)s' is strictly disallowed for security reasons."),
            params={"ext": ext},
        )

    if ext not in ALLOWED_EXTENSIONS:
        allowed_list = ", ".join(sorted(ALLOWED_EXTENSIONS.keys()))
        raise ValidationError(
            _("Unsupported file format '%(ext)s'. Allowed formats: %(allowed)s"),
            params={"ext": ext, "allowed": allowed_list},
        )

    # Read header for magic bytes verification
    uploaded_file.seek(0)
    header = uploaded_file.read(1024)
    if not header:
        raise ValidationError(_("Uploaded file is empty."))

    detected_mime = detect_magic_type(header, ext)

    # Verify that the detected MIME type matches the extension
    expected_mime = ALLOWED_EXTENSIONS[ext]
    if detected_mime != expected_mime and not (ext in {".txt", ".log", ".csv", ".json"} and detected_mime.startswith("text/")):
        raise ValidationError(
            _("File content signature (%(detected)s) does not match extension '%(ext)s'."),
            params={"detected": detected_mime, "ext": ext},
        )

    # Compute SHA-256 hash over entire file
    uploaded_file.seek(0)
    hasher = hashlib.sha256()
    for chunk in uploaded_file.chunks():
        hasher.update(chunk)
    sha256_hash = hasher.hexdigest()

    # Reset file pointer for subsequent storage save
    uploaded_file.seek(0)

    return detected_mime, sha256_hash
