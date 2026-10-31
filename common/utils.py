import math
import logging
import re
import os
import sys

def setup_logging(service_name: str):
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"{service_name}.log")
    
    # Configure root logger to output to both file and console
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - [%(name)s] - %(levelname)s - %(message)s')
    
    # File handler
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename.endswith(f"{service_name}.log") for h in root_logger.handlers):
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Console handler
    if not any(isinstance(h, logging.StreamHandler) and h.stream == sys.stdout for h in root_logger.handlers):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

logger = logging.getLogger("file_sniffer")

class FileSniffer:
    """
    Determines the true type of a file based on 'Magic Numbers' (file signatures)
    and Shannon Entropy, ignoring the provided file extension or Content-Type header.
    """

    # Common Magic Numbers (Hex Signatures)
    SIGNATURES = {
        "pdf": b"%PDF",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff",
        "gif": b"GIF8",
        "zip": b"PK\x03\x04", # Zip, Jar, Docx, Xlsx often start with this
        "exe": b"MZ",         # DOS/Windows executable
        "elf": b"\x7fELF",    # Linux executable
        "mp3": b"\xff\xfb",   # MPEG Audio (approx)
    }

    _PDF_HEADER = re.compile(rb"%PDF-")

    # OLE2 / Compound File header: the container of legacy .doc/.xls/.ppt (and also .msi, .msg,
    # .vsd ...), so the magic alone is not enough to call a file "legacy Office".
    OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    # Directory-entry names that only Word / Excel (BIFF8 and BIFF5) / PowerPoint write, as stored
    # on disk: UTF-16LE, NUL-terminated.
    _OFFICE_STREAMS = tuple(n.encode("utf-16-le") + b"\x00\x00"
                            for n in ("WordDocument", "Workbook", "Book", "PowerPoint Document", "PP40"))

    @staticmethod
    def is_legacy_office(content: bytes) -> bool:
        """True for a legacy Word/Excel/PowerPoint binary: OLE magic AND an Office stream name sitting
        in a directory slot. Directory entries are 128 bytes and the header is a whole number of
        128-byte slots (512 or 4096), so a real entry starts at a multiple of 128; a document that
        merely quotes the string elsewhere does not count. Encrypted OOXML (EncryptedPackage),
        MSI, Outlook .msg and Visio share the container but carry none of these names."""
        if not content.startswith(FileSniffer.OLE_MAGIC):
            return False
        for needle in FileSniffer._OFFICE_STREAMS:
            i = content.find(needle)
            while i != -1:
                if i % 128 == 0:
                    return True
                i = content.find(needle, i + 1)
        return False

    @staticmethod
    def get_true_file_type(content: bytes, lenient_pdf: bool = True) -> str:
        """
        Returns a simplified type: 'image', 'document', 'executable', 'legacy_office', 'text', or 'unknown'
        """
        header = content[:16] # Look at first 16 bytes

        # OLE2 container: only Word/Excel/PowerPoint binaries get their own type (they are blocked
        # outright by the gateway); any other OLE file stays an unknown binary as before.
        if header.startswith(FileSniffer.OLE_MAGIC):
            return "legacy_office" if FileSniffer.is_legacy_office(content) else "binary_unknown"

        # 1. Check Magic Numbers
        for ext, sig in FileSniffer.SIGNATURES.items():
            if header.startswith(sig):
                if ext in ["jpg", "png", "gif"]:
                    return "image"
                if ext in ["pdf", "zip"]:
                    return "document" 
                if ext in ["exe", "elf"]:
                    return "executable"

        # PDF readers (and our own YARA/structure analyzers) accept "%PDF-" anywhere in the first
        # KiB, and the version after it may be truncated or missing, so junk or comment text in front
        # (or a sloppy "%PDF-1.") must not hide the file from the document service. A bare "%PDF" at
        # offset 0 was already a document above (unchanged); mid-text mentions need the hyphen.
        if lenient_pdf and FileSniffer._PDF_HEADER.search(content[:1024]):
            return "document"

        # 2. Check for Text vs Binary via Null Bytes and ASCII
        # If it contains null bytes in the first 1kb, it's likely binary (unless it's UTF-16)
        # Simple heuristic:
        chunk = content[:1024]
        if b"\x00" in chunk:
            # It has null bytes. Likely binary.
            # Could be a specialized binary format or unknown malware.
            return "binary_unknown"

        # 3. Fallback to Text
        # If it looks like text, we check entropy to see if it's obfuscated/encrypted text
        try:
            chunk.decode('utf-8')
            return "text"
        except UnicodeDecodeError:
            return "binary_unknown"

    @staticmethod
    def calculate_entropy(content: bytes) -> float:
        """
        Calculates Shannon Entropy.
        Range: 0.0 to 8.0
        Values > 7.5 usually indicate encryption or compression.
        Values < 5.0 usually indicate standard text.
        """
        if not content:
            return 0.0
        
        # Count byte occurrences
        frequency = [0] * 256
        for byte in content:
            frequency[byte] += 1
        
        # Calculate entropy
        entropy = 0
        total_len = len(content)
        for count in frequency:
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
                
        return entropy

    @staticmethod
    def is_obfuscated_or_encrypted(content: bytes, threshold: float = 7.5) -> bool:
        return FileSniffer.calculate_entropy(content) > threshold
