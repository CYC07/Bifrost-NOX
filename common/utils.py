import math
import logging
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

    @staticmethod
    def get_true_file_type(content: bytes) -> str:
        """
        Returns a simplified type: 'image', 'document', 'executable', 'text', or 'unknown'
        """
        header = content[:16] # Look at first 16 bytes

        # 1. Check Magic Numbers
        for ext, sig in FileSniffer.SIGNATURES.items():
            if header.startswith(sig):
                if ext in ["jpg", "png", "gif"]:
                    return "image"
                if ext in ["pdf", "zip"]:
                    return "document" 
                if ext in ["exe", "elf"]:
                    return "executable"

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
