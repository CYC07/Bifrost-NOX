class HTTPParser:
    def __init__(self):
        self.headers = {}
        self.body = b""
        self.method = ""
        self.path = ""
        self.protocol = ""
        self.content_length = 0
        self.header_done = False
        
    def parse(self, data: bytes):
        """Simple parse logic. Returns parsed bytes count."""
        if self.header_done:
            # Just accumulate body
            self.body += data
            return len(data)
            
        # Try to find header terminator
        parts = data.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            return 0 # Incomplete headers
            
        header_bytes = parts[0]
        remaining_bytes = parts[1]
        
        header_lines = header_bytes.split(b"\r\n")
        request_line = header_lines[0].decode('utf-8', errors='ignore')
        
        try:
            self.method, self.path, self.protocol = request_line.split(" ")
        except:
             # Response or invalid
             self.method = ""
             self.path = ""
        
        for line in header_lines[1:]:
            if b":" in line:
                key, val = line.split(b":", 1)
                self.headers[key.decode().strip().lower()] = val.decode().strip()
                
        if "content-length" in self.headers:
            self.content_length = int(self.headers["content-length"])
            
        self.header_done = True
        self.body = remaining_bytes
        
        return len(data)
