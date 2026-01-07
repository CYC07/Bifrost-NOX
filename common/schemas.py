from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import datetime

class ContentType(str, Enum):
    IMAGE = "image"
    DOCUMENT = "document"
    TEXT = "text"
    UNKNOWN = "unknown"

class VerdictStatus(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CENSOR = "censor" # Forward but redact

class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnalysisResult(BaseModel):
    module: str  # e.g., "ocr", "yolo", "semantic"
    score: float # 0.0 to 1.0 confidence
    findings: List[str] # List of detected items/threats
    raw_data: Optional[Dict[str, Any]] = None

class AggregatedVerdict(BaseModel):
    status: VerdictStatus
    risk_level: RiskLevel
    reason: str
    detailed_findings: Dict[str, Any]

class TrafficPacket(BaseModel):
    id: str
    timestamp: datetime.datetime
    source_ip: str
    destination_ip: str
    protocol: str
    content_type: ContentType
    payload: bytes  # Raw content (image bytes, file bytes, text)
    metadata: Dict[str, Any] = {}

class AnalysisRequest(BaseModel):
    request_id: str
    content_type: ContentType
    payload_reference: str # Path to file or ID if payload is too large to send direct? 
                           # For now, let's assume we send bytes or base64 in a separate field if needed, 
                           # but for services, maybe passing a file path is better if on same machine.
                           # Let's support both: direct bytes or file path.
    file_path: Optional[str] = None
    text_content: Optional[str] = None
