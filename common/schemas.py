from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
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

@dataclass
class AnalysisResult:
    module: str  # e.g., "ocr", "yolo", "semantic"
    score: float # 0.0 to 1.0 confidence
    findings: List[str] # List of detected items/threats
    raw_data: Optional[Dict[str, Any]] = None

@dataclass
class AggregatedVerdict:
    status: VerdictStatus
    risk_level: RiskLevel
    reason: str
    detailed_findings: Dict[str, Any]

@dataclass
class TrafficPacket:
    id: str
    timestamp: datetime.datetime
    source_ip: str
    destination_ip: str
    protocol: str
    content_type: ContentType
    payload: bytes  # Raw content (image bytes, file bytes, text)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalysisRequest:
    request_id: str
    content_type: ContentType
    payload_reference: str 
    file_path: Optional[str] = None
    text_content: Optional[str] = None
