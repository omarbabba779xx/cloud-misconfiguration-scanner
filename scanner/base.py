from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    PUBLIC_STORAGE = "Public Storage"
    IAM_PERMISSIONS = "IAM Permissions"
    LOGGING = "Logging & Monitoring"
    MFA = "MFA / Authentication"
    NETWORK = "Network Exposure"


@dataclass
class Finding:
    provider: str          # aws | azure | gcp
    category: Category
    severity: Severity
    resource_type: str
    resource_id: str
    title: str
    description: str
    recommendation: str
    region: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "category": self.category.value,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "region": self.region,
            **self.extra,
        }


class BaseScanner:
    provider: str = ""

    def scan(self) -> list[Finding]:
        raise NotImplementedError
