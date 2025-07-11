"""
SQLAlchemy Models for ReconCLI Database

Defines the database schema for storing reconnaissance data including:
- Targets (domains, IP ranges, programs)
- Subdomains discovered during enumeration
- Port scan results
- Vulnerability findings
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    ForeignKey,
    Boolean,
    Enum,
    Float,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()


class ScopeType(enum.Enum):
    """Target scope enumeration"""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


class Priority(enum.Enum):
    """Priority levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(enum.Enum):
    """Scan status enumeration"""

    NEW = "new"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnSeverity(enum.Enum):
    """Vulnerability severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(enum.Enum):
    """Vulnerability types"""

    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    IDOR = "idor"
    BROKEN_AUTH = "broken_auth"
    SENSITIVE_DATA = "sensitive_data"
    XXE = "xxe"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    OTHER = "other"


class Target(Base):
    """
    Target represents a reconnaissance target (domain, IP, program)
    """

    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    program = Column(String(100), nullable=True)  # Bug bounty program name
    scope = Column(Enum(ScopeType), default=ScopeType.UNKNOWN)
    priority = Column(Enum(Priority), default=Priority.MEDIUM)

    # Metadata
    added_date = Column(DateTime, default=datetime.utcnow)
    last_scan = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    active = Column(Boolean, default=True)

    # Relationships
    subdomains = relationship("Subdomain", back_populates="target")
    port_scans = relationship("PortScan", back_populates="target")
    vulnerabilities = relationship("Vulnerability", back_populates="target")

    def __repr__(self):
        return f"<Target(domain='{self.domain}', program='{self.program}')>"


class Subdomain(Base):
    """
    Subdomain discovery results
    """

    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    subdomain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)

    # Discovery metadata
    discovered_date = Column(DateTime, default=datetime.utcnow)
    discovery_method = Column(String(50), nullable=False)  # subfinder, amass, etc.
    status = Column(String(20), default="active")  # active, inactive, new

    # Technical details
    cname = Column(String(255), nullable=True)
    mx_record = Column(String(255), nullable=True)
    txt_record = Column(Text, nullable=True)

    # HTTP details
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    technology_stack = Column(Text, nullable=True)  # JSON string

    # Relationships
    target = relationship("Target", back_populates="subdomains")

    def __repr__(self):
        return f"<Subdomain(subdomain='{self.subdomain}', method='{self.discovery_method}')>"


class PortScan(Base):
    """
    Port scan results
    """

    __tablename__ = "port_scans"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")  # tcp, udp

    # Service details
    service = Column(String(100), nullable=True)
    version = Column(String(200), nullable=True)
    banner = Column(Text, nullable=True)

    # Scan metadata
    scan_date = Column(DateTime, default=datetime.utcnow)
    scanner = Column(String(50), nullable=False)  # nmap, naabu, rustscan
    status = Column(String(20), nullable=False)  # open, closed, filtered

    # Performance metrics
    response_time = Column(Float, nullable=True)  # milliseconds
    confidence = Column(Integer, default=100)  # 0-100%

    # Relationships
    target = relationship("Target", back_populates="port_scans")

    def __repr__(self):
        return f"<PortScan(ip='{self.ip_address}', port={self.port}, status='{self.status}')>"


class Vulnerability(Base):
    """
    Vulnerability findings
    """

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    url = Column(String(1000), nullable=False)

    # Vulnerability details
    vuln_type = Column(Enum(VulnType), nullable=False)
    severity = Column(Enum(VulnSeverity), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Discovery metadata
    discovered_date = Column(DateTime, default=datetime.utcnow)
    discovery_tool = Column(String(50), nullable=False)  # sqlmap, nuclei, custom

    # Technical details
    payload = Column(Text, nullable=True)
    request = Column(Text, nullable=True)  # Raw HTTP request
    response = Column(Text, nullable=True)  # Raw HTTP response
    evidence = Column(Text, nullable=True)  # Screenshots, logs, etc.

    # Status tracking
    status = Column(String(20), default="new")  # new, confirmed, false_positive, fixed
    verified = Column(Boolean, default=False)
    reported = Column(Boolean, default=False)

    # OWASP/CWE classification
    cwe_id = Column(String(20), nullable=True)  # CWE-89, CWE-79, etc.
    owasp_category = Column(String(50), nullable=True)

    # Relationships
    target = relationship("Target", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(type='{self.vuln_type}', severity='{self.severity}', url='{self.url[:50]}...')>"


class ScanSession(Base):
    """
    Scan session tracking for resume functionality
    """

    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)

    # Session details
    session_id = Column(String(100), unique=True, nullable=False)
    scan_type = Column(String(50), nullable=False)  # subdomain, port, vuln
    command = Column(Text, nullable=False)  # Original command

    # Status tracking
    status = Column(Enum(ScanStatus), default=ScanStatus.NEW)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Progress tracking
    total_items = Column(Integer, default=0)
    completed_items = Column(Integer, default=0)
    failed_items = Column(Integer, default=0)

    # Results
    output_file = Column(String(500), nullable=True)
    error_log = Column(Text, nullable=True)

    def __repr__(self):
        return f"<ScanSession(id='{self.session_id}', type='{self.scan_type}', status='{self.status}')>"
