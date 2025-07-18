"""
Database Operations for ReconCLI

High-level functions for storing and retrieving reconnaissance data.
Provides simple interfaces for common operations without requiring
direct SQLAlchemy knowledge.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, func

from .database import get_db_manager
from .models import (
    PortScan,
    Priority,
    ScopeType,
    Subdomain,
    Target,
    Vulnerability,
    VulnSeverity,
    VulnType,
)


def store_target(
    domain: str,
    program: Optional[str] = None,
    scope: str = "unknown",
    priority: str = "medium",
    ip_address: Optional[str] = None,
    notes: Optional[str] = None,
) -> int:
    """
    Store a reconnaissance target

    Args:
        domain: Target domain name
        program: Bug bounty program name
        scope: Target scope (in_scope, out_of_scope, unknown)
        priority: Priority level (critical, high, medium, low)
        ip_address: Target IP address (optional)
        notes: Additional notes

    Returns:
        Target ID
    """
    db = get_db_manager()
    with db.get_session() as session:
        # Check if target already exists
        existing = session.query(Target).filter_by(domain=domain).first()
        if existing:
            return existing.id

        # Create new target
        target = Target(
            domain=domain,
            program=program,
            scope=(
                ScopeType(scope)
                if scope in [e.value for e in ScopeType]
                else ScopeType.UNKNOWN
            ),
            priority=(
                Priority(priority)
                if priority in [e.value for e in Priority]
                else Priority.MEDIUM
            ),
            ip_address=ip_address,
            notes=notes,
        )

        session.add(target)
        session.commit()
        return target.id


def store_subdomains(
    domain: str, subdomains: List[Dict[str, Any]], discovery_method: str = "unknown"
) -> List[int]:
    """
    Store subdomain discovery results

    Args:
        domain: Parent domain
        subdomains: List of subdomain data dictionaries
        discovery_method: Tool used for discovery (subfinder, amass, etc.)

    Returns:
        List of subdomain IDs
    """
    db = get_db_manager()
    with db.get_session() as session:
        # Get or create target
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            target_id = store_target(domain)
            target = session.query(Target).filter_by(id=target_id).first()

        subdomain_ids = []

        for sub_data in subdomains:
            subdomain_name = sub_data.get("subdomain") or sub_data.get("domain")
            if not subdomain_name:
                continue

            # Check if subdomain already exists
            existing = (
                session.query(Subdomain)
                .filter_by(target_id=target.id, subdomain=subdomain_name)
                .first()
            )

            if existing:
                # Update existing subdomain
                existing.discovery_method = discovery_method
                existing.discovered_date = datetime.utcnow()
                if "ip" in sub_data:
                    existing.ip_address = sub_data["ip"]
                if "status_code" in sub_data:
                    existing.http_status = sub_data["status_code"]
                subdomain_ids.append(existing.id)
            else:
                # Create new subdomain
                subdomain = Subdomain(
                    target_id=target.id,
                    subdomain=subdomain_name,
                    ip_address=sub_data.get("ip"),
                    discovery_method=discovery_method,
                    http_status=sub_data.get("status_code"),
                    http_title=sub_data.get("title"),
                    cname=sub_data.get("cname"),
                )

                session.add(subdomain)
                session.flush()  # Get the ID
                subdomain_ids.append(subdomain.id)

        session.commit()
        return subdomain_ids


def store_port_scan(
    domain: str, scan_results: List[Dict[str, Any]], scanner: str = "unknown"
) -> List[int]:
    """
    Store port scan results

    Args:
        domain: Target domain
        scan_results: List of port scan data
        scanner: Scanner used (nmap, naabu, rustscan)

    Returns:
        List of port scan IDs
    """
    db = get_db_manager()
    with db.get_session() as session:
        # Get or create target
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            target_id = store_target(domain)
            target = session.query(Target).filter_by(id=target_id).first()

        scan_ids = []

        for scan_data in scan_results:
            ip = scan_data.get("ip") or scan_data.get("host")
            port = scan_data.get("port")

            if not ip or not port:
                continue

            # Create port scan entry
            port_scan = PortScan(
                target_id=target.id,
                ip_address=ip,
                port=port,
                protocol=scan_data.get("protocol", "tcp"),
                service=scan_data.get("service"),
                version=scan_data.get("version"),
                banner=scan_data.get("banner"),
                scanner=scanner,
                status=scan_data.get("status", "open"),
                response_time=scan_data.get("response_time"),
            )

            session.add(port_scan)
            session.flush()
            scan_ids.append(port_scan.id)

        session.commit()
        return scan_ids


def store_vulnerability(
    domain: str, vuln_data: Dict[str, Any], discovery_tool: str = "unknown"
) -> int:
    """
    Store vulnerability finding

    Args:
        domain: Target domain
        vuln_data: Vulnerability data dictionary
        discovery_tool: Tool used for discovery

    Returns:
        Vulnerability ID
    """
    db = get_db_manager()
    with db.get_session() as session:
        # Get or create target
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            target_id = store_target(domain)
            target = session.query(Target).filter_by(id=target_id).first()

        # Create vulnerability
        vuln = Vulnerability(
            target_id=target.id,
            url=vuln_data.get("url", ""),
            vuln_type=VulnType(vuln_data.get("type", "other")),
            severity=VulnSeverity(vuln_data.get("severity", "info")),
            title=vuln_data.get("title", "Unknown Vulnerability"),
            description=vuln_data.get("description"),
            discovery_tool=discovery_tool,
            payload=vuln_data.get("payload"),
            request=vuln_data.get("request"),
            response=vuln_data.get("response"),
            evidence=vuln_data.get("evidence"),
            cwe_id=vuln_data.get("cwe"),
            owasp_category=vuln_data.get("owasp"),
        )

        session.add(vuln)
        session.commit()
        return vuln.id


def get_target(domain: str) -> Optional[Dict[str, Any]]:
    """Get target information by domain"""
    db = get_db_manager()
    with db.get_session() as session:
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            return None

        return {
            "id": target.id,
            "domain": target.domain,
            "program": target.program,
            "scope": target.scope.value,
            "priority": target.priority.value,
            "ip_address": target.ip_address,
            "added_date": target.added_date.isoformat(),
            "last_scan": target.last_scan.isoformat() if target.last_scan else None,
            "notes": target.notes,
        }


def get_subdomains(domain: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get subdomains for a target domain"""
    db = get_db_manager()
    with db.get_session() as session:
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            return []

        subdomains = (
            session.query(Subdomain)
            .filter_by(target_id=target.id)
            .order_by(desc(Subdomain.discovered_date))
            .limit(limit)
            .all()
        )

        return [
            {
                "id": sub.id,
                "subdomain": sub.subdomain,
                "ip_address": sub.ip_address,
                "discovered_date": sub.discovered_date.isoformat(),
                "discovery_method": sub.discovery_method,
                "status": sub.status,
                "http_status": sub.http_status,
                "http_title": sub.http_title,
                "cname": sub.cname,
            }
            for sub in subdomains
        ]


def get_port_scans(domain: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get port scan results for a target domain"""
    db = get_db_manager()
    with db.get_session() as session:
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            return []

        scans = (
            session.query(PortScan)
            .filter_by(target_id=target.id)
            .order_by(desc(PortScan.scan_date))
            .limit(limit)
            .all()
        )

        return [
            {
                "id": scan.id,
                "ip_address": scan.ip_address,
                "port": scan.port,
                "protocol": scan.protocol,
                "service": scan.service,
                "version": scan.version,
                "banner": scan.banner,
                "scan_date": scan.scan_date.isoformat(),
                "scanner": scan.scanner,
                "status": scan.status,
                "response_time": scan.response_time,
            }
            for scan in scans
        ]


def get_vulnerabilities(domain: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get vulnerabilities for a target domain"""
    db = get_db_manager()
    with db.get_session() as session:
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            return []

        vulns = (
            session.query(Vulnerability)
            .filter_by(target_id=target.id)
            .order_by(desc(Vulnerability.discovered_date))
            .limit(limit)
            .all()
        )

        return [
            {
                "id": vuln.id,
                "url": vuln.url,
                "type": vuln.vuln_type.value,
                "severity": vuln.severity.value,
                "title": vuln.title,
                "description": vuln.description,
                "discovered_date": vuln.discovered_date.isoformat(),
                "discovery_tool": vuln.discovery_tool,
                "payload": vuln.payload,
                "status": vuln.status,
                "verified": vuln.verified,
                "cwe_id": vuln.cwe_id,
                "owasp_category": vuln.owasp_category,
            }
            for vuln in vulns
        ]


def get_recent_discoveries(days: int = 7) -> Dict[str, List[Dict[str, Any]]]:
    """Get recent discoveries across all targets"""
    db = get_db_manager()
    with db.get_session() as session:
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # Recent subdomains
        recent_subdomains = (
            session.query(Subdomain)
            .filter(Subdomain.discovered_date >= cutoff_date)
            .order_by(desc(Subdomain.discovered_date))
            .limit(50)
            .all()
        )

        # Recent vulnerabilities
        recent_vulns = (
            session.query(Vulnerability)
            .filter(Vulnerability.discovered_date >= cutoff_date)
            .order_by(desc(Vulnerability.discovered_date))
            .limit(50)
            .all()
        )

        return {
            "subdomains": [
                {
                    "subdomain": sub.subdomain,
                    "discovered_date": sub.discovered_date.isoformat(),
                    "discovery_method": sub.discovery_method,
                    "target_domain": session.query(Target)
                    .filter_by(id=sub.target_id)
                    .first()
                    .domain,
                }
                for sub in recent_subdomains
            ],
            "vulnerabilities": [
                {
                    "url": vuln.url,
                    "type": vuln.vuln_type.value,
                    "severity": vuln.severity.value,
                    "title": vuln.title,
                    "discovered_date": vuln.discovered_date.isoformat(),
                    "target_domain": session.query(Target)
                    .filter_by(id=vuln.target_id)
                    .first()
                    .domain,
                }
                for vuln in recent_vulns
            ],
        }


def get_target_stats(domain: str) -> Dict[str, Any]:
    """Get statistics for a target"""
    db = get_db_manager()
    with db.get_session() as session:
        target = session.query(Target).filter_by(domain=domain).first()
        if not target:
            return {}

        subdomain_count = (
            session.query(Subdomain).filter_by(target_id=target.id).count()
        )
        port_scan_count = session.query(PortScan).filter_by(target_id=target.id).count()
        vuln_count = session.query(Vulnerability).filter_by(target_id=target.id).count()

        # Vulnerability breakdown by severity
        vuln_breakdown = (
            session.query(Vulnerability.severity, func.count(Vulnerability.id))
            .filter_by(target_id=target.id)
            .group_by(Vulnerability.severity)
            .all()
        )

        return {
            "domain": domain,
            "subdomains": subdomain_count,
            "port_scans": port_scan_count,
            "vulnerabilities": vuln_count,
            "vulnerability_breakdown": {
                severity.value: count for severity, count in vuln_breakdown
            },
        }


def store_whois_findings(
    target_domain: str,
    finding_data: Dict[str, Any],
) -> int:
    """
    Store WHOIS findings for a target domain

    Args:
        target_domain: Target domain name
        finding_data: Dictionary containing WHOIS data with keys:
            - domain: Domain name
            - whois_data: Raw WHOIS response data
            - timestamp: Discovery timestamp
            - source: Source tool (e.g., 'whoisfreaks')
            - risk_analysis: Optional risk analysis data

    Returns:
        WhoisFinding ID
    """
    import json
    from datetime import datetime as dt

    from .models import Target, WhoisFinding

    db = get_db_manager()
    with db.get_session() as session:
        # Get target object
        target = session.query(Target).filter_by(domain=target_domain).first()
        if not target:
            raise ValueError(f"Target domain {target_domain} not found")

        # Extract WHOIS data
        domain = finding_data.get("domain", "")
        whois_data = finding_data.get("whois_data", {})
        source = finding_data.get("source", "unknown")

        # Parse dates
        def parse_date(date_str):
            if not date_str:
                return None
            try:
                # Handle ISO format with timezone
                if "T" in date_str:
                    return dt.fromisoformat(date_str.replace("Z", "+00:00"))
                # Handle simple date format
                return dt.strptime(date_str, "%Y-%m-%d")
            except:
                return None

        # Extract key WHOIS fields
        registrar = (
            whois_data.get("registrarName")
            or whois_data.get("domain_registrar", {}).get("registrar_name")
            or whois_data.get("registrar")
        )

        registrant_org = whois_data.get("registrantOrganization") or whois_data.get(
            "registrant_organization"
        )

        admin_org = whois_data.get("adminOrganization") or whois_data.get(
            "admin_organization"
        )

        # Extract dates
        created_date = parse_date(
            whois_data.get("createdDate")
            or whois_data.get("create_date")
            or whois_data.get("creation_date")
        )

        updated_date = parse_date(
            whois_data.get("updatedDate") or whois_data.get("updated_date")
        )

        expires_date = parse_date(
            whois_data.get("expiresDate")
            or whois_data.get("expiry_date")
            or whois_data.get("expires_date")
        )

        # Extract nameservers
        nameservers = (
            whois_data.get("nameservers") or whois_data.get("nameServers") or []
        )
        nameservers_json = json.dumps(nameservers) if nameservers else None

        # Extract risk analysis if available
        risk_analysis = finding_data.get("risk_analysis", {})
        risk_level = risk_analysis.get("risk_level")
        risk_score = risk_analysis.get("risk_score", 0)
        risk_factors = risk_analysis.get("risk_factors", [])
        risk_factors_json = json.dumps(risk_factors) if risk_factors else None

        # Check if finding already exists
        existing_finding = (
            session.query(WhoisFinding)
            .filter_by(target_id=target.id, domain=domain)
            .first()
        )

        if existing_finding:
            # Update existing finding
            existing_finding.registrar = registrar
            existing_finding.registrant_org = registrant_org
            existing_finding.admin_org = admin_org
            existing_finding.created_date = created_date
            existing_finding.updated_date = updated_date
            existing_finding.expires_date = expires_date
            existing_finding.nameservers = nameservers_json
            existing_finding.risk_level = risk_level
            existing_finding.risk_score = risk_score
            existing_finding.risk_factors = risk_factors_json
            existing_finding.raw_whois_data = json.dumps(whois_data)
            existing_finding.source = source
            existing_finding.last_updated = dt.utcnow()

            session.commit()
            return existing_finding.id
        else:
            # Create new finding
            finding = WhoisFinding(
                target_id=target.id,
                domain=domain,
                registrar=registrar,
                registrant_org=registrant_org,
                admin_org=admin_org,
                created_date=created_date,
                updated_date=updated_date,
                expires_date=expires_date,
                nameservers=nameservers_json,
                risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=risk_factors_json,
                raw_whois_data=json.dumps(whois_data),
                source=source,
            )

            session.add(finding)
            session.commit()
            return finding.id
