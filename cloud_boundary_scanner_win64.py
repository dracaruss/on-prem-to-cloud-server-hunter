#!/usr/bin/env python3
"""
Cloud Boundary Scanner (Windows)
================================
Enumerates on-prem to cloud connectivity during authorized penetration tests.
Discovers sync services, cached credentials, cloud endpoints, and
misconfigurations at the hybrid identity boundary.

Usage:
    python cloud_boundary_scanner_win64.py [--output report.json] [--silent]
    python cloud_boundary_scanner_win64.py -dc 10.0.0.2 -u DOMAIN\\user -p Password1

Requirements:
    - Run from a domain-joined Windows host (ideally with local admin)
    - Python 3.8+

Author: Russell (Thrive Offensive Security)
"""

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------

class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def severity_color(severity: str) -> str:
        return {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFO": Colors.GRAY,
        }.get(severity, Colors.WHITE)

    @staticmethod
    def strip_if_no_tty(text: str) -> str:
        if not sys.stdout.isatty():
            return re.sub(r"\033\[[0-9;]*m", "", text)
        return text


def cprint(text: str, color: str = "", end: str = "\n"):
    """Print with optional color, stripping ANSI if not a TTY."""
    msg = f"{color}{text}{Colors.RESET}" if color else text
    print(Colors.strip_if_no_tty(msg), end=end)


# ---------------------------------------------------------------------------
# Debug logging (only prints when --debug is set)
# ---------------------------------------------------------------------------

DEBUG_MODE = True


def debug(msg: str):
    """Print a debug message (suppressed by --silent)."""
    if DEBUG_MODE:
        cprint(f"  [DBG] {msg}", Colors.GRAY)


def status(msg: str):
    """Print a phase/module status line (always shown)."""
    cprint(f"  [*] {msg}", Colors.CYAN)


def _enable_windows_vt_processing():
    """Enable ANSI/VT100 escape sequence processing on Windows consoles.

    Windows PowerShell and cmd.exe do not process ANSI escape codes by
    default.  This flips the ENABLE_VIRTUAL_TERMINAL_PROCESSING flag via
    the Win32 API so \\033[...m sequences render as colors instead of
    printing as raw text (the ?[1m?[96m artifacts Russell was seeing).

    Must be called BEFORE any ANSI output.  The reason later status lines
    rendered correctly was that the first subprocess call (sc query, etc.)
    incidentally enabled VT processing as a side effect — this function
    does it explicitly at startup.
    """
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        STD_OUTPUT_HANDLE = -11
        STD_ERROR_HANDLE = -12
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

        for handle_id in (STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
            handle = kernel32.GetStdHandle(handle_id)
            if handle == 0 or handle == wintypes.HANDLE(-1).value:
                continue
            mode = wintypes.DWORD()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                continue
            mode.value |= ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode)
    except Exception:
        # Fallback: launching a subprocess briefly enables VT processing
        # as a side effect on many Windows builds.
        os.system("")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLOUD_DOMAINS = {
    "azure": [
        "login.microsoftonline.com", "graph.microsoft.com",
        "management.azure.com", "portal.azure.com",
        "aadconnecthealth.azure.com", "adminwebservice.microsoftonline.com",
        "login.windows.net", "provisioningapi.microsoftonline.com",
        "graph.windows.net", "autologon.microsoftazuread-sso.com",
        "enterpriseregistration.windows.net", "pas.windows.net",
    ],
    "aws": [
        "sts.amazonaws.com", "signin.aws.amazon.com",
        "sso.amazonaws.com", "console.aws.amazon.com",
    ],
    "gcp": [
        "accounts.google.com", "oauth2.googleapis.com",
        "cloudresourcemanager.googleapis.com", "iam.googleapis.com",
    ],
}

# Tier 1 (HIGH): patterns that match actual credential VALUES or exportable secrets
CREDENTIAL_PATTERNS = [
    (r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
     "AWS access key ID"),
    (r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{20,}",
     "AWS secret access key"),
    (r"(?i)aws_session_token\s*=\s*\S{20,}",
     "AWS session token"),
    (r"(?i)SharedAccessSignature=sv=[^\s&\"']{20,}",
     "Azure SAS token"),
    (r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;\"']+;AccountKey=[^;\"']+",
     "Azure storage connection string"),
    (r"(?i)AccountKey=[A-Za-z0-9/+=]{80,}",
     "Azure storage account key"),
    (r'"type"\s*:\s*"service_account"',
     "GCP service account JSON key"),
    (r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "Private key (PEM)"),
]

# Tier 2 (MEDIUM): credential-adjacent patterns, variable names with values assigned
CREDENTIAL_REF_PATTERNS = [
    (r"(?i)AZURE[_\-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_\-]?(?:ID|SECRET)\s*[:=]\s*\S+",
     "Azure credential variable with value"),
    (r"(?i)AZURE[_\-]?(?:STORAGE|ACCOUNT)[_\-]?KEY\s*[:=]\s*\S+",
     "Azure storage key variable"),
    (r"(?i)(?:client[_\-]?secret|client[_\-]?key)\s*[:=]\s*[\"'][^\"']{16,}[\"']",
     "Client secret or key"),
    (r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*[\"'][^\"']{16,}[\"']",
     "API key or token with value"),
    (r"(?i)GOOGLE_APPLICATION_CREDENTIALS\s*[:=]\s*\S+",
     "GCP credentials path"),
]

SCANNER_FILENAME = "cloud_boundary_scanner"  # exclude self from results

SYNC_SERVICES = [
    ("Microsoft Azure AD Sync", "Entra Connect Sync (legacy name)"),
    ("Microsoft Entra Connect Sync", "Entra Connect Sync"),
    ("ADSync", "AD Sync engine service"),
    ("AzureADConnectHealthSyncInsights", "Entra Connect Health monitoring"),
    ("AADConnectProvisioningAgent", "Entra Cloud Sync provisioning agent"),
    ("adfssrv", "Active Directory Federation Services"),
    ("AzureADConnectAgentUpdater", "Entra Connect agent auto-updater"),
]

CLOUD_BRIDGE_SERVICES = [
    ("himds", "Azure Arc Hybrid Instance Metadata Service"),
    ("GCArcService", "Azure Arc Guest Configuration agent"),
    ("ExtensionService", "Azure Arc Extension Service"),
    ("Microsoft AAD App Proxy Connector", "Entra Application Proxy Connector"),
    ("WAPCSvc", "Web Application Proxy Service (ADFS/App Proxy)"),
    ("AzureADConnectAuthenticationAgent", "Entra Pass-through Authentication agent"),
]

CONFIG_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs",
    ".py", ".rb", ".config", ".xml", ".json", ".yaml",
    ".yml", ".env", ".ini", ".conf", ".tf", ".tfvars",
    ".properties",
}

# Directories to skip during file scanning (dev/tool artifacts, not real creds)
DEFAULT_EXCLUDE_DIRS = {
    ".venv", "venv", "env", ".env", "__pycache__", "site-packages",
    "node_modules", ".git", ".tox", "dist-packages", "lib-python",
    "SelfTest", ".mypy_cache", ".pytest_cache",
}

# Remote DC targeting (set by -dc flag in main())
DC_TARGET = ""
DC_BASE_DN = ""
DC_CONFIG_NC = ""
DC_USER = ""
DC_PASS = ""

# ---------------------------------------------------------------------------
# Finding / Results
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, category: str, title: str, detail: str,
                 severity: str = "INFO", evidence: str = ""):
        self.category = category
        self.title = title
        self.detail = detail
        self.severity = severity
        self.evidence = evidence
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category, "title": self.title,
            "detail": self.detail, "severity": self.severity,
            "evidence": self.evidence, "timestamp": self.timestamp,
        }


class ScanResults:
    def __init__(self):
        self.findings: list[Finding] = []
        self.scan_start = datetime.utcnow().isoformat()
        self.hostname = platform.node()
        self.host_ip = self._get_host_ip()
        self.onprem_domain = self._get_onprem_domain()
        self.cloud_domain = self._get_cloud_domain()

    @staticmethod
    def _get_host_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "unknown"

    @staticmethod
    def _get_onprem_domain() -> str:
        """Detect the on-prem Active Directory domain name."""
        # USERDNSDOMAIN holds the FQDN (e.g. corp.local) for the logged-in user
        domain = os.environ.get("USERDNSDOMAIN", "")
        if domain and "%" not in domain:
            return domain
        # WMI via PowerShell returns the FQDN even when the env var is empty
        wmi = run_powershell(
            "(Get-WmiObject Win32_ComputerSystem).Domain")
        if wmi and wmi.strip() and "." in wmi.strip():
            return wmi.strip()
        # Last resort: NetBIOS domain name
        nb = os.environ.get("USERDOMAIN", "")
        return nb if nb and "%" not in nb else "WORKGROUP"

    @staticmethod
    def _get_cloud_domain() -> str:
        """Detect the Entra ID / Azure AD tenant from device join info."""
        output = run_cmd("dsregcmd /status")
        if not output:
            return ""
        # Try TenantName first, then DomainName
        for key in ("TenantName", "DomainName"):
            for line in output.splitlines():
                stripped = line.strip()
                if stripped.startswith(key) and ":" in stripped:
                    val = stripped.split(":", 1)[1].strip()
                    if val and val.lower() not in ("", "n/a", "none"):
                        return val
        return ""

    def add(self, finding: Finding):
        self.findings.append(finding)
        color = Colors.severity_color(finding.severity)
        # In normal mode, only print CRITICAL/HIGH/MEDIUM inline as they happen
        if finding.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            cprint(f"  [+] [{finding.severity}] {finding.title}", color)
            # Show evidence inline for credential findings so values are visible
            if finding.evidence and finding.category == "credentials":
                for eline in finding.evidence.splitlines():
                    cprint(f"      {eline.strip()}", Colors.DIM)
        elif DEBUG_MODE:
            cprint(f"  [.] [{finding.severity}] {finding.title}", color)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_start": self.scan_start,
            "scan_end": datetime.utcnow().isoformat(),
            "hostname": self.hostname,
            "host_ip": self.host_ip,
            "onprem_domain": self.onprem_domain,
            "cloud_domain": self.cloud_domain,
            "total_findings": len(self.findings),
            "severity_counts": {
                s: sum(1 for f in self.findings if f.severity == s)
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception as exc:
        debug(f"Command failed ({cmd}): {exc}")
        return ""


def run_powershell(script: str, timeout: int = 30) -> str:
    cmd = f'powershell.exe -NoProfile -NonInteractive -Command "{script}"'
    return run_cmd(cmd, timeout=timeout)


def is_windows() -> bool:
    return platform.system() == "Windows"


# ---------------------------------------------------------------------------
# Scanner modules
# ---------------------------------------------------------------------------

def _adsi_searcher(base_dn_override: str = "") -> str:
    """Return PowerShell to create a DirectorySearcher, targeting remote DC if set."""
    if DC_TARGET:
        base = base_dn_override or DC_BASE_DN
        if DC_USER and DC_PASS:
            escaped_pass = DC_PASS.replace("'", "''")
            return (f"$entry = New-Object DirectoryServices.DirectoryEntry("
                    f"'LDAP://{DC_TARGET}/{base}','{DC_USER}','{escaped_pass}');"
                    f"$s = New-Object DirectoryServices.DirectorySearcher($entry);")
        return (f"$s = New-Object DirectoryServices.DirectorySearcher("
                f"[ADSI]'LDAP://{DC_TARGET}/{base}');")
    return "$s = New-Object DirectoryServices.DirectorySearcher;"


def _rsat_server() -> str:
    """Return -Server and optional -Credential for RSAT cmdlets targeting a remote DC."""
    if DC_TARGET:
        if DC_USER and DC_PASS:
            escaped_pass = DC_PASS.replace("'", "''")
            return (f"-Server {DC_TARGET} "
                    f"-Credential (New-Object System.Management.Automation.PSCredential("
                    f"'{DC_USER}',(ConvertTo-SecureString '{escaped_pass}' "
                    f"-AsPlainText -Force))) ")
        return f"-Server {DC_TARGET} "
    return ""


def _domain_from_base_dn(base_dn: str) -> str:
    """Convert 'DC=corp,DC=local' to 'corp.local'."""
    parts = re.findall(r"DC=([^,]+)", base_dn, re.IGNORECASE)
    return ".".join(parts) if parts else ""


def check_sync_services(results: ScanResults):
    status("Checking cloud sync services...")

    if not is_windows():
        debug("Not a Windows host, skipping sync service checks.")
        return

    output = run_cmd("sc query type= service state= all")
    found_any = False

    for svc_name, description in SYNC_SERVICES:
        if svc_name.lower() in output.lower():
            found_any = True
            state = "running" if "RUNNING" in output else "installed"
            severity = "CRITICAL" if svc_name in (
                "ADSync", "Microsoft Azure AD Sync",
                "Microsoft Entra Connect Sync") else "HIGH"
            results.add(Finding(
                "sync_services",
                f"Cloud sync service detected: {svc_name}",
                f"{description} is {state} on this host. "
                f"This server bridges on-prem AD and the cloud tenant.",
                severity=severity, evidence=f"Service: {svc_name}",
            ))

    if not found_any:
        debug("No cloud sync services found on this host.")

    # MSOL_ account — try ADSI first (works without RSAT), then RSAT cmdlet
    debug("Querying AD for MSOL_ sync account (ADSI)...")
    msol_check = run_powershell(
        _adsi_searcher() +
        "$s.Filter = '(&(objectCategory=person)(objectClass=user)"
        "(samAccountName=MSOL_*))';"
        "$s.PropertiesToLoad.AddRange(@('samaccountname','description'));"
        "$r = $s.FindAll();"
        "foreach($e in $r){"
        "  $p = $e.Properties;"
        "  [PSCustomObject]@{"
        "    SamAccountName=$p['samaccountname'][0];"
        "    Description=if($p['description']){$p['description'][0]}else{''}"
        "  }"
        "} | ConvertTo-Json")
    if not msol_check or "MSOL_" not in msol_check:
        debug("ADSI MSOL_ query returned nothing, trying RSAT Get-ADUser...")
        msol_check = run_powershell(
            f"Get-ADUser {_rsat_server()}"
            "-Filter {SamAccountName -like 'MSOL_*'} "
            "-Properties Description "
            "| Select-Object SamAccountName, Enabled, Description "
            "| ConvertTo-Json")
    if msol_check and "MSOL_" in msol_check:
        debug(f"MSOL_ account found: {msol_check[:200]}")
        # Extract the boundary server name from the description field
        # Format: "...running on computer [HOSTNAME] configured to synchronize to tenant [TENANT]..."
        server_hint = ""
        tenant_hint = ""
        m_srv = re.search(r"running on computer\s+(\S+)", msol_check, re.IGNORECASE)
        if m_srv:
            server_hint = m_srv.group(1).rstrip(".")
        m_ten = re.search(r"synchronize to tenant\s+(\S+)", msol_check, re.IGNORECASE)
        if m_ten:
            tenant_hint = m_ten.group(1).rstrip(".")
            if tenant_hint and not results.cloud_domain:
                results.cloud_domain = tenant_hint

        detail = (
            "The MSOL_ account is the Entra Connect directory sync account. "
            "It holds DCSync-equivalent privileges on-prem and write access "
            "in the Entra tenant."
        )
        if server_hint:
            detail += f" Entra Connect server: {server_hint}."
        if tenant_hint:
            detail += f" Target tenant: {tenant_hint}."

        results.add(Finding(
            "sync_services", "MSOL sync service account found in AD",
            detail, severity="CRITICAL", evidence=msol_check[:500],
        ))
    else:
        debug("No MSOL_ service account found in AD (tried ADSI and RSAT).")

    # Entra Connect Service Connection Point — try ADSI first, then RSAT
    debug("Querying AD for Entra Connect SCP (ADSI)...")
    if DC_TARGET and DC_CONFIG_NC:
        scp_base = (f"CN=Device Registration Configuration,"
                    f"CN=Services,{DC_CONFIG_NC}")
        if DC_USER and DC_PASS:
            escaped_pass = DC_PASS.replace("'", "''")
            scp_entry = (f"$entry = New-Object DirectoryServices.DirectoryEntry("
                         f"'LDAP://{DC_TARGET}/{scp_base}',"
                         f"'{DC_USER}','{escaped_pass}');")
        else:
            scp_entry = (f"$entry = [ADSI]'LDAP://{DC_TARGET}/{scp_base}';")
        scp_check = run_powershell(
            f"{scp_entry}"
            "$s = New-Object DirectoryServices.DirectorySearcher($entry);"
            "$s.Filter = '(objectClass=serviceConnectionPoint)';"
            "$s.PropertiesToLoad.AddRange(@('keywords','distinguishedname'));"
            "$r = $s.FindAll();"
            "foreach($e in $r){"
            "  $p = $e.Properties;"
            "  [PSCustomObject]@{"
            "    DN=$p['distinguishedname'][0];"
            "    Keywords=($p['keywords'] -join ',')"
            "  }"
            "} | ConvertTo-Json")
    else:
        scp_check = run_powershell(
            "$root = [ADSI]'LDAP://RootDSE';"
            "$configNC = $root.configurationNamingContext;"
            "$s = New-Object DirectoryServices.DirectorySearcher;"
            "$s.SearchRoot = [ADSI]\\\"LDAP://CN=Device Registration Configuration,"
            "CN=Services,$configNC\\\";"
            "$s.Filter = '(objectClass=serviceConnectionPoint)';"
            "$s.PropertiesToLoad.AddRange(@('keywords','distinguishedname'));"
            "$r = $s.FindAll();"
            "foreach($e in $r){"
            "  $p = $e.Properties;"
            "  [PSCustomObject]@{"
            "    DN=$p['distinguishedname'][0];"
            "    Keywords=($p['keywords'] -join ',')"
            "  }"
            "} | ConvertTo-Json")
    if not scp_check or "azureAD" not in scp_check.lower():
        debug("ADSI SCP query returned nothing, trying RSAT Get-ADObject...")
        if DC_TARGET and DC_CONFIG_NC:
            _configNC_ps = f"$configNC = '{DC_CONFIG_NC}';"
        else:
            _configNC_ps = "$configNC = (Get-ADRootDSE).configurationNamingContext;"
        scp_check = run_powershell(
            f"{_configNC_ps} "
            f"Get-ADObject {_rsat_server()}"
            "-SearchBase \\\"CN=Device Registration Configuration,"
            "CN=Services,$configNC\\\" "
            "-Filter {objectClass -eq 'serviceConnectionPoint'} "
            "-Properties keywords "
            "| Select-Object DistinguishedName, keywords "
            "| ConvertTo-Json")
    if scp_check and "azureAD" in scp_check.lower():
        debug(f"Entra Connect SCP found: {scp_check[:200]}")
        tenant_from_scp = ""
        m_ad = re.search(r"azureADName[:\s]+(\S+)", scp_check, re.IGNORECASE)
        if m_ad:
            tenant_from_scp = m_ad.group(1)
        results.add(Finding(
            "sync_services",
            "Entra Connect Service Connection Point in AD",
            f"The Entra Connect SCP is registered in the AD configuration "
            f"partition, confirming hybrid identity sync is deployed."
            + (f" Cloud tenant: {tenant_from_scp}." if tenant_from_scp else ""),
            severity="HIGH", evidence=scp_check[:500],
        ))
    else:
        debug("No Entra Connect SCP found in AD (tried ADSI and RSAT).")

    # ADSync database
    adsync_db_paths = [
        r"C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf",
        r"C:\Program Files\Microsoft Azure AD Sync\MaData",
    ]
    for db_path in adsync_db_paths:
        if os.path.exists(db_path):
            results.add(Finding(
                "sync_services", "ADSync database found on disk",
                f"The ADSync database at {db_path} contains encrypted cloud "
                f"credentials extractable with local admin and AADInternals.",
                severity="CRITICAL", evidence=f"Path: {db_path}",
            ))
        else:
            debug(f"ADSync DB not found at {db_path}")

    # Cloud bridge services (Arc, App Proxy, PTA)
    if output:  # reuse the sc query output from above
        for svc_name, description in CLOUD_BRIDGE_SERVICES:
            if svc_name.lower() in output.lower():
                state = "running" if "RUNNING" in output else "installed"
                severity = ("CRITICAL"
                            if svc_name == "AzureADConnectAuthenticationAgent"
                            else "HIGH")
                results.add(Finding(
                    "cloud_bridge",
                    f"Cloud bridge service: {svc_name}",
                    f"{description} is {state} on this host. "
                    f"This service extends cloud management to on-prem.",
                    severity=severity, evidence=f"Service: {svc_name}",
                ))


def check_adfs(results: ScanResults):
    status("Checking ADFS configuration...")
    if not is_windows():
        return

    adfs_config = run_powershell(
        "if (Get-Service adfssrv -ErrorAction SilentlyContinue) {"
        "  Get-AdfsProperties | Select-Object HostName,Identifier,"
        "  CurrentFarmBehavior | ConvertTo-Json"
        "}")
    if adfs_config and "HostName" in adfs_config:
        results.add(Finding(
            "federation", "ADFS server detected",
            "This host runs ADFS. The token-signing certificate can forge "
            "SAML tokens for any federated cloud identity (Golden SAML).",
            severity="CRITICAL", evidence=adfs_config[:500],
        ))

        cert_check = run_powershell(
            "if (Get-Command Get-AdfsCertificate -ErrorAction SilentlyContinue) {"
            "  Get-AdfsCertificate -CertificateType Token-Signing "
            "  | Select-Object CertificateType,Thumbprint,StoreLocation "
            "  | ConvertTo-Json"
            "}")
        if cert_check and "Thumbprint" in cert_check:
            results.add(Finding(
                "federation", "ADFS token-signing certificate accessible",
                "The token-signing certificate is readable. If the private "
                "key is exportable, Golden SAML attacks are possible.",
                severity="CRITICAL", evidence=cert_check[:500],
            ))
    else:
        debug("No ADFS service found on this host.")


def check_cloud_dns(results: ScanResults):
    status("Checking cloud endpoint DNS resolution...")
    for provider, domains in CLOUD_DOMAINS.items():
        reachable = []
        for domain in domains:
            try:
                addr = socket.gethostbyname(domain)
                reachable.append(f"{domain} -> {addr}")
                debug(f"DNS resolved: {domain} -> {addr}")
            except socket.gaierror:
                debug(f"DNS failed: {domain}")

        if reachable:
            results.add(Finding(
                "network",
                f"{provider.upper()} endpoints resolvable ({len(reachable)}/{len(domains)})",
                f"Cloud connectivity to {provider.upper()} confirmed from this host.",
                severity="INFO",
                evidence="\n".join(reachable[:6]),
            ))


def check_cloud_dns_integration(results: ScanResults):
    """Check for DNS records indicating cloud identity integration."""
    domain = results.onprem_domain
    if not domain or domain == "WORKGROUP":
        debug("No domain name available for DNS integration checks.")
        return

    status(f"Checking cloud integration DNS records for {domain}...")

    dns_checks = [
        (f"enterpriseregistration.{domain}",
         "Entra device registration (Workplace Join)", "HIGH"),
        (f"enterpriseenrollment.{domain}",
         "Intune MDM enrollment", "HIGH"),
        (f"msoid.{domain}",
         "Microsoft Online ID (O365 client detection)", "MEDIUM"),
        (f"autodiscover.{domain}",
         "Exchange Online autodiscovery", "MEDIUM"),
        (f"lyncdiscover.{domain}",
         "Teams/Skype for Business federation", "INFO"),
    ]

    found_any = False
    for hostname, description, severity in dns_checks:
        try:
            addr = socket.gethostbyname(hostname)
            found_any = True
            results.add(Finding(
                "dns_integration",
                f"Cloud DNS: {hostname}",
                f"{hostname} resolves to {addr}. "
                f"This confirms {description} is configured, "
                f"indicating cloud identity integration.",
                severity=severity,
                evidence=f"{hostname} -> {addr}",
            ))
            debug(f"Cloud DNS integration: {hostname} -> {addr}")
        except socket.gaierror:
            debug(f"Cloud DNS not found: {hostname}")

    if not found_any:
        debug(f"No cloud integration DNS records found for {domain}.")


def check_outbound_connections(results: ScanResults):
    status("Checking active outbound cloud connections...")
    if not is_windows():
        output = run_cmd("ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null")
    else:
        output = run_cmd("netstat -ano")

    if not output:
        debug("Could not retrieve active connections.")
        return

    for provider, domains in CLOUD_DOMAINS.items():
        for domain in domains[:5]:
            try:
                ip = socket.gethostbyname(domain)
                if ip in output:
                    results.add(Finding(
                        "network",
                        f"Active connection to {provider.upper()}: {domain}",
                        f"Outbound connection to {domain} ({ip}) is active.",
                        severity="MEDIUM", evidence=f"{domain} -> {ip}",
                    ))
            except socket.gaierror:
                pass


def check_environment_variables(results: ScanResults):
    status("Checking environment variables...")
    # HIGH-value patterns: these likely hold actual secrets or IDs
    secret_env_patterns = [
        (r"(?i)TENANT.ID", "Tenant ID"),
        (r"(?i)CLIENT.SECRET", "Client secret"),
        (r"(?i)(?:API|ACCESS|SECRET)[_\-]?KEY", "API/access key"),
        (r"(?i)(?:AWS_SECRET|AWS_ACCESS|AWS_SESSION)", "AWS credential"),
        (r"(?i)AZURE[_\-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_\-]?(?:ID|SECRET)", "Azure identity"),
        (r"(?i)GOOGLE_APPLICATION_CREDENTIALS", "GCP credential"),
    ]
    # MEDIUM-value patterns: cloud presence indicators, not credentials
    presence_env_patterns = [
        (r"(?i)^AZURE", "Azure"),
        (r"(?i)^AWS_", "AWS"),
        (r"(?i)^GOOGLE_CLOUD|^GCLOUD|^GCP", "GCP"),
    ]
    found = False
    for var_name, var_value in os.environ.items():
        # Check high-value secret patterns first
        matched = False
        for pattern, label in secret_env_patterns:
            if re.search(pattern, var_name):
                found = True
                matched = True
                results.add(Finding(
                    "credentials",
                    f"Cloud env var: {var_name}",
                    f"Environment variable {var_name} matches pattern for "
                    f"{label}. Accessible to any process as this user.",
                    severity="HIGH", evidence=f"{var_name}={var_value}",
                ))
                break
        if matched:
            continue
        # Then check general cloud presence indicators
        for pattern, label in presence_env_patterns:
            if re.search(pattern, var_name):
                found = True
                results.add(Finding(
                    "credentials",
                    f"Cloud env var: {var_name}",
                    f"Environment variable {var_name} indicates {label} "
                    f"presence on this host.",
                    severity="MEDIUM", evidence=f"{var_name}={var_value}",
                ))
                break
    if not found:
        debug("No cloud-related environment variables found.")


def _is_excluded_path(filepath: Path, extra_excludes: list[str]) -> bool:
    """Check if any path component matches an excluded directory."""
    parts = set(p.lower() for p in filepath.parts)
    for excl in DEFAULT_EXCLUDE_DIRS:
        if excl.lower() in parts:
            return True
    for excl in extra_excludes:
        if excl.lower() in parts or excl.lower() in str(filepath).lower():
            return True
    return False


def _extract_match_context(content: str, pattern: str, max_lines: int = 3) -> str:
    """Extract the actual matching lines from file content."""
    matches = []
    for line in content.splitlines():
        if re.search(pattern, line):
            clean = line.strip()
            if len(clean) > 300:
                clean = clean[:300] + "..."
            matches.append(clean)
            if len(matches) >= max_lines:
                break
    return "\n    ".join(matches) if matches else "(pattern matched but no printable line)"


def check_credential_files(results: ScanResults, extra_excludes: list[str] = None):
    status("Scanning filesystem for cloud credentials...")
    if extra_excludes is None:
        extra_excludes = []
    scanned = 0
    hits = 0
    skipped = 0
    max_file_size = 5 * 1024 * 1024

    search_roots = []
    if is_windows():
        search_roots = [
            Path(r"C:\Scripts"), Path(r"C:\Automation"),
            Path(r"C:\Tools"), Path(r"C:\ProgramData"),
        ]
        users_dir = Path(r"C:\Users")
        if users_dir.exists():
            for user_dir in users_dir.iterdir():
                if user_dir.is_dir() and user_dir.name not in (
                        "Public", "Default", "Default User", "All Users"):
                    search_roots.extend([
                        user_dir / "Documents", user_dir / "Desktop",
                        user_dir / "Downloads", user_dir / ".aws",
                        user_dir / ".azure", user_dir / ".config" / "gcloud",
                    ])
    else:
        search_roots = [Path.home(), Path("/opt"), Path("/tmp")]

    for root in search_roots:
        if not root.exists():
            continue
        try:
            for filepath in root.rglob("*"):
                if scanned > 5000:
                    break
                if not filepath.is_file():
                    continue
                if filepath.suffix.lower() not in CONFIG_EXTENSIONS:
                    continue
                if _is_excluded_path(filepath, extra_excludes):
                    skipped += 1
                    continue
                # Skip the scanner itself
                if SCANNER_FILENAME in filepath.name.lower():
                    continue
                if filepath.stat().st_size > max_file_size:
                    continue
                scanned += 1
                try:
                    content = filepath.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue

                # Check tier 1 patterns first (actual credential values)
                matched = False
                for pattern, label in CREDENTIAL_PATTERNS:
                    if re.search(pattern, content):
                        hits += 1
                        matched = True
                        matched_lines = _extract_match_context(content, pattern)
                        results.add(Finding(
                            "credentials",
                            f"Credential found: {filepath.name}",
                            f"{label} in {filepath}",
                            severity="HIGH",
                            evidence=f"File: {filepath}\n    {matched_lines}",
                        ))
                        break

                # If no tier 1 match, check tier 2 (credential references)
                if not matched:
                    for pattern, label in CREDENTIAL_REF_PATTERNS:
                        if re.search(pattern, content):
                            hits += 1
                            matched_lines = _extract_match_context(
                                content, pattern)
                            results.add(Finding(
                                "credentials",
                                f"Possible credential ref: {filepath.name}",
                                f"{label} in {filepath}",
                                severity="MEDIUM",
                                evidence=f"File: {filepath}\n    {matched_lines}",
                            ))
                            break
        except PermissionError:
            pass

    debug(f"File scan complete: {scanned} scanned, {hits} hits, {skipped} skipped (excluded dirs).")


def check_aws_profiles(results: ScanResults):
    status("Checking AWS credential profiles...")
    aws_paths = [Path.home() / ".aws" / "credentials",
                 Path.home() / ".aws" / "config"]
    if is_windows():
        users_dir = Path(r"C:\Users")
        if users_dir.exists():
            for user_dir in users_dir.iterdir():
                if user_dir.is_dir():
                    aws_paths.append(user_dir / ".aws" / "credentials")
                    aws_paths.append(user_dir / ".aws" / "config")

    found = False
    for aws_path in aws_paths:
        if aws_path.exists():
            found = True
            try:
                content = aws_path.read_text(errors="ignore")
                profiles = re.findall(r"\[(?:profile\s+)?(.+?)\]", content)
                has_keys = "aws_access_key_id" in content.lower()
                results.add(Finding(
                    "credentials", f"AWS credential file: {aws_path}",
                    f"Contains {len(profiles)} profile(s). "
                    f"{'Static access keys present.' if has_keys else 'No static keys (SSO/role assumption).'}",
                    severity="HIGH" if has_keys else "MEDIUM",
                    evidence=f"Profiles: {', '.join(profiles[:5])}",
                ))
            except (PermissionError, OSError):
                pass
    if not found:
        debug("No AWS credential files found.")


def check_azure_cli(results: ScanResults):
    status("Checking Azure CLI tokens...")
    azure_paths = []
    if is_windows():
        profile = os.environ.get("USERPROFILE", "")
        azure_paths = [
            Path(profile) / ".azure" / "azureProfile.json",
            Path(profile) / ".azure" / "msal_token_cache.json",
            Path(profile) / ".azure" / "accessTokens.json",
        ]
    else:
        azure_paths = [
            Path.home() / ".azure" / "azureProfile.json",
            Path.home() / ".azure" / "msal_token_cache.json",
            Path.home() / ".azure" / "accessTokens.json",
        ]

    found = False
    for az_path in azure_paths:
        if az_path.exists():
            found = True
            severity = "CRITICAL" if "token" in az_path.name.lower() else "HIGH"
            try:
                size = az_path.stat().st_size
                results.add(Finding(
                    "credentials", f"Azure CLI cache: {az_path.name}",
                    f"Token cache at {az_path} ({size} bytes). May contain "
                    f"valid refresh tokens for the Entra tenant.",
                    severity=severity, evidence=f"Path: {az_path}",
                ))
            except (PermissionError, OSError):
                pass
    if not found:
        debug("No Azure CLI cache files found.")


def check_scheduled_tasks(results: ScanResults):
    status("Checking scheduled tasks for cloud references...")
    if not is_windows():
        cron_output = run_cmd("crontab -l 2>/dev/null")
        if cron_output:
            for pattern, label in CREDENTIAL_PATTERNS[:6]:
                if re.search(pattern, cron_output, re.IGNORECASE):
                    results.add(Finding(
                        "persistence", "Cron job references cloud credentials",
                        f"A cron entry matches pattern for {label}.",
                        severity="HIGH", evidence=cron_output[:300],
                    ))
        return

    task_output = run_powershell(
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} "
        "| ForEach-Object { $_.TaskName + '|' + "
        "($_.Actions.Execute -join ';') + '|' + "
        "($_.Actions.Arguments -join ';') }")
    if not task_output:
        debug("No scheduled tasks retrieved or none active.")
        return

    cloud_keywords = [
        "azure", "aws", "gcloud", "azcopy", "az.ps1",
        "microsoftonline", "graph.microsoft", "s3",
        "Connect-AzAccount", "Connect-MsolService",
        "Connect-AzureAD", "Set-MsolUser",
    ]
    found = False
    for line in task_output.splitlines():
        for kw in cloud_keywords:
            if kw.lower() in line.lower():
                found = True
                parts = line.split("|")
                task_name = parts[0] if parts else line
                results.add(Finding(
                    "persistence",
                    f"Scheduled task references cloud: {task_name}",
                    f"Task \"{task_name}\" contains cloud commands or endpoints.",
                    severity="MEDIUM", evidence=line[:300],
                ))
                break
    if not found:
        debug("No cloud-referencing scheduled tasks found.")


def check_registry_cloud_agents(results: ScanResults):
    status("Checking registry for cloud agents...")
    if not is_windows():
        return

    registry_checks = [
        (r"HKLM\SOFTWARE\Microsoft\Azure AD Connect", "Entra Connect"),
        (r"HKLM\SOFTWARE\Microsoft\ADFS", "ADFS"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudDomainJoin",
         "Entra device join"),
        (r"HKLM\SOFTWARE\Amazon\SSMAgent", "AWS SSM Agent"),
        (r"HKLM\SOFTWARE\Google\CloudOpsAgent", "GCP Ops Agent"),
        (r"HKLM\SOFTWARE\Microsoft\Intune", "Microsoft Intune"),
        (r"HKLM\SOFTWARE\Microsoft\OneDrive", "OneDrive (cloud sync)"),
        (r"HKLM\SOFTWARE\Microsoft\Azure Connected Machine Agent",
         "Azure Arc Connected Machine agent"),
        (r"HKLM\SOFTWARE\Microsoft\Microsoft AAD App Proxy Connector",
         "Entra Application Proxy Connector"),
        (r"HKLM\SOFTWARE\Microsoft\AzureADPrivateNetwork",
         "Entra Private Access / App Proxy network"),
        (r"HKLM\SOFTWARE\Microsoft\PassthroughAuthentication",
         "Entra Pass-through Authentication"),
    ]
    for reg_path, agent_name in registry_checks:
        output = run_cmd(f'reg query "{reg_path}" 2>nul')
        if output and "ERROR" not in output.upper():
            results.add(Finding(
                "cloud_agents", f"Cloud agent installed: {agent_name}",
                f"Registry key for {agent_name} exists. May hold cached "
                f"credentials or session tokens.",
                severity="MEDIUM", evidence=f"Key: {reg_path}",
            ))
        else:
            debug(f"Registry key not found: {agent_name}")

    # Device join status
    dsregcmd = run_cmd("dsregcmd /status")
    if dsregcmd:
        join_indicators = {
            "AzureAdJoined : YES": ("Azure AD Joined", "HIGH"),
            "DomainJoined : YES": ("Domain Joined", "INFO"),
            "WorkplaceJoined : YES": ("Workplace Joined (BYOD)", "MEDIUM"),
        }
        for indicator, (label, severity) in join_indicators.items():
            if indicator in dsregcmd:
                results.add(Finding(
                    "cloud_agents", f"Device join: {label}",
                    f"This host is {label}. May hold PRTs usable for cloud auth.",
                    severity=severity, evidence=indicator,
                ))


def check_conditional_access_indicators(results: ScanResults):
    status("Checking conditional access bypass indicators...")
    if not is_windows():
        return

    # Try ADSI first (works without RSAT), then RSAT cmdlet
    debug("Querying AD for AZUREADSSOACC$ Seamless SSO account (ADSI)...")
    sso_check = run_powershell(
        _adsi_searcher() +
        "$s.Filter = '(&(objectCategory=computer)"
        "(samAccountName=AZUREADSSOACC$))';"
        "$s.PropertiesToLoad.AddRange(@('samaccountname','dnshostname'));"
        "$r = $s.FindOne();"
        "if($r){"
        "  $p = $r.Properties;"
        "  [PSCustomObject]@{"
        "    SamAccountName=$p['samaccountname'][0];"
        "    DnsHostName=if($p['dnshostname']){$p['dnshostname'][0]}else{''}"
        "  } | ConvertTo-Json"
        "}")
    if not sso_check or "AZUREADSSOACC" not in sso_check:
        debug("ADSI SSO query returned nothing, trying RSAT Get-ADComputer...")
        sso_check = run_powershell(
            f"Get-ADComputer {_rsat_server()}"
            "-Filter {SamAccountName -eq 'AZUREADSSOACC$'} "
            "| Select-Object SamAccountName, Enabled | ConvertTo-Json")
    if sso_check and "AZUREADSSOACC" in sso_check:
        debug(f"AZUREADSSOACC$ found: {sso_check[:200]}")
        results.add(Finding(
            "federation",
            "Seamless SSO account found (AZUREADSSOACC$)",
            "Seamless SSO is configured. Extracting this account's Kerberos "
            "key enables forging cloud auth tickets for any synced user.",
            severity="CRITICAL", evidence=sso_check[:300],
        ))
    else:
        debug("AZUREADSSOACC$ not found in AD (tried ADSI and RSAT).")

    prt_check = run_cmd("dsregcmd /status")
    if prt_check and "AzureAdPrt : YES" in prt_check:
        results.add(Finding(
            "credentials", "Primary Refresh Token (PRT) present",
            "This device holds an Entra PRT. Extractable and replayable "
            "to access cloud services, potentially bypassing MFA.",
            severity="HIGH", evidence="AzureAdPrt : YES",
        ))
    else:
        debug("No PRT detected on this device.")


def check_network_shares_for_cloud_scripts(results: ScanResults):
    status("Scanning SYSVOL/NETLOGON for cloud credentials...")
    if not is_windows():
        return

    share_paths = []
    domain_info = run_cmd("echo %USERDNSDOMAIN%")
    if domain_info and "%" not in domain_info:
        share_paths.extend([
            f"\\\\{domain_info}\\SYSVOL",
            f"\\\\{domain_info}\\NETLOGON",
        ])

    for share_path in share_paths:
        if not os.path.exists(share_path):
            debug(f"Share not accessible: {share_path}")
            continue
        try:
            for root, dirs, files in os.walk(share_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in CONFIG_EXTENSIONS:
                        continue
                    try:
                        content = open(fpath, "r", errors="ignore").read()
                        found_in_share = False
                        for pattern, label in CREDENTIAL_PATTERNS:
                            if re.search(pattern, content):
                                found_in_share = True
                                matched_lines = _extract_match_context(content, pattern)
                                results.add(Finding(
                                    "credentials",
                                    f"Credential on share: {fname}",
                                    f"{label} in {fpath}. Readable by all domain users.",
                                    severity="CRITICAL",
                                    evidence=f"File: {fpath}\n    {matched_lines}",
                                ))
                                break
                        if not found_in_share:
                            for pattern, label in CREDENTIAL_REF_PATTERNS:
                                if re.search(pattern, content):
                                    matched_lines = _extract_match_context(content, pattern)
                                    results.add(Finding(
                                        "credentials",
                                        f"Possible credential ref on share: {fname}",
                                        f"{label} in {fpath}. Readable by all domain users.",
                                        severity="HIGH",
                                        evidence=f"File: {fpath}\n    {matched_lines}",
                                    ))
                                    break
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_summary(results: ScanResults):
    report = results.to_dict()

    print()
    cprint("=" * 70, Colors.BOLD)
    cprint("  CLOUD BOUNDARY SCANNER  //  RESULTS SUMMARY", Colors.BOLD + Colors.CYAN)
    cprint("=" * 70, Colors.BOLD)

    # Domain context
    if report.get("cloud_domain"):
        cprint(f"  Cloud Tenant:    {report['cloud_domain']}", Colors.WHITE)
    cprint(f"  On-prem Domain:  {report['onprem_domain']}", Colors.WHITE)
    if DC_TARGET:
        cprint(f"  Remote DC:       {DC_TARGET}", Colors.WHITE)

    # Surface discovered boundary servers from findings
    boundary_servers = []
    for f in report["findings"]:
        if f["category"] in ("sync_services", "federation", "cloud_bridge"):
            # Extract server name from detail text
            m = re.search(r"Entra Connect server:\s*(\S+)", f["detail"])
            if m:
                boundary_servers.append(
                    (m.group(1).rstrip("."), f["title"]))
            elif "ADFS server detected" in f["title"]:
                boundary_servers.append(
                    (report["hostname"], f["title"]))
            elif f["category"] == "cloud_bridge":
                boundary_servers.append(
                    (report["hostname"], f["title"]))
    if boundary_servers:
        print()
        cprint("  Boundary Servers Identified:", Colors.BOLD + Colors.MAGENTA)
        seen = set()
        for server, role in boundary_servers:
            if server not in seen:
                seen.add(server)
                cprint(f"    {server}  —  {role}", Colors.MAGENTA)
    else:
        print()
        cprint("  Boundary Servers:  none identified on this scan",
               Colors.GRAY)

    if DEBUG_MODE:
        cprint(f"  Started:   {report['scan_start']}", Colors.GRAY)
        cprint(f"  Completed: {report['scan_end']}", Colors.GRAY)
    print()

    total = report["total_findings"]
    crits = report["severity_counts"]["CRITICAL"]
    highs = report["severity_counts"]["HIGH"]
    meds = report["severity_counts"]["MEDIUM"]

    cprint(f"  Total findings: {total}", Colors.BOLD)
    if crits:
        cprint(f"    CRITICAL : {crits}", Colors.RED + Colors.BOLD)
    if highs:
        cprint(f"    HIGH     : {highs}", Colors.RED)
    if meds:
        cprint(f"    MEDIUM   : {meds}", Colors.YELLOW)
    if report["severity_counts"]["LOW"]:
        cprint(f"    LOW      : {report['severity_counts']['LOW']}", Colors.CYAN)
    if report["severity_counts"]["INFO"]:
        cprint(f"    INFO     : {report['severity_counts']['INFO']}", Colors.GRAY)

    cprint("=" * 70, Colors.BOLD)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG_MODE, DC_TARGET, DC_BASE_DN, DC_CONFIG_NC, DC_USER, DC_PASS

    parser = argparse.ArgumentParser(
        description="Cloud Boundary Scanner (Windows)")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Write JSON report to file.")
    parser.add_argument("-dc", type=str, default="",
                        help="Target a remote domain controller by IP. "
                             "Queries that DC's domain for sync objects "
                             "instead of the local domain.")
    parser.add_argument("-u", "--user", type=str, default="",
                        help="Username for remote DC authentication "
                             "(DOMAIN\\\\user or user@domain). "
                             "Required with -dc for cross-domain queries.")
    parser.add_argument("-p", "--password", type=str, default="",
                        help="Password for remote DC authentication. "
                             "Used with -u for explicit LDAP bind.")
    parser.add_argument("--silent", action="store_true",
                        help="Reduce output (suppress debug/negative results).")
    parser.add_argument("--debug", action="store_true",
                        help="(Default behavior) Verbose output. Kept for "
                             "backward compatibility.")
    parser.add_argument("--exclude-path", action="append", default=[],
                        metavar="DIR",
                        help="Additional directory names to skip during file "
                             "scanning (repeatable). .venv, site-packages, "
                             "node_modules etc. are excluded by default.")
    args = parser.parse_args()

    # Verbose is now the default; --silent suppresses debug output
    DEBUG_MODE = not args.silent

    # Enable ANSI color support on Windows terminals before any output.
    # Without this, the first lines print raw escape codes (?[1m?[96m).
    _enable_windows_vt_processing()

    print()
    cprint("  Cloud Boundary Scanner (Windows)", Colors.BOLD + Colors.CYAN)
    print()

    results = ScanResults()

    # Resolve remote DC if specified
    if args.dc:
        DC_TARGET = args.dc
        if args.user:
            DC_USER = args.user
        if args.password:
            DC_PASS = args.password
        status(f"Resolving base DN from remote DC {DC_TARGET}...")
        if DC_USER and DC_PASS:
            escaped_pass = DC_PASS.replace("'", "''")
            rootdse_out = run_powershell(
                f"$r = New-Object DirectoryServices.DirectoryEntry("
                f"'LDAP://{DC_TARGET}/RootDSE','{DC_USER}','{escaped_pass}'); "
                f"$r.defaultNamingContext[0] + '|' + "
                f"$r.configurationNamingContext[0]")
        else:
            rootdse_out = run_powershell(
                f"$r = [ADSI]'LDAP://{DC_TARGET}/RootDSE'; "
                f"$r.defaultNamingContext[0] + '|' + "
                f"$r.configurationNamingContext[0]")
        if rootdse_out and "|" in rootdse_out:
            parts = rootdse_out.strip().split("|", 1)
            DC_BASE_DN = parts[0].strip()
            DC_CONFIG_NC = parts[1].strip()
            debug(f"Remote DC base DN: {DC_BASE_DN}")
            debug(f"Remote DC config NC: {DC_CONFIG_NC}")
            domain_from_dn = _domain_from_base_dn(DC_BASE_DN)
            if domain_from_dn:
                results.onprem_domain = domain_from_dn
                cprint(f"  Remote domain: {domain_from_dn}", Colors.WHITE)
        else:
            cprint(f"  [!] Could not resolve base DN from {DC_TARGET}. "
                   "AD queries will target this DC but may fail.",
                   Colors.YELLOW)
        print()

    modules = [
        check_sync_services, check_adfs, check_cloud_dns,
        check_cloud_dns_integration,
        check_outbound_connections, check_environment_variables,
        lambda r: check_credential_files(r, extra_excludes=args.exclude_path),
        check_aws_profiles, check_azure_cli,
        check_scheduled_tasks, check_registry_cloud_agents,
        check_conditional_access_indicators,
        check_network_shares_for_cloud_scripts,
    ]

    for module in modules:
        try:
            module(results)
        except Exception as exc:
            name = getattr(module, "__name__", "check_credential_files")
            cprint(f"  [!] Module {name} failed: {exc}",
                   Colors.YELLOW)

    print_summary(results)

    if args.output:
        report_path = Path(args.output)
        report_path.write_text(json.dumps(results.to_dict(), indent=2))
        cprint(f"  JSON report written to: {report_path}\n", Colors.GREEN)

    critical_count = sum(1 for f in results.findings
                         if f.severity == "CRITICAL")
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
