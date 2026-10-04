#!/usr/bin/env python3
"""
Cloud Boundary Scanner (Kali)
=============================
Remote enumeration of on-prem to cloud connectivity during authorized
penetration tests. Runs from a Kali VM against a target AD environment
using supplied credentials.

Usage:
    python3 cloud_boundary_scanner_kali.py -u 'DOMAIN\\user' -p 'Pass' -dc 10.0.0.1
    python3 cloud_boundary_scanner_kali.py -u 'user@domain.com' -p 'Pass' -dc 10.0.0.1 -t 10.0.0.0/24
    python3 cloud_boundary_scanner_kali.py -u 'DOMAIN\\user' -H lm:nt -dc 10.0.0.1

Requirements:
    pip3 install impacket ldap3 dnspython

Author: Russell (Thrive Offensive Security)
License: For authorized testing only.
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------

class Colors:
    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
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
            "KEY": Colors.RED + Colors.BOLD,
            "NOTABLE": Colors.ORANGE,
            "RELEVANT": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFO": Colors.GRAY,
        }.get(severity, Colors.WHITE)

    @staticmethod
    def strip_if_no_tty(text: str) -> str:
        if not sys.stdout.isatty():
            return re.sub(r"\033\[[0-9;]*m", "", text)
        return text


def cprint(text: str, color: str = "", end: str = "\n"):
    msg = f"{color}{text}{Colors.RESET}" if color else text
    print(Colors.strip_if_no_tty(msg), end=end)


DEBUG_MODE = True


def debug(msg: str):
    if DEBUG_MODE:
        cprint(f"  [DBG] {msg}", Colors.GRAY)


def status(msg: str):
    cprint(f"  [*] {msg}", Colors.CYAN)


# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, scmr, rrp
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

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

SYNC_SERVICE_NAMES = [
    "ADSync", "AzureADConnectHealthSyncInsights",
    "AADConnectProvisioningAgent", "AzureADConnectAgentUpdater", "adfssrv",
    # Cloud bridge services
    "himds", "GCArcService", "ExtensionService",
    "Microsoft AAD App Proxy Connector", "WAPCSvc",
    "AzureADConnectAuthenticationAgent",
]

# Descriptions for cloud bridge services (used for finding output)
CLOUD_BRIDGE_SERVICES = {
    "himds": ("Azure Arc Hybrid Instance Metadata Service", "NOTABLE"),
    "GCArcService": ("Azure Arc Guest Configuration agent", "NOTABLE"),
    "ExtensionService": ("Azure Arc Extension Service", "RELEVANT"),
    "Microsoft AAD App Proxy Connector": ("Entra Application Proxy Connector", "NOTABLE"),
    "WAPCSvc": ("Web Application Proxy Service (ADFS/App Proxy)", "NOTABLE"),
    "AzureADConnectAuthenticationAgent": ("Entra Pass-through Authentication agent", "KEY"),
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
    (r"(?i)Connect-AzAccount", "Azure PowerShell login"),
    (r"(?i)Connect-MsolService", "MSOnline PowerShell login"),
    (r"(?i)Connect-AzureAD", "AzureAD PowerShell login"),
    (r"(?i)Set-Msoluser", "MSOnline user modification"),
    (r"(?i)azcopy", "AzCopy cloud transfer tool"),
]

SCANNER_FILENAME = "cloud_boundary_scanner"  # exclude self from results

# Directories to skip during share scanning (dev/tool artifacts, not real creds)
DEFAULT_EXCLUDE_DIRS = {
    ".venv", "venv", "env", ".env", "__pycache__", "site-packages",
    "node_modules", ".git", ".tox", "dist-packages", "lib-python",
    "SelfTest", ".mypy_cache", ".pytest_cache",
}

SHARE_SCAN_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs",
    ".py", ".rb", ".config", ".xml", ".json", ".yaml",
    ".yml", ".env", ".ini", ".conf", ".tf", ".tfvars",
    ".txt", ".log", ".properties",
}

INTERESTING_SHARES = ["SYSVOL", "NETLOGON", "Scripts", "Automation",
                      "IT", "Admin", "Deploy", "Backup", "Tools"]

# ---------------------------------------------------------------------------
# Finding / Results
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, category: str, title: str, detail: str,
                 severity: str = "INFO", evidence: str = "",
                 host: str = ""):
        self.category = category
        self.title = title
        self.detail = detail
        self.severity = severity
        self.evidence = evidence
        self.host = host
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category, "title": self.title,
            "detail": self.detail, "severity": self.severity,
            "evidence": self.evidence, "host": self.host,
            "timestamp": self.timestamp,
        }


class ScanResults:
    def __init__(self, onprem_domain: str = "", cloud_domain: str = ""):
        self.findings: list[Finding] = []
        self.scan_start = datetime.utcnow().isoformat()
        self.hosts_scanned: list[str] = []
        self.onprem_domain = onprem_domain
        self.cloud_domain = cloud_domain

    def add(self, finding: Finding):
        self.findings.append(finding)
        color = Colors.severity_color(finding.severity)
        host_tag = f" [{finding.host}]" if finding.host else ""
        if finding.severity in ("KEY", "NOTABLE", "RELEVANT"):
            cprint(f"  [+] [{finding.severity}]{host_tag} {finding.title}", color)
            # Show evidence inline for credential findings so values are visible
            if finding.evidence and finding.category == "credentials":
                for eline in finding.evidence.splitlines():
                    cprint(f"      {eline.strip()}", Colors.DIM)
        elif DEBUG_MODE:
            cprint(f"  [.] [{finding.severity}]{host_tag} {finding.title}", color)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_start": self.scan_start,
            "scan_end": datetime.utcnow().isoformat(),
            "onprem_domain": self.onprem_domain,
            "cloud_domain": self.cloud_domain,
            "hosts_scanned": self.hosts_scanned,
            "total_findings": len(self.findings),
            "severity_counts": {
                s: sum(1 for f in self.findings if f.severity == s)
                for s in ("KEY", "NOTABLE", "RELEVANT", "LOW", "INFO")
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class Credentials:
    def __init__(self, username: str, password: str, domain: str,
                 nthash: str = "", lmhash: str = ""):
        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = nthash
        self.lmhash = lmhash

    @classmethod
    def from_args(cls, args) -> "Credentials":
        username = args.username
        domain = args.domain or ""
        password = args.password or ""
        lmhash = ""
        nthash = ""

        if "\\" in username:
            domain, username = username.split("\\", 1)
        elif "@" in username and not domain:
            username, domain = username.split("@", 1)

        if args.hashes:
            parts = args.hashes.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts
            else:
                nthash = parts[0]
                lmhash = "aad3b435b51404eeaad3b435b51404ee"

        if not domain:
            cprint("  [!] Domain is required. Use DOMAIN\\user, user@domain, or -d DOMAIN.",
                   Colors.RED)
            sys.exit(1)

        return cls(username=username, password=password,
                   domain=domain, nthash=nthash, lmhash=lmhash)

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    @property
    def has_hash(self) -> bool:
        return bool(self.nthash)


# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------

def discover_live_hosts(target: str, timeout: float = 1.0) -> list[str]:
    hosts = []
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]

    if network.num_addresses > 65536:
        cprint(f"  [!] Subnet too large ({network.num_addresses} hosts). "
               f"Limit to /16 or smaller.", Colors.YELLOW)
        return []

    status(f"Scanning {target} for live hosts ({network.num_addresses} addresses)...")

    def probe_host(ip: str) -> Optional[str]:
        for port in (445, 389, 88, 135):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return ip
            except (socket.error, OSError):
                pass
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(probe_host, str(ip)): str(ip)
                   for ip in network.hosts()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hosts.append(result)
                cprint(f"    Host alive: {result}", Colors.GREEN)

    cprint(f"  [*] Found {len(hosts)} live hosts.", Colors.CYAN)
    return sorted(hosts, key=lambda x: ipaddress.ip_address(x))


# ---------------------------------------------------------------------------
# LDAP enumeration
# ---------------------------------------------------------------------------

def ldap_connect(dc_ip: str, creds: Credentials) -> Optional[ldap3.Connection]:
    if not HAS_LDAP3:
        cprint("  [!] ldap3 not installed. Run: pip3 install ldap3", Colors.RED)
        return None

    try:
        server = Server(dc_ip, get_info=ALL, use_ssl=False, port=389)
        ntlm_user = f"{creds.domain}\\{creds.username}"

        if creds.has_hash and not creds.has_password:
            cprint("  [!] LDAP bind with hash only is limited in ldap3. "
                   "Provide a password for LDAP queries.", Colors.YELLOW)
            return None

        conn = Connection(server, user=ntlm_user,
                          password=creds.password,
                          authentication=NTLM, auto_bind=True)
        cprint(f"  [+] LDAP bind successful to {dc_ip} as {ntlm_user}",
               Colors.GREEN)
        return conn
    except Exception as exc:
        cprint(f"  [!] LDAP bind failed to {dc_ip}: {exc}", Colors.RED)
        return None


def enumerate_ad_cloud_objects(conn: ldap3.Connection,
                                results: ScanResults, dc_ip: str):
    base_dn = conn.server.info.other.get("defaultNamingContext", [None])[0]
    if not base_dn:
        try:
            base_dn = conn.server.info.other["rootDomainNamingContext"][0]
        except (KeyError, IndexError):
            cprint("  [!] Could not determine base DN.", Colors.RED)
            return

    debug(f"Base DN: {base_dn}")

    # --- MSOL_ sync account ---
    status("Querying AD for MSOL_ sync account...")
    conn.search(base_dn, "(sAMAccountName=MSOL_*)", SUBTREE,
                attributes=["sAMAccountName", "description", "whenCreated",
                             "userAccountControl", "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            desc = str(entry.description) if hasattr(entry, "description") else ""
            debug(f"MSOL_ account found: {entry.sAMAccountName}, "
                  f"Description: {desc[:200]}")
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""

            # Parse description for boundary server and tenant
            # Format: "...running on computer [HOSTNAME] configured to
            # synchronize to tenant [TENANT]..."
            server_hint = ""
            tenant_hint = ""
            m_srv = re.search(r"running on computer\s+(\S+)",
                              desc, re.IGNORECASE)
            if m_srv:
                server_hint = m_srv.group(1).rstrip(".")
            m_ten = re.search(r"synchronize to tenant\s+(\S+)",
                              desc, re.IGNORECASE)
            if m_ten:
                tenant_hint = m_ten.group(1).rstrip(".")
                if not results.cloud_domain:
                    results.cloud_domain = tenant_hint

            detail = (
                "The MSOL_ account is the Entra Connect directory sync "
                "account. It holds DCSync-equivalent privileges on-prem "
                "and write access in the Entra tenant."
            )
            if server_hint:
                detail += f" Entra Connect server: {server_hint}."
            if tenant_hint:
                detail += f" Target tenant: {tenant_hint}."

            results.add(Finding(
                "sync_services",
                f"MSOL sync service account: {sam}" if sam else "MSOL sync service account found in AD",
                detail, severity="KEY", host=dc_ip,
                evidence=(f"DN: {entry.distinguishedName}, "
                          f"Description: {desc[:300]}"),
            ))
    else:
        debug("No MSOL_ sync account found.")

    # --- Entra Connect Service Connection Point (SCP) ---
    status("Querying AD for Entra Connect SCP...")
    config_nc = conn.server.info.other.get(
        "configurationNamingContext", [None])[0]
    if config_nc:
        scp_base = (f"CN=Device Registration Configuration,"
                    f"CN=Services,{config_nc}")
        try:
            conn.search(scp_base,
                        "(objectClass=serviceConnectionPoint)", SUBTREE,
                        attributes=["keywords", "distinguishedName"])
            if conn.entries:
                for entry in conn.entries:
                    keywords = (str(entry.keywords)
                                if hasattr(entry, "keywords") else "")
                    debug(f"Entra Connect SCP found: {keywords[:200]}")
                    tenant_from_scp = ""
                    m_ad = re.search(r"azureADName[:\s]+(\S+)",
                                     keywords, re.IGNORECASE)
                    if m_ad:
                        tenant_from_scp = m_ad.group(1)
                        if not results.cloud_domain:
                            results.cloud_domain = tenant_from_scp
                    results.add(Finding(
                        "sync_services",
                        "Entra Connect Service Connection Point in AD",
                        "The Entra Connect SCP is registered in the AD "
                        "configuration partition, confirming hybrid "
                        "identity sync is deployed."
                        + (f" Cloud tenant: {tenant_from_scp}."
                           if tenant_from_scp else ""),
                        severity="NOTABLE", host=dc_ip,
                        evidence=(f"DN: {entry.distinguishedName}, "
                                  f"Keywords: {keywords[:300]}"),
                    ))
            else:
                debug("No Entra Connect SCP found in configuration partition.")
        except Exception as exc:
            debug(f"SCP query failed (config partition may not be "
                  f"accessible): {exc}")
    else:
        debug("Could not determine configurationNamingContext for SCP query.")

    # --- AZUREADSSOACC$ (Seamless SSO) ---
    status("Querying AD for AZUREADSSOACC$ (Seamless SSO)...")
    conn.search(base_dn, "(sAMAccountName=AZUREADSSOACC$)", SUBTREE,
                attributes=["sAMAccountName", "distinguishedName",
                             "whenCreated", "servicePrincipalName"])
    if conn.entries:
        for entry in conn.entries:
            debug(f"AZUREADSSOACC$ found: {entry.distinguishedName}")
            results.add(Finding(
                "federation",
                "Seamless SSO account found (AZUREADSSOACC$)",
                "Seamless SSO is configured. Extracting this account's "
                "Kerberos key enables forging cloud auth tickets for "
                "any synced user.",
                severity="KEY", host=dc_ip,
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("AZUREADSSOACC$ not found.")

    # --- Entra Connect server ---
    status("Locating Entra Connect server...")
    conn.search(base_dn,
                "(&(objectClass=computer)(description=*Azure AD Connect*))",
                SUBTREE,
                attributes=["cn", "dNSHostName", "operatingSystem",
                             "description", "distinguishedName"])
    if not conn.entries:
        debug("No Entra Connect server found via description, "
              "trying SPN search...")
        conn.search(base_dn, "(servicePrincipalName=*ADSync*)", SUBTREE,
                    attributes=["cn", "dNSHostName", "servicePrincipalName",
                                 "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            hostname = (entry.dNSHostName
                        if hasattr(entry, "dNSHostName") else entry.cn)
            debug(f"Entra Connect server found: {hostname}")
            results.add(Finding(
                "sync_services",
                f"Entra Connect server: {hostname}",
                "Primary target for ADSync database credential extraction."
                f" Entra Connect server: {hostname}.",
                severity="KEY", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No Entra Connect server found via LDAP.")

    # --- ADFS servers ---
    status("Locating ADFS servers...")
    conn.search(base_dn, "(servicePrincipalName=*adfs*)", SUBTREE,
                attributes=["cn", "dNSHostName", "servicePrincipalName",
                             "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            hostname = (entry.dNSHostName
                        if hasattr(entry, "dNSHostName") else entry.cn)
            debug(f"ADFS server found: {hostname}")
            results.add(Finding(
                "federation", f"ADFS server: {hostname}",
                "Token-signing certificate enables Golden SAML if "
                "compromised.",
                severity="KEY", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No ADFS servers found via SPN search.")

    # --- AAD Password Protection ---
    status("Checking for Azure AD Password Protection proxies...")
    conn.search(base_dn, "(servicePrincipalName=*AzureADPasswordProtection*)",
                SUBTREE, attributes=["cn", "dNSHostName", "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            debug(f"AAD Password Protection proxy found: {entry.cn}")
            results.add(Finding(
                "cloud_agents",
                f"Azure AD Password Protection proxy: {entry.cn}",
                "Cloud policy enforcement on-prem. Proxy communicates "
                "with Entra.",
                severity="RELEVANT", host=str(entry.cn),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No Azure AD Password Protection proxies found.")

    # --- Cloud-related SPNs ---
    status("Checking for cloud-related SPNs...")
    for spn_filter in [
        "(servicePrincipalName=*microsoftonline*)",
        "(servicePrincipalName=*graph.microsoft*)",
        "(servicePrincipalName=*amazonaws*)",
        "(servicePrincipalName=*googleapis*)",
    ]:
        try:
            conn.search(base_dn, spn_filter, SUBTREE,
                        attributes=["cn", "sAMAccountName",
                                     "servicePrincipalName",
                                     "distinguishedName"])
            for entry in conn.entries:
                debug(f"Cloud SPN found: {entry.sAMAccountName} -> "
                      f"{entry.servicePrincipalName}")
                results.add(Finding(
                    "cloud_agents",
                    f"Cloud SPN on: {entry.sAMAccountName}",
                    "Account authenticates to cloud services via SPN.",
                    severity="RELEVANT", host=dc_ip,
                    evidence=f"SPN: {entry.servicePrincipalName}",
                ))
        except Exception:
            pass

    # --- Unconstrained delegation ---
    status("Checking for unconstrained delegation...")
    conn.search(base_dn,
                "(&(objectCategory=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                SUBTREE, attributes=["cn", "dNSHostName",
                                      "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            hostname = (entry.dNSHostName
                        if hasattr(entry, "dNSHostName") else entry.cn)
            debug(f"Unconstrained delegation found: {hostname}")
            results.add(Finding(
                "delegation", f"Unconstrained delegation: {hostname}",
                "TGTs cached for any authenticating user. High-value "
                "pivot if the sync server authenticates here.",
                severity="NOTABLE", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No unconstrained delegation found.")

    # --- RBCD ---
    status("Checking for RBCD configurations...")
    conn.search(base_dn, "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                SUBTREE,
                attributes=["cn", "dNSHostName", "distinguishedName",
                             "msDS-AllowedToActOnBehalfOfOtherIdentity"])
    if conn.entries:
        for entry in conn.entries:
            hostname = (entry.dNSHostName
                        if hasattr(entry, "dNSHostName") else entry.cn)
            debug(f"RBCD configured on: {hostname}")
            results.add(Finding(
                "delegation", f"RBCD configured on: {hostname}",
                "Check if this is a sync/federation server with "
                "overly broad delegation.",
                severity="RELEVANT", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No RBCD configurations found.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_match_context(content: str, pattern: str,
                           max_lines: int = 3) -> str:
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
    return ("\n    ".join(matches)
            if matches else "(pattern matched but no printable line)")


def _is_excluded_share_path(file_path: str) -> bool:
    """Check if any path component matches an excluded directory."""
    parts = file_path.replace("/", "\\").split("\\")
    lower_excludes = {d.lower() for d in DEFAULT_EXCLUDE_DIRS}
    for part in parts:
        if part.lower() in lower_excludes:
            return True
    return False


# ---------------------------------------------------------------------------
# Remote host checks
# ---------------------------------------------------------------------------

def smb_connect(target: str, creds: Credentials) -> Optional["SMBConnection"]:
    if not HAS_IMPACKET:
        return None
    try:
        smb = SMBConnection(target, target, timeout=10)
        if creds.has_hash:
            smb.login(creds.username, "", creds.domain,
                      lmhash=creds.lmhash, nthash=creds.nthash)
        else:
            smb.login(creds.username, creds.password, creds.domain)
        debug(f"SMB auth OK to {target}")
        return smb
    except Exception as exc:
        debug(f"SMB auth failed to {target}: {exc}")
        return None


def check_remote_services(target: str, creds: Credentials,
                          results: ScanResults):
    if not HAS_IMPACKET:
        return
    status(f"Checking services on {target}...")
    try:
        string_binding = f"ncacn_np:{target}[\\pipe\\svcctl]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_credentials(
            creds.username, creds.password, creds.domain,
            creds.lmhash, creds.nthash)
        rpc_transport.set_connect_timeout(10)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        scmr_handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]

        for svc_name in SYNC_SERVICE_NAMES:
            try:
                svc_handle = scmr.hROpenServiceW(
                    dce, scmr_handle, svc_name)["lpServiceHandle"]
                svc_status = scmr.hRQueryServiceStatus(dce, svc_handle)
                state = svc_status["lpServiceStatus"]["dwCurrentState"]
                state_str = {1: "stopped", 2: "starting",
                             3: "stopping", 4: "running"}.get(
                    state, f"unknown({state})")
                if svc_name in CLOUD_BRIDGE_SERVICES:
                    bridge_desc, severity = CLOUD_BRIDGE_SERVICES[svc_name]
                    category = "cloud_bridge"
                    detail_msg = (f"{bridge_desc} is {state_str}. "
                                  f"Cloud bridge on {target}.")
                else:
                    severity = ("KEY" if svc_name in ("ADSync", "adfssrv")
                                else "NOTABLE")
                    category = "sync_services"
                    detail_msg = (f"Service is {state_str}. This is a Tier 0 "
                                  f"cloud boundary server."
                                  f" Entra Connect server: {target}.")
                debug(f"Service found on {target}: {svc_name} ({state_str})")
                results.add(Finding(
                    category,
                    f"Cloud service on {target}: {svc_name} ({state_str})",
                    detail_msg,
                    severity=severity, host=target,
                    evidence=f"Service: {svc_name}, State: {state_str}",
                ))
                scmr.hRCloseServiceHandle(dce, svc_handle)
            except Exception:
                debug(f"Service {svc_name} not found on {target}")

        scmr.hRCloseServiceHandle(dce, scmr_handle)
        dce.disconnect()
    except Exception as exc:
        debug(f"Service enum failed on {target}: {exc}")


def check_remote_registry(target: str, creds: Credentials,
                          results: ScanResults):
    if not HAS_IMPACKET:
        return
    status(f"Checking remote registry on {target}...")
    registry_checks = [
        ("HKLM", "SOFTWARE\\Microsoft\\Azure AD Connect", "Entra Connect"),
        ("HKLM", "SOFTWARE\\Microsoft\\ADFS", "ADFS"),
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                 "\\CloudDomainJoin", "Entra device join"),
        ("HKLM", "SOFTWARE\\Amazon\\SSMAgent", "AWS SSM Agent"),
        ("HKLM", "SOFTWARE\\Google\\CloudOpsAgent", "GCP Ops Agent"),
        ("HKLM", "SOFTWARE\\Microsoft\\Intune", "Microsoft Intune"),
        ("HKLM", "SOFTWARE\\Microsoft\\Azure Connected Machine Agent",
         "Azure Arc Connected Machine agent"),
        ("HKLM", "SOFTWARE\\Microsoft\\Microsoft AAD App Proxy Connector",
         "Entra Application Proxy Connector"),
        ("HKLM", "SOFTWARE\\Microsoft\\AzureADPrivateNetwork",
         "Entra Private Access / App Proxy network"),
        ("HKLM", "SOFTWARE\\Microsoft\\PassthroughAuthentication",
         "Entra Pass-through Authentication"),
    ]
    try:
        string_binding = f"ncacn_np:{target}[\\pipe\\winreg]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_credentials(
            creds.username, creds.password, creds.domain,
            creds.lmhash, creds.nthash)
        rpc_transport.set_connect_timeout(10)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        for hive_name, key_path, agent_name in registry_checks:
            try:
                hive_handle = rrp.hOpenLocalMachine(dce)["phKey"]
                key_handle = rrp.hBaseRegOpenKey(
                    dce, hive_handle, key_path)["phkResult"]
                debug(f"Registry key found on {target}: {agent_name}")
                results.add(Finding(
                    "cloud_agents",
                    f"Cloud agent on {target}: {agent_name}",
                    f"Registry key for {agent_name} exists. May hold "
                    f"cached tokens.",
                    severity=("RELEVANT" if "SSM" in agent_name or
                              "Intune" in agent_name else "NOTABLE"),
                    host=target, evidence=f"Key: {hive_name}\\{key_path}",
                ))
                rrp.hBaseRegCloseKey(dce, key_handle)
                rrp.hBaseRegCloseKey(dce, hive_handle)
            except Exception:
                debug(f"Registry key not found on {target}: {agent_name}")
        dce.disconnect()
    except Exception as exc:
        debug(f"Remote registry failed on {target}: {exc}")


def check_remote_shares(target: str, creds: Credentials,
                        results: ScanResults, max_files: int = 500):
    status(f"Scanning shares on {target}...")
    smb = smb_connect(target, creds)
    if not smb:
        return
    try:
        shares = smb.listShares()
    except Exception as exc:
        debug(f"Share listing failed on {target}: {exc}")
        return

    files_scanned = 0
    hits = 0
    skipped = 0
    for share in shares:
        share_name = share["shi1_netname"][:-1]
        if share_name.upper() in ("IPC$", "PRINT$", "C$", "ADMIN$"):
            continue
        is_priority = share_name.upper() in [s.upper()
                                              for s in INTERESTING_SHARES]
        try:
            file_list = []
            _walk_share(smb, share_name, "", file_list,
                        max_depth=3, max_files=max_files)
            for file_path, file_size in file_list:
                if files_scanned >= max_files:
                    break
                ext = os.path.splitext(file_path)[1].lower()
                if ext not in SHARE_SCAN_EXTENSIONS:
                    continue
                if file_size > 2 * 1024 * 1024:
                    continue
                # Skip excluded directories (dev tool artifacts)
                if _is_excluded_share_path(file_path):
                    skipped += 1
                    continue
                # Skip the scanner itself
                if SCANNER_FILENAME in file_path.lower():
                    continue
                files_scanned += 1
                try:
                    tid = smb.connectTree(share_name)
                    fh = smb.openFile(tid, file_path, desiredAccess=0x80)
                    content = b""
                    offset = 0
                    while offset < 2 * 1024 * 1024:
                        chunk = smb.readFile(tid, fh, offset, 65536)
                        if not chunk:
                            break
                        content += chunk
                        offset += len(chunk)
                    smb.closeFile(tid, fh)
                    text = content.decode("utf-8", errors="ignore")

                    # Check tier 1 patterns (actual credential values = HIGH)
                    matched = False
                    for pattern, label in CREDENTIAL_PATTERNS:
                        if re.search(pattern, text):
                            hits += 1
                            matched = True
                            sev = "KEY" if is_priority else "NOTABLE"
                            matched_lines = _extract_match_context(
                                text, pattern)
                            results.add(Finding(
                                "credentials",
                                f"Credential found: "
                                f"\\\\{target}\\{share_name}\\{file_path}",
                                f"{label} in share-accessible file.",
                                severity=sev, host=target,
                                evidence=(
                                    f"Share: {share_name}\\{file_path}\n"
                                    f"    {matched_lines}"),
                            ))
                            break

                    # If no tier 1, check tier 2 (references = MEDIUM)
                    if not matched:
                        for pattern, label in CREDENTIAL_REF_PATTERNS:
                            if re.search(pattern, text):
                                hits += 1
                                sev = "NOTABLE" if is_priority else "RELEVANT"
                                matched_lines = _extract_match_context(
                                    text, pattern)
                                results.add(Finding(
                                    "credentials",
                                    f"Possible credential ref: "
                                    f"\\\\{target}\\{share_name}"
                                    f"\\{file_path}",
                                    f"{label} in share-accessible file.",
                                    severity=sev, host=target,
                                    evidence=(
                                        f"Share: {share_name}\\{file_path}\n"
                                        f"    {matched_lines}"),
                                ))
                                break
                except Exception:
                    pass
        except Exception as exc:
            debug(f"Cannot access share {share_name} on {target}: {exc}")

    debug(f"Share scan on {target}: {files_scanned} scanned, "
          f"{hits} hits, {skipped} skipped (excluded dirs).")
    try:
        smb.logoff()
    except Exception:
        pass


def _walk_share(smb, share, path, results_list,
                max_depth=3, max_files=500, depth=0):
    if depth > max_depth or len(results_list) >= max_files:
        return
    try:
        listing = smb.listPath(share, path + "\\*" if path else "*")
        for item in listing:
            name = item.get_longname()
            if name in (".", ".."):
                continue
            full_path = f"{path}\\{name}" if path else name
            if item.is_directory():
                # Skip excluded directories early
                if name.lower() in {d.lower() for d in DEFAULT_EXCLUDE_DIRS}:
                    continue
                _walk_share(smb, share, full_path, results_list,
                            max_depth, max_files, depth + 1)
            else:
                results_list.append((full_path, item.get_filesize()))
                if len(results_list) >= max_files:
                    return
    except Exception:
        pass


# ---------------------------------------------------------------------------
# DNS and network checks
# ---------------------------------------------------------------------------

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
                f"{provider.upper()} endpoints resolvable "
                f"({len(reachable)}/{len(domains)})",
                f"Cloud connectivity to {provider.upper()} confirmed "
                f"from test network.",
                severity="INFO", evidence="\n".join(reachable[:6]),
            ))


def check_cloud_dns_integration(results: ScanResults, domain: str):
    """Check for DNS records indicating cloud identity integration."""
    if not domain:
        debug("No domain name available for DNS integration checks.")
        return

    status(f"Checking cloud integration DNS records for {domain}...")

    dns_checks = [
        (f"enterpriseregistration.{domain}",
         "Entra device registration (Workplace Join)", "NOTABLE"),
        (f"enterpriseenrollment.{domain}",
         "Intune MDM enrollment", "NOTABLE"),
        (f"msoid.{domain}",
         "Microsoft Online ID (O365 client detection)", "RELEVANT"),
        (f"autodiscover.{domain}",
         "Exchange Online autodiscovery", "RELEVANT"),
        (f"lyncdiscover.{domain}",
         "Teams/Skype for Business federation", "INFO"),
    ]

    found_any = False
    for hostname, description, severity in dns_checks:
        try:
            cname_target = ""
            addr = ""
            # Try CNAME resolution with dnspython
            if HAS_DNS:
                try:
                    answers = dns.resolver.resolve(hostname, "CNAME")
                    for rdata in answers:
                        cname_target = str(rdata.target).rstrip(".")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers, Exception):
                    pass
                try:
                    answers = dns.resolver.resolve(hostname, "A")
                    addr = str(answers[0])
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers, Exception):
                    pass

            # Fallback to socket
            if not addr:
                addr = socket.gethostbyname(hostname)

            found_any = True
            detail = (f"{hostname} resolves to {addr}. ")
            if cname_target:
                detail += f"CNAME target: {cname_target}. "
            detail += (f"This confirms {description} is configured, "
                       f"indicating cloud identity integration.")

            results.add(Finding(
                "dns_integration",
                f"Cloud DNS: {hostname}",
                detail, severity=severity,
                evidence=f"{hostname} -> {cname_target or addr}",
            ))
            debug(f"Cloud DNS integration: {hostname} -> "
                  f"{cname_target or addr}")
        except (socket.gaierror, Exception):
            debug(f"Cloud DNS not found: {hostname}")

    if not found_any:
        debug(f"No cloud integration DNS records found for {domain}.")


def check_adfs_metadata(dc_ip: str, creds: Credentials,
                        results: ScanResults):
    status("Probing for ADFS federation endpoints...")
    domain = creds.domain
    for hostname in [f"adfs.{domain}", f"sts.{domain}", f"fs.{domain}",
                     f"login.{domain}", f"sso.{domain}"]:
        try:
            ip = socket.gethostbyname(hostname)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 443))
            sock.close()
            if result == 0:
                debug(f"ADFS endpoint found: {hostname} ({ip})")
                results.add(Finding(
                    "federation", f"ADFS endpoint: {hostname} ({ip})",
                    f"Port 443 open. Check https://{hostname}/adfs/ls/ "
                    f"and the FederationMetadata.xml endpoint.",
                    severity="NOTABLE", host=ip,
                    evidence=f"{hostname} -> {ip}, port 443 open",
                ))
        except (socket.gaierror, socket.error):
            debug(f"ADFS probe failed: {hostname}")


def check_adsync_remote(target: str, creds: Credentials,
                        results: ScanResults):
    status(f"Checking for ADSync database on {target}...")
    smb = smb_connect(target, creds)
    if not smb:
        return
    adsync_paths = [
        ("C$", "Program Files\\Microsoft Azure AD Sync\\Data\\ADSync.mdf"),
        ("C$", "Program Files\\Microsoft Azure AD Sync\\Data\\"
               "ADSync_log.ldf"),
        ("C$", "ProgramData\\AADConnect\\PersistedState.xml"),
    ]
    for share, path in adsync_paths:
        try:
            smb.connectTree(share)
            smb.listPath(share, path)
            debug(f"ADSync file accessible on {target}: {path}")
            results.add(Finding(
                "sync_services", f"ADSync DB accessible: {path}",
                f"Extractable with local admin and AADInternals at "
                f"\\\\{target}\\{share}\\{path}.",
                severity="KEY", host=target,
                evidence=f"\\\\{target}\\{share}\\{path}",
            ))
        except Exception:
            debug(f"ADSync file not found on {target}: {path}")
    try:
        smb.logoff()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_summary(results: ScanResults):
    report = results.to_dict()

    print()
    cprint("=" * 70, Colors.BOLD)
    cprint("  CLOUD BOUNDARY SCANNER (KALI)  //  RESULTS SUMMARY",
           Colors.BOLD + Colors.CYAN)
    cprint("=" * 70, Colors.BOLD)

    # Domain context
    if report.get("cloud_domain"):
        cprint(f"  Cloud Tenant:    {report['cloud_domain']}", Colors.WHITE)
    cprint(f"  On-prem Domain:  {report['onprem_domain']}", Colors.WHITE)

    # Surface discovered boundary servers from findings
    boundary_servers = []
    for f in report["findings"]:
        if f["category"] in ("sync_services", "federation", "cloud_bridge"):
            # Extract server name from detail text
            m = re.search(r"Entra Connect server:\s*(\S+)", f["detail"])
            if m:
                boundary_servers.append(
                    (m.group(1).rstrip("."), f["title"]))
            elif "ADFS server:" in f["title"]:
                m_host = re.search(r"ADFS server:\s*(\S+)", f["title"])
                if m_host:
                    boundary_servers.append(
                        (m_host.group(1).rstrip("."), f["title"]))
            elif f["category"] == "cloud_bridge":
                boundary_servers.append(
                    (f.get("host", "unknown"), f["title"]))
    if boundary_servers:
        print()
        cprint("  Boundary Servers Identified:",
               Colors.BOLD + Colors.MAGENTA)
        seen = set()
        for server, role in boundary_servers:
            if server not in seen:
                seen.add(server)
                ip_hint = ""
                try:
                    ip_hint = f" ({socket.gethostbyname(server)})"
                except (socket.gaierror, socket.herror):
                    ip_hint = " (IP unresolved)"
                cprint(f"    {server}{ip_hint}  —  {role}", Colors.MAGENTA)
    else:
        print()
        cprint("  Boundary Servers:  none identified on this scan",
               Colors.GRAY)

    cprint(f"  Hosts scanned: {len(report['hosts_scanned'])}",
           Colors.WHITE)
    print()

    total = report["total_findings"]
    keys = report["severity_counts"]["KEY"]
    notables = report["severity_counts"]["NOTABLE"]
    relevants = report["severity_counts"]["RELEVANT"]

    cprint(f"  Total findings: {total}", Colors.BOLD)
    if keys:
        cprint(f"    KEY      : {keys}", Colors.RED + Colors.BOLD)
    if notables:
        cprint(f"    NOTABLE  : {notables}", Colors.ORANGE)
    if relevants:
        cprint(f"    RELEVANT : {relevants}", Colors.YELLOW)
    if report["severity_counts"]["LOW"]:
        cprint(f"    LOW      : {report['severity_counts']['LOW']}",
               Colors.CYAN)
    if report["severity_counts"]["INFO"]:
        cprint(f"    INFO     : {report['severity_counts']['INFO']}",
               Colors.GRAY)

    # Boundary analysis conclusion
    sync_method = ""
    sso_method = ""
    boundary_host = ""
    attack_paths = []
    for f in report["findings"]:
        if "MSOL" in f.get("title", ""):
            sync_method = "Entra Connect"
            m_srv = re.search(r"Entra Connect server:\s*(\S+)", f["detail"])
            if m_srv:
                boundary_host = m_srv.group(1).rstrip(".")
        if "AZUREADSSOACC" in f.get("title", ""):
            sso_method = "Seamless SSO"
        if "ADFS" in f.get("title", "") and "server" in f.get("title", "").lower():
            if not sync_method:
                sync_method = "ADFS federation"
            sso_method = "ADFS"
    if sync_method:
        print()
        domain = report.get("onprem_domain", "")
        tenant = report.get("cloud_domain", "")
        line = f"  {domain} syncs to Entra ID via {sync_method}"
        if boundary_host:
            line += f" on {boundary_host}"
        if sso_method:
            line += f", {sso_method} enabled"
        cprint(line, Colors.WHITE)
        if sync_method == "Entra Connect":
            attack_paths.append("DCSync for MSOL_ account credentials")
        if sso_method == "Seamless SSO":
            attack_paths.append("DCSync for AZUREADSSOACC$ Kerberos key")
        if boundary_host:
            attack_paths.append(f"Local admin on {boundary_host}")
        if attack_paths:
            cprint("  Attack paths:", Colors.BOLD + Colors.YELLOW)
            for ap in attack_paths:
                cprint(f"    > {ap}", Colors.YELLOW)

    cprint("=" * 70, Colors.BOLD)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG_MODE

    banner = f"""
{Colors.BOLD}{Colors.CYAN}    +----------------------------------------------+
    |   Cloud Boundary Scanner  //  Kali Edition   |
    |   For authorized penetration testing only    |
    +----------------------------------------------+{Colors.RESET}
    """
    print(Colors.strip_if_no_tty(banner))

    parser = argparse.ArgumentParser(
        description="Kali-native cloud boundary scanner for authorized "
                    "pentests.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u 'CORP\\jsmith' -p 'P@ss1' -dc 10.0.0.1
  %(prog)s -u 'jsmith@corp.local' -p 'P@ss1' -dc 10.0.0.1 -t 10.0.0.0/24
  %(prog)s -u 'CORP\\jsmith' -H 'lm:nt' -dc 10.0.0.1 -t 10.0.0.50
        """)
    parser.add_argument("-u", "--username", required=True,
                        help="Username (DOMAIN\\user or user@domain)")
    parser.add_argument("-p", "--password", default="",
                        help="Password")
    parser.add_argument("-H", "--hashes", default="",
                        help="NTLM hash (LM:NT or just NT)")
    parser.add_argument("-d", "--domain", default="",
                        help="Domain (if not embedded in username)")
    parser.add_argument("-dc", "--dc-ip", required=True,
                        help="Domain controller IP for LDAP queries")
    parser.add_argument("-t", "--target", default="",
                        help="Target IP or CIDR subnet (default: DC only)")
    parser.add_argument("-o", "--output", default=None,
                        help="Write JSON report to file")
    parser.add_argument("--silent", action="store_true",
                        help="Reduce output (suppress debug/negative results)")
    parser.add_argument("--debug", action="store_true",
                        help="(Default behavior) Verbose output. Kept for "
                             "backward compatibility.")
    parser.add_argument("--threads", type=int, default=10,
                        help="Max threads for host scanning (default: 10)")
    parser.add_argument("--skip-shares", action="store_true",
                        help="Skip share credential scanning (faster)")
    parser.add_argument("--max-share-files", type=int, default=500,
                        help="Max files to scan per share (default: 500)")
    args = parser.parse_args()

    # Verbose is now the default; --silent suppresses debug output
    DEBUG_MODE = not args.silent

    # Validate dependencies
    missing = []
    if not HAS_IMPACKET:
        missing.append("impacket")
    if not HAS_LDAP3:
        missing.append("ldap3")
    if not HAS_DNS:
        missing.append("dnspython")
    if missing:
        cprint(f"  [!] Missing: {', '.join(missing)}", Colors.RED)
        cprint(f"  [!] Install: pip3 install {' '.join(missing)}",
               Colors.RED)
        sys.exit(1)

    creds = Credentials.from_args(args)
    results = ScanResults(onprem_domain=creds.domain)

    cprint(f"  Auth: {creds.domain}\\{creds.username}", Colors.WHITE)
    cprint(f"  DC:   {args.dc_ip}", Colors.WHITE)
    print()

    # Phase 1: LDAP
    cprint("  [Phase 1] LDAP enumeration against domain controller",
           Colors.BOLD + Colors.MAGENTA)
    conn = ldap_connect(args.dc_ip, creds)
    if conn:
        enumerate_ad_cloud_objects(conn, results, args.dc_ip)
        conn.unbind()
    else:
        results.add(Finding(
            "scanner_error", "LDAP bind failed",
            f"Could not bind to {args.dc_ip}. AD enumeration skipped.",
            severity="NOTABLE", host=args.dc_ip))

    # Phase 2: DNS
    print()
    cprint("  [Phase 2] DNS and federation endpoint discovery",
           Colors.BOLD + Colors.MAGENTA)
    check_cloud_dns(results)
    check_cloud_dns_integration(results, creds.domain)
    check_adfs_metadata(args.dc_ip, creds, results)

    # Phase 3: Remote hosts
    if args.target:
        targets = discover_live_hosts(args.target)
    else:
        targets = [args.dc_ip]

    ldap_discovered = [f.host for f in results.findings
                       if f.host and f.host != args.dc_ip]
    for hostname in ldap_discovered:
        try:
            ip = socket.gethostbyname(hostname)
            if ip not in targets:
                targets.append(ip)
                cprint(f"  [+] Added LDAP-discovered host: "
                       f"{hostname} ({ip})", Colors.GREEN)
        except socket.gaierror:
            pass

    results.hosts_scanned = targets
    print()
    cprint(f"  [Phase 3] Remote host checks ({len(targets)} hosts)",
           Colors.BOLD + Colors.MAGENTA)

    for target_ip in targets:
        check_remote_services(target_ip, creds, results)
        check_remote_registry(target_ip, creds, results)
        check_adsync_remote(target_ip, creds, results)
        if not args.skip_shares:
            check_remote_shares(target_ip, creds, results,
                                max_files=args.max_share_files)

    print_summary(results)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(results.to_dict(), indent=2))
        cprint(f"  JSON report written to: {output_path}\n", Colors.GREEN)

    critical_count = sum(1 for f in results.findings
                         if f.severity == "KEY")
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
