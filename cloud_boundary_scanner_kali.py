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
    msg = f"{color}{text}{Colors.RESET}" if color else text
    print(Colors.strip_if_no_tty(msg), end=end)


DEBUG_MODE = False


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
        "management.azure.com", "aadconnecthealth.azure.com",
        "adminwebservice.microsoftonline.com",
        "provisioningapi.microsoftonline.com",
        "autologon.microsoftazuread-sso.com",
    ],
    "aws": ["sts.amazonaws.com", "signin.aws.amazon.com"],
    "gcp": ["accounts.google.com", "oauth2.googleapis.com"],
}

SYNC_SERVICE_NAMES = [
    "ADSync", "AzureADConnectHealthSyncInsights",
    "AADConnectProvisioningAgent", "AzureADConnectAgentUpdater", "adfssrv",
]

CREDENTIAL_PATTERNS = [
    (r"(?i)AZURE[_\-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_\-]?(?:ID|SECRET)", "Azure credential variable"),
    (r"(?i)AZURE[_\-]?(?:STORAGE|ACCOUNT)[_\-]?KEY", "Azure storage key"),
    (r"(?i)SharedAccessSignature=", "Azure SAS token"),
    (r"(?i)DefaultEndpointsProtocol=https;AccountName=", "Azure connection string"),
    (r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "AWS access key ID"),
    (r"(?i)aws_secret_access_key\s*=", "AWS secret key assignment"),
    (r'"type"\s*:\s*"service_account"', "GCP service account JSON key"),
    (r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)\s*[:=]", "Generic API key or token"),
    (r"(?i)-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private key (PEM)"),
    (r"(?i)Connect-AzAccount", "Azure PowerShell login"),
    (r"(?i)Connect-MsolService", "MSOnline PowerShell login"),
    (r"(?i)Connect-AzureAD", "AzureAD PowerShell login"),
    (r"(?i)Set-Msoluser", "MSOnline user modification"),
    (r"(?i)azcopy", "AzCopy cloud transfer tool"),
]

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
    def __init__(self):
        self.findings: list[Finding] = []
        self.scan_start = datetime.utcnow().isoformat()
        self.hosts_scanned: list[str] = []

    def add(self, finding: Finding):
        self.findings.append(finding)
        color = Colors.severity_color(finding.severity)
        host_tag = f" [{finding.host}]" if finding.host else ""
        if finding.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            cprint(f"  [+] [{finding.severity}]{host_tag} {finding.title}", color)
        elif DEBUG_MODE:
            cprint(f"  [.] [{finding.severity}]{host_tag} {finding.title}", color)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_start": self.scan_start,
            "scan_end": datetime.utcnow().isoformat(),
            "hosts_scanned": self.hosts_scanned,
            "total_findings": len(self.findings),
            "severity_counts": {
                s: sum(1 for f in self.findings if f.severity == s)
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
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

    # MSOL_ sync account
    status("Querying AD for MSOL_ sync account...")
    conn.search(base_dn, "(sAMAccountName=MSOL_*)", SUBTREE,
                attributes=["sAMAccountName", "description", "whenCreated",
                             "userAccountControl", "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            results.add(Finding(
                "sync_services",
                f"MSOL sync account: {entry.sAMAccountName}",
                "Entra Connect sync account with DCSync privileges on-prem "
                "and write access in the cloud tenant.",
                severity="CRITICAL", host=dc_ip,
                evidence=f"DN: {entry.distinguishedName}, Created: {entry.whenCreated}",
            ))
    else:
        debug("No MSOL_ sync account found.")

    # AZUREADSSOACC$ (Seamless SSO)
    status("Querying AD for AZUREADSSOACC$ (Seamless SSO)...")
    conn.search(base_dn, "(sAMAccountName=AZUREADSSOACC$)", SUBTREE,
                attributes=["sAMAccountName", "distinguishedName", "whenCreated",
                             "servicePrincipalName"])
    if conn.entries:
        for entry in conn.entries:
            results.add(Finding(
                "federation",
                "Seamless SSO account found (AZUREADSSOACC$)",
                "Extracting this account's Kerberos key enables forging "
                "cloud auth tickets for any synced user.",
                severity="CRITICAL", host=dc_ip,
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("AZUREADSSOACC$ not found.")

    # Entra Connect server
    status("Locating Entra Connect server...")
    conn.search(base_dn,
                "(&(objectClass=computer)(description=*Azure AD Connect*))",
                SUBTREE,
                attributes=["cn", "dNSHostName", "operatingSystem",
                             "description", "distinguishedName"])
    if not conn.entries:
        conn.search(base_dn, "(servicePrincipalName=*ADSync*)", SUBTREE,
                    attributes=["cn", "dNSHostName", "servicePrincipalName",
                                 "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            hostname = entry.dNSHostName if hasattr(entry, "dNSHostName") else entry.cn
            results.add(Finding(
                "sync_services",
                f"Entra Connect server: {hostname}",
                "Primary target for ADSync database credential extraction.",
                severity="CRITICAL", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No Entra Connect server found via LDAP.")

    # ADFS servers
    status("Locating ADFS servers...")
    conn.search(base_dn, "(servicePrincipalName=*adfs*)", SUBTREE,
                attributes=["cn", "dNSHostName", "servicePrincipalName",
                             "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            hostname = entry.dNSHostName if hasattr(entry, "dNSHostName") else entry.cn
            results.add(Finding(
                "federation", f"ADFS server: {hostname}",
                "Token-signing certificate enables Golden SAML if compromised.",
                severity="CRITICAL", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No ADFS servers found via SPN search.")

    # AAD Password Protection
    conn.search(base_dn, "(servicePrincipalName=*AzureADPasswordProtection*)",
                SUBTREE, attributes=["cn", "dNSHostName", "distinguishedName"])
    for entry in conn.entries:
        results.add(Finding(
            "cloud_agents",
            f"Azure AD Password Protection proxy: {entry.cn}",
            "Cloud policy enforcement on-prem. Proxy communicates with Entra.",
            severity="MEDIUM", host=str(entry.cn),
            evidence=f"DN: {entry.distinguishedName}",
        ))

    # Cloud-related SPNs
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
                                     "servicePrincipalName", "distinguishedName"])
            for entry in conn.entries:
                results.add(Finding(
                    "cloud_agents",
                    f"Cloud SPN on: {entry.sAMAccountName}",
                    "Account authenticates to cloud services via SPN.",
                    severity="MEDIUM", host=dc_ip,
                    evidence=f"SPN: {entry.servicePrincipalName}",
                ))
        except Exception:
            pass

    # Unconstrained delegation
    status("Checking for unconstrained delegation...")
    conn.search(base_dn,
                "(&(objectCategory=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                SUBTREE, attributes=["cn", "dNSHostName", "distinguishedName"])
    if conn.entries:
        for entry in conn.entries:
            hostname = entry.dNSHostName if hasattr(entry, "dNSHostName") else entry.cn
            results.add(Finding(
                "delegation", f"Unconstrained delegation: {hostname}",
                "TGTs cached for any authenticating user. High-value pivot "
                "if the sync server authenticates here.",
                severity="HIGH", host=str(hostname),
                evidence=f"DN: {entry.distinguishedName}",
            ))
    else:
        debug("No unconstrained delegation found.")

    # RBCD
    conn.search(base_dn, "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                SUBTREE,
                attributes=["cn", "dNSHostName", "distinguishedName",
                             "msDS-AllowedToActOnBehalfOfOtherIdentity"])
    for entry in conn.entries:
        hostname = entry.dNSHostName if hasattr(entry, "dNSHostName") else entry.cn
        results.add(Finding(
            "delegation", f"RBCD configured on: {hostname}",
            "Check if this is a sync/federation server with overly broad delegation.",
            severity="MEDIUM", host=str(hostname),
            evidence=f"DN: {entry.distinguishedName}",
        ))


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
                             3: "stopping", 4: "running"}.get(state, f"unknown({state})")
                severity = "CRITICAL" if svc_name in ("ADSync", "adfssrv") else "HIGH"
                results.add(Finding(
                    "sync_services",
                    f"Cloud service on {target}: {svc_name} ({state_str})",
                    f"Service is {state_str}. This is a Tier 0 cloud boundary server.",
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
                results.add(Finding(
                    "cloud_agents",
                    f"Cloud agent on {target}: {agent_name}",
                    f"Registry key for {agent_name} exists. May hold cached tokens.",
                    severity="MEDIUM" if "SSM" in agent_name or
                             "Intune" in agent_name else "HIGH",
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
    for share in shares:
        share_name = share["shi1_netname"][:-1]
        if share_name.upper() in ("IPC$", "PRINT$", "C$", "ADMIN$"):
            continue
        is_priority = share_name.upper() in [s.upper() for s in INTERESTING_SHARES]
        try:
            file_list = []
            _walk_share(smb, share_name, "", file_list, max_depth=3, max_files=max_files)
            for file_path, file_size in file_list:
                if files_scanned >= max_files:
                    break
                ext = os.path.splitext(file_path)[1].lower()
                if ext not in SHARE_SCAN_EXTENSIONS:
                    continue
                if file_size > 2 * 1024 * 1024:
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
                    for pattern, label in CREDENTIAL_PATTERNS:
                        if re.search(pattern, text):
                            sev = "CRITICAL" if is_priority else "HIGH"
                            results.add(Finding(
                                "credentials",
                                f"Cloud credential: \\\\{target}\\{share_name}\\{file_path}",
                                f"Pattern \"{label}\" found in a share-accessible file.",
                                severity=sev, host=target,
                                evidence=f"Share: {share_name}, File: {file_path}",
                            ))
                            break
                except Exception:
                    pass
        except Exception as exc:
            debug(f"Cannot access share {share_name} on {target}: {exc}")

    debug(f"Share scan on {target}: {files_scanned} files checked.")
    try:
        smb.logoff()
    except Exception:
        pass


def _walk_share(smb, share, path, results_list, max_depth=3, max_files=500, depth=0):
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
                f"{provider.upper()} endpoints resolvable ({len(reachable)}/{len(domains)})",
                f"Cloud connectivity to {provider.upper()} confirmed from test network.",
                severity="INFO", evidence="\n".join(reachable[:6]),
            ))


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
                results.add(Finding(
                    "federation", f"ADFS endpoint: {hostname} ({ip})",
                    f"Port 443 open. Check https://{hostname}/adfs/ls/ and "
                    f"the FederationMetadata.xml endpoint.",
                    severity="HIGH", host=ip,
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
        ("C$", "Program Files\\Microsoft Azure AD Sync\\Data\\ADSync_log.ldf"),
        ("C$", "ProgramData\\AADConnect\\PersistedState.xml"),
    ]
    for share, path in adsync_paths:
        try:
            smb.connectTree(share)
            smb.listPath(share, path)
            results.add(Finding(
                "sync_services", f"ADSync DB accessible: {path}",
                f"Extractable with local admin and AADInternals at "
                f"\\\\{target}\\{share}\\{path}.",
                severity="CRITICAL", host=target,
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
    cprint(f"  Started:       {report['scan_start']}", Colors.WHITE)
    cprint(f"  Completed:     {report['scan_end']}", Colors.WHITE)
    cprint(f"  Hosts scanned: {len(report['hosts_scanned'])}", Colors.WHITE)
    print()

    total = report["total_findings"]
    cprint(f"  Total findings: {total}", Colors.BOLD)
    for sev, color in [("CRITICAL", Colors.RED + Colors.BOLD),
                        ("HIGH", Colors.RED), ("MEDIUM", Colors.YELLOW),
                        ("LOW", Colors.CYAN), ("INFO", Colors.GRAY)]:
        count = report["severity_counts"][sev]
        if count:
            cprint(f"    {sev:10s}: {count}", color)

    cprint("=" * 70, Colors.BOLD)

    for finding in results.findings:
        if finding.severity in ("CRITICAL", "HIGH"):
            color = Colors.severity_color(finding.severity)
            host_tag = f" [{finding.host}]" if finding.host else ""
            print()
            cprint(f"  [{finding.severity}]{host_tag} {finding.title}", color)
            cprint(f"    {finding.detail}", Colors.WHITE)
            if finding.evidence:
                cprint(f"    Evidence: {finding.evidence[:200]}", Colors.DIM)

    print()
    cprint("=" * 70, Colors.BOLD)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG_MODE

    banner = f"""
{Colors.BOLD}{Colors.CYAN}    ┌──────────────────────────────────────────────┐
    │   Cloud Boundary Scanner  //  Kali Edition   │
    │   For authorized penetration testing only    │
    └──────────────────────────────────────────────┘{Colors.RESET}
    """
    print(Colors.strip_if_no_tty(banner))

    parser = argparse.ArgumentParser(
        description="Kali-native cloud boundary scanner for authorized pentests.",
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
    parser.add_argument("--debug", action="store_true",
                        help="Show all debug output including negative results")
    parser.add_argument("--threads", type=int, default=10,
                        help="Max threads for host scanning (default: 10)")
    parser.add_argument("--skip-shares", action="store_true",
                        help="Skip share credential scanning (faster)")
    parser.add_argument("--max-share-files", type=int, default=500,
                        help="Max files to scan per share (default: 500)")
    args = parser.parse_args()

    DEBUG_MODE = args.debug

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
        cprint(f"  [!] Install: pip3 install {' '.join(missing)}", Colors.RED)
        sys.exit(1)

    creds = Credentials.from_args(args)
    results = ScanResults()

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
            severity="HIGH", host=args.dc_ip))

    # Phase 2: DNS
    print()
    cprint("  [Phase 2] DNS and federation endpoint discovery",
           Colors.BOLD + Colors.MAGENTA)
    check_cloud_dns(results)
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
                cprint(f"  [+] Added LDAP-discovered host: {hostname} ({ip})",
                       Colors.GREEN)
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
                         if f.severity == "CRITICAL")
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
