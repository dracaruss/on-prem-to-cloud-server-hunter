#!/usr/bin/env python3
"""
Cloud Boundary Scanner (Windows)
================================
Enumerates on-prem to cloud connectivity during authorized penetration tests.
Discovers sync services, cached credentials, cloud endpoints, and
misconfigurations at the hybrid identity boundary.

Usage:
    python cloud_boundary_scanner_win64.py [--output report.json] [--debug]

Requirements:
    - Run from a domain-joined Windows host (ideally with local admin)
    - Python 3.8+

Author: Russell (Thrive Offensive Security)
License: For authorized testing only.
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

DEBUG_MODE = False


def debug(msg: str):
    """Print a debug message only when --debug is active."""
    if DEBUG_MODE:
        cprint(f"  [DBG] {msg}", Colors.GRAY)


def status(msg: str):
    """Print a phase/module status line (always shown)."""
    cprint(f"  [*] {msg}", Colors.CYAN)


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

CREDENTIAL_PATTERNS = [
    (r"(?i)AZURE[_\-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_\-]?(?:ID|SECRET)", "Azure credential variable"),
    (r"(?i)AZURE[_\-]?(?:STORAGE|ACCOUNT)[_\-]?KEY", "Azure storage key"),
    (r"(?i)SharedAccessSignature=", "Azure SAS token"),
    (r"(?i)DefaultEndpointsProtocol=https;AccountName=", "Azure connection string"),
    (r"(?i)\.microsoftonline\.com", "Microsoft Online endpoint reference"),
    (r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "AWS access key ID"),
    (r"(?i)aws_secret_access_key\s*=", "AWS secret key assignment"),
    (r"(?i)aws_session_token\s*=", "AWS session token"),
    (r'"type"\s*:\s*"service_account"', "GCP service account JSON key"),
    (r"(?i)GOOGLE_APPLICATION_CREDENTIALS", "GCP application credentials env var"),
    (r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)\s*[:=]", "Generic API key or token"),
    (r"(?i)-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private key (PEM)"),
]

SYNC_SERVICES = [
    ("Microsoft Azure AD Sync", "Entra Connect Sync (legacy name)"),
    ("Microsoft Entra Connect Sync", "Entra Connect Sync"),
    ("ADSync", "AD Sync engine service"),
    ("AzureADConnectHealthSyncInsights", "Entra Connect Health monitoring"),
    ("AADConnectProvisioningAgent", "Entra Cloud Sync provisioning agent"),
    ("adfssrv", "Active Directory Federation Services"),
    ("AzureADConnectAgentUpdater", "Entra Connect agent auto-updater"),
]

CONFIG_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs",
    ".py", ".rb", ".config", ".xml", ".json", ".yaml",
    ".yml", ".env", ".ini", ".conf", ".tf", ".tfvars",
    ".properties",
}

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

    def add(self, finding: Finding):
        self.findings.append(finding)
        color = Colors.severity_color(finding.severity)
        # In normal mode, only print CRITICAL/HIGH/MEDIUM inline as they happen
        if finding.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            cprint(f"  [+] [{finding.severity}] {finding.title}", color)
        elif DEBUG_MODE:
            cprint(f"  [.] [{finding.severity}] {finding.title}", color)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_start": self.scan_start,
            "scan_end": datetime.utcnow().isoformat(),
            "hostname": self.hostname,
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

    # MSOL_ account
    msol_check = run_powershell(
        "Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} "
        "| Select-Object SamAccountName, Enabled | ConvertTo-Json")
    if msol_check and "MSOL_" in msol_check:
        results.add(Finding(
            "sync_services", "MSOL sync service account found in AD",
            "The MSOL_ account is the Entra Connect directory sync account. "
            "It holds DCSync-equivalent privileges on-prem and write access "
            "in the Entra tenant.",
            severity="CRITICAL", evidence=msol_check[:500],
        ))
    else:
        debug("No MSOL_ service account found in AD.")

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
    cloud_env_patterns = [
        (r"AZURE", "Azure"), (r"AWS", "AWS"),
        (r"GOOGLE_CLOUD|GCLOUD|GCP", "GCP"),
        (r"TENANT.ID", "Tenant ID"), (r"CLIENT.SECRET", "Client secret"),
        (r"(?:API|ACCESS|SECRET)[_\-]?KEY", "API/access key"),
    ]
    found = False
    for var_name, var_value in os.environ.items():
        for pattern, label in cloud_env_patterns:
            if re.search(pattern, var_name, re.IGNORECASE):
                found = True
                masked = var_value[:4] + "****" if len(var_value) > 4 else "****"
                results.add(Finding(
                    "credentials",
                    f"Cloud env var: {var_name}",
                    f"Environment variable {var_name} matches pattern for "
                    f"{label}. Accessible to any process as this user.",
                    severity="HIGH", evidence=f"{var_name}={masked}",
                ))
                break
    if not found:
        debug("No cloud-related environment variables found.")


def check_credential_files(results: ScanResults):
    status("Scanning filesystem for cloud credentials...")
    scanned = 0
    hits = 0
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
                if filepath.stat().st_size > max_file_size:
                    continue
                scanned += 1
                try:
                    content = filepath.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue
                for pattern, label in CREDENTIAL_PATTERNS:
                    if re.search(pattern, content):
                        hits += 1
                        results.add(Finding(
                            "credentials",
                            f"Cloud credential in file: {filepath.name}",
                            f"File {filepath} matches pattern \"{label}\". "
                            f"Review for embedded secrets enabling cloud pivot.",
                            severity="HIGH",
                            evidence=f"Pattern: {label}, File: {filepath}",
                        ))
                        break
        except PermissionError:
            pass

    debug(f"File scan complete: {scanned} files scanned, {hits} hits.")


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

    sso_check = run_powershell(
        "Get-ADComputer -Filter {SamAccountName -eq 'AZUREADSSOACC$'} "
        "| Select-Object SamAccountName, Enabled | ConvertTo-Json")
    if sso_check and "AZUREADSSOACC" in sso_check:
        results.add(Finding(
            "federation",
            "Seamless SSO account found (AZUREADSSOACC$)",
            "Seamless SSO is configured. Extracting this account's Kerberos "
            "key enables forging cloud auth tickets for any synced user.",
            severity="CRITICAL", evidence=sso_check[:300],
        ))
    else:
        debug("AZUREADSSOACC$ not found in AD.")

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
                        for pattern, label in CREDENTIAL_PATTERNS:
                            if re.search(pattern, content):
                                results.add(Finding(
                                    "credentials",
                                    f"Cloud credential in share: {fname}",
                                    f"File {fpath} on a domain share matches "
                                    f"\"{label}\". Readable by all domain users.",
                                    severity="CRITICAL",
                                    evidence=f"File: {fpath}, Pattern: {label}",
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
    cprint(f"  Host:      {report['hostname']}", Colors.WHITE)
    cprint(f"  Started:   {report['scan_start']}", Colors.WHITE)
    cprint(f"  Completed: {report['scan_end']}", Colors.WHITE)
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

    # Detail for CRITICAL and HIGH
    for finding in results.findings:
        if finding.severity in ("CRITICAL", "HIGH"):
            color = Colors.severity_color(finding.severity)
            print()
            cprint(f"  [{finding.severity}] {finding.title}", color)
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

    parser = argparse.ArgumentParser(
        description="Cloud Boundary Scanner (Windows) for authorized pentests.")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Write JSON report to file.")
    parser.add_argument("--debug", action="store_true",
                        help="Show all debug output including negative results.")
    args = parser.parse_args()

    DEBUG_MODE = args.debug

    cprint("\n  Cloud Boundary Scanner (Windows)", Colors.BOLD + Colors.CYAN)
    cprint("  For authorized penetration testing only.\n", Colors.DIM)

    results = ScanResults()

    modules = [
        check_sync_services, check_adfs, check_cloud_dns,
        check_outbound_connections, check_environment_variables,
        check_credential_files, check_aws_profiles, check_azure_cli,
        check_scheduled_tasks, check_registry_cloud_agents,
        check_conditional_access_indicators,
        check_network_shares_for_cloud_scripts,
    ]

    for module in modules:
        try:
            module(results)
        except Exception as exc:
            cprint(f"  [!] Module {module.__name__} failed: {exc}",
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
