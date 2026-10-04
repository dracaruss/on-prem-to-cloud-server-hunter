# Cloud Boundary Scanner

Enumerates the on-prem to cloud boundary during authorized penetration tests. Finds sync services, cached cloud credentials, federation misconfigurations, cloud bridge agents, and pivot paths between Active Directory and cloud tenants (Azure/Entra ID, AWS, GCP).

Two versions are included: one for Windows-based engagements and one for Kali-based engagements.

## What It Checks

- **Entra Connect / AD Sync**: MSOL_ service account, ADSync database, sync services, Entra Cloud Sync provisioning agents
- **Federation**: ADFS servers, token-signing certificates, Seamless SSO (AZUREADSSOACC$)
- **Cloud Bridge Agents**: Azure Arc (himds, GCArcService, ExtensionService), Entra Application Proxy Connector, WAP Service, Pass-through Authentication agent
- **DNS Integration**: Enterprise registration, enterprise enrollment, msoid, autodiscover, and lyncdiscover records indicating Entra/M365 integration
- **Cached Credentials**: Azure CLI tokens, AWS profiles, cloud keys in env vars, scripts on SYSVOL/NETLOGON and other shares
- **Cloud Agents**: Registry keys and services for Entra, Intune, AWS SSM, GCP Ops Agent
- **Device Identity**: Azure AD join status, Primary Refresh Tokens (PRTs)
- **Delegation Abuse**: Unconstrained and resource-based constrained delegation on cloud boundary servers
- **Network**: DNS resolution and active connections to cloud endpoints

## Installation

```bash
# Kali version dependencies (most are pre-installed on Kali)
pip3 install impacket ldap3 dnspython

# Windows version has no external dependencies (uses built-in PowerShell and OS tools)
```

## Usage

### Windows Version

Run directly on a domain-joined Windows host. Uses the current user's session for authentication.

```bash
# Standard scan (verbose output is the default, shows all checks with color-coded results)
python cloud_boundary_scanner_win64.py

# Save JSON report
python cloud_boundary_scanner_win64.py -o report.json

# Query a remote DC to find sync objects in another domain (useful when sync infra lives in a different domain)
python cloud_boundary_scanner_win64.py -dc 10.0.0.2

# Combine remote DC targeting with JSON output
python cloud_boundary_scanner_win64.py -dc 10.0.0.2 -o report.json

# Reduced output (suppress debug/negative results)
python cloud_boundary_scanner_win64.py --silent
```

### Kali Version

Run from your Kali VM with domain credentials pointed at the target environment.

```bash
# Basic scan using the DC as the only target (verbose by default)
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1

# Scan a subnet for cloud boundary hosts
python3 cloud_boundary_scanner_kali.py -u 'jsmith@corp.local' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.0/24

# Pass-the-hash authentication
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -H 'aad3b435b51404eeaad3b435b51404ee:ntlmhash' -dc 10.0.0.1

# Reduced output
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1 --silent

# Fast scan skipping share enumeration
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.0/24 --skip-shares

# Full engagement scan with JSON output
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.0/24 -o report.json
```

### Windows Arguments

| Argument | Description |
|----------|-------------|
| `-dc` | Remote domain controller IP to query (for cross-domain sync enumeration) |
| `-o` | Output JSON report path |
| `--silent` | Reduce output (suppress debug/negative results) |
| `--debug` | No-op, kept for backward compatibility (verbose is now the default) |

### Kali Arguments

| Argument | Description |
|----------|-------------|
| `-u` | Username (`DOMAIN\user` or `user@domain`) |
| `-p` | Password |
| `-H` | NTLM hash (`LM:NT` or just `NT`) |
| `-d` | Domain (if not embedded in username) |
| `-dc` | Domain controller IP (required) |
| `-t` | Target IP or CIDR subnet |
| `-o` | Output JSON report path |
| `--silent` | Reduce output (suppress debug/negative results) |
| `--debug` | No-op, kept for backward compatibility (verbose is now the default) |
| `--skip-shares` | Skip SMB share credential scanning |
| `--max-share-files` | Max files to scan per share (default: 500) |
| `--threads` | Max threads for host discovery (default: 10) |

## Output

Both scripts default to verbose output with color-coded severity for every check as it runs. The final summary lists all findings by severity with detail on CRITICAL and HIGH items, the identified boundary servers, and the detected on-prem and cloud domains.

When the Windows version is run with `-dc`, the summary also shows the remote DC being queried and which domain it belongs to.

Use `--silent` to suppress negative results and debug output, showing only actionable findings.

The `-o` flag writes a full JSON report with every finding, timestamps, and evidence fields suitable for import into pentest reporting tools.

## Recommended Workflow

1. Run the **Kali version** first against the DC to enumerate sync accounts, federation servers, cloud bridge agents, and delegation paths via LDAP.
2. Note which hosts are identified as Entra Connect, ADFS, Azure Arc, or Application Proxy servers.
3. Run the **Kali version** again with `-t` pointed at those specific hosts for remote service, registry, share, and ADSync database checks.
4. If you land on one of those servers during the engagement, run the **Windows version** locally for deeper host-level checks (PRT extraction, local token caches, scheduled tasks).
5. If the scanner finds nothing but you know cloud exists, the sync infrastructure may live in a different AD domain. Run the **Windows version** with `-dc <other_DC_IP>` to query that domain for MSOL_ accounts, SCP objects, and bridge agents.

## Disclaimer

These tools are designed for **authorized penetration testing only**. Only use them against environments where you have explicit written authorization. Unauthorized use is illegal.

## Author

Russell — Thrive Offensive Security
