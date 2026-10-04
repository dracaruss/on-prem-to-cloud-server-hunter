# Cloud Boundary Scanner

Enumerates the on-prem to cloud boundary during authorized penetration tests. Finds sync services, cached cloud credentials, federation misconfigurations, and pivot paths between Active Directory and cloud tenants (Azure/Entra ID, AWS, GCP).

Two versions are included: one for Windows-based engagements and one for Kali-based engagements.

## What It Checks

- **Entra Connect / AD Sync**: MSOL_ service account, ADSync database, sync services
- **Federation**: ADFS servers, token-signing certificates, Seamless SSO (AZUREADSSOACC$)
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
# Standard scan (shows only relevant findings)
python cloud_boundary_scanner_win64.py

The credential file scan: This is a cloud-scoped LaZagne style scanner, that scours the filesystem but only looks for cloud-specific secrets, like AWS access keys hardcoded in scripts, Azure SAS tokens in config files, GCP service account JSON keys, PEM private keys, and connection strings. The idea is that admins leave these in PowerShell scripts, .env files, config files on SYSVOL, scheduled task scripts, and similar places. Finding an AWS secret key in a .ps1 on NETLOGON is an instant pivot to cloud from on-prem, which is exactly the boundary crossing this tool is about.

# Save JSON report
python cloud_boundary_scanner_win64.py -o report.json

# Full debug output (shows negative results and all checks)
python cloud_boundary_scanner_win64.py --debug

# Combined
python cloud_boundary_scanner_win64.py -o report.json --debug
```

### Kali Version

Run from your Kali VM with domain credentials pointed at the target environment.

```bash
# Basic scan using the DC as the only target
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1

# Scan a subnet for cloud boundary hosts
python3 cloud_boundary_scanner_kali.py -u 'jsmith@corp.local' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.0/24

# Pass-the-hash authentication
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -H 'aad3b435b51404eeaad3b435b51404ee:ntlmhash' -dc 10.0.0.1

# Scan a specific host with debug output
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.50 --debug

# Fast scan skipping share enumeration
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.0/24 --skip-shares

# Full engagement scan with JSON output
python3 cloud_boundary_scanner_kali.py -u 'CORP\jsmith' -p 'Password1' -dc 10.0.0.1 -t 10.0.0.0/24 -o report.json
```

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
| `--debug` | Show all output including negative/empty results |
| `--skip-shares` | Skip SMB share credential scanning |
| `--max-share-files` | Max files to scan per share (default: 500) |
| `--threads` | Max threads for host discovery (default: 10) |

## Output

By default, both scripts show only actionable findings (CRITICAL, HIGH, MEDIUM) with color-coded severity as they are discovered. The final summary lists all findings by severity with detail on CRITICAL and HIGH items.

Use `--debug` to see all checks including those that returned nothing, which is useful for confirming the scanner ran each module against the target.

The `-o` flag writes a full JSON report with every finding, timestamps, and evidence fields suitable for import into pentest reporting tools.

## Recommended Workflow

1. Run the **Kali version** first against the DC to enumerate sync accounts, federation servers, and delegation paths via LDAP.
2. Note which hosts are identified as Entra Connect or ADFS servers.
3. Run the **Kali version** again with `-t` pointed at those specific hosts for remote service, registry, share, and ADSync database checks.
4. If you land on one of those servers during the engagement, run the **Windows version** locally for deeper host-level checks (PRT extraction, local token caches, scheduled tasks).

## Disclaimer

These tools are designed for **authorized penetration testing only**. Only use them against environments where you have explicit written authorization. Unauthorized use is illegal.

## Author

Russell — Thrive Offensive Security
