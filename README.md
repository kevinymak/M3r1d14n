# Lab scripts

Scripts built from the *Blue Team Field Manual* (BTFM): Protect, Log Auditing,
Live Triage and Kill Malware Process. Each one runs on the local machine or on
remote targets.

| Script | Platform | Remote access |
|---|---|---|
| `btfm-windows.ps1` | Windows 10 / Server (PowerShell 5.1+) | WinRM (PowerShell Remoting) |
| `btfm-linux.sh` | Ubuntu, Debian, Rocky, Alma, openSUSE | SSH + sudo |

## Modes

| Mode | What it does | Changes the system? |
|---|---|---|
| Triage | Users, network, processes, services, autoruns, recent files, logs, plus a summary of red flags | No |
| Harden | Firewall on (keeps current services open), audit logging, BTFM registry/LSA settings | Yes (backs up first; use `-WhatIf` / `-n` to preview) |
| Block | Sinkhole domains in the hosts file, block IPs in the firewall | Yes |
| Kill | Copy + hash the binary, then stop the process | Yes |
| Password | Set a new password on listed users; white team / scoring accounts are protected | Yes |

## Targets

Windows: `-Target localhost` (default), `-Target dc01,10.0.5.20`, or `-Target .\hosts.txt`
Linux: `-t local` (default), `-t 10.0.5.30,user@web01`, or `-f hosts.txt`

Host files contain one target per line; `#` starts a comment.

## Quick start

```powershell
# Windows (elevated PowerShell)
Set-ExecutionPolicy -Scope Process Bypass
.\btfm-windows.ps1 -Mode Triage
.\btfm-windows.ps1 -Mode Harden -Target .\windows-hosts.txt -WhatIf
.\btfm-windows.ps1 -Mode Harden -Target .\windows-hosts.txt -Credential (Get-Credential)
.\btfm-windows.ps1 -Mode Block -BlockIP 203.0.113.7 -BlockDomain evil.example
.\btfm-windows.ps1 -Mode Kill -ProcessName nc
.\btfm-windows.ps1 -Mode Password -Target web01 -User blueteam1,blueteam2
Get-Help .\btfm-windows.ps1 -Full
```

```bash
# Linux
chmod +x btfm-linux.sh
sudo ./btfm-linux.sh -m triage
./btfm-linux.sh -m harden -f linux-hosts.txt -u blueteam1 -n      # dry run
./btfm-linux.sh -m harden -t web01 --allow-ports 22,80,443
./btfm-linux.sh -m block -t web01 --ip 203.0.113.7 --domain evil.example
./btfm-linux.sh -m kill -t web01 --name nc --quarantine
./btfm-linux.sh -m password -t web01,db01 --user blueteam1,blueteam2
./btfm-linux.sh -h
```

Results are saved under `btfm-output/<host>_<mode>_<timestamp>/`.

## Safety notes

- Always run Harden with `-WhatIf` (Windows) or `-n` (Linux) first.
- Firewall hardening keeps every port that is listening at that moment and always keeps SSH open.
  On Linux, if no listeners can be detected, the firewall is left alone; pass `--allow-ports` instead.
- RDP, admin shares and IPv6 stay on unless you pass `-DisableRDP`, `-DisableAdminShares`
  or `-DisableIPv6`. Remote consoles (e.g. Guacamole) often depend on RDP.
- Backups and rollback commands are written to `C:\btfm\backup-*` / `/root/btfm-backup-*`.
