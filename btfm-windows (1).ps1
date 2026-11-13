<#
.SYNOPSIS
    Blue Team Field Manual (BTFM) toolkit for Windows: triage, harden, block,
    kill and password changes, run on the local machine or on remote targets.

.DESCRIPTION
    Commands come from the BTFM sections Protect (Windows), Log Auditing,
    Live Triage - Windows and Kill Malware Process. Lines marked [extra] are
    common competition additions that are not in the book.

    Remote targets are reached over WinRM (PowerShell Remoting). Run from an
    elevated PowerShell. Works with Windows PowerShell 5.1 and PowerShell 7.

    MODES
      Triage    Read-only. Collects system, user, network, service, autorun,
                policy, share and log information into an output folder.
      Harden    Changes settings. Backs up firewall and registry first.
                Use -WhatIf to preview without changing anything.
      Block     Sinkholes domains in the hosts file and blocks IPs in the
                firewall.
      Kill      Copies, hashes and quarantines a process's executable, then
                stops it.
      Password  Sets a new password for the listed users (prompts once).

.PARAMETER Target
    One or more hostnames or IPs, or the path of a .txt file with one target
    per line (# comments allowed). Default: localhost.

.EXAMPLE
    .\btfm-windows.ps1 -Mode Triage
    Triage the local machine.

.EXAMPLE
    .\btfm-windows.ps1 -Mode Triage -Target dc01,10.0.5.20 -Credential (Get-Credential)
    Triage two remote machines over WinRM.

.EXAMPLE
    .\btfm-windows.ps1 -Mode Harden -Target .\windows-hosts.txt -WhatIf
    Show what hardening would change on every host in the file, change nothing.

.EXAMPLE
    .\btfm-windows.ps1 -Mode Harden -Target dc01 -DisableService Spooler,RemoteRegistry

.EXAMPLE
    .\btfm-windows.ps1 -Mode Block -BlockDomain evil.example -BlockIP 203.0.113.7

.EXAMPLE
    .\btfm-windows.ps1 -Mode Kill -Target web01 -ProcessName nc,svch0st

.EXAMPLE
    .\btfm-windows.ps1 -Mode Password -Target web01,dc01 -User blueteam1,blueteam2
    Prompts once for the new password. Add -ADAccount to change domain accounts
    (run against the domain controller).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Triage', 'Harden', 'Block', 'Kill', 'Password')]
    [string]$Mode,

    [string[]]$Target = @('localhost'),

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputDir = (Join-Path -Path (Get-Location) -ChildPath 'btfm-output'),

    # Triage: how far back to look for recently changed executables/scripts.
    [int]$RecentDays = 7,

    # Harden: optional, off by default because they can break scored services.
    [switch]$DisableRDP,
    [switch]$DisableAdminShares,
    [switch]$DisableIPv6,
    [string[]]$DisableService,

    # Block
    [string[]]$BlockDomain,
    [string[]]$BlockIP,

    # Kill
    [int[]]$ProcessId,
    [string[]]$ProcessName,

    # Password
    [string[]]$User,
    [switch]$ADAccount,
    [string[]]$ProtectedUser = @('whiteteam*', '*score*', '*scoring*', 'krbtgt')
)

$ErrorActionPreference = 'Stop'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ---------------------------------------------------------------- targets
function Resolve-Targets {
    param([string[]]$InputTargets)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($t in $InputTargets) {
        if ($t -and (Test-Path -LiteralPath $t -PathType Leaf)) {
            Get-Content -LiteralPath $t | ForEach-Object {
                $line = ($_ -replace '#.*$', '').Trim()
                if ($line) { $list.Add($line) }
            }
        }
        elseif ($t) { $list.Add($t.Trim()) }
    }
    return $list | Select-Object -Unique
}

function Test-IsLocal {
    param([string]$Name)
    $local = @('localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME)
    return ($local -contains $Name) -or ($Name -ieq "$env:COMPUTERNAME.$env:USERDNSDOMAIN")
}

# ============================================================ TRIAGE (remote)
$TriageBlock = {
    param([int]$RecentDays)
    $ErrorActionPreference = 'Continue'
    $sections = [ordered]@{}

    function Run([string]$Title, [scriptblock]$Code) {
        $text = try { (& $Code 2>&1 | Out-String -Width 400) } catch { "ERROR: $_" }
        $sections[$Title] = $text
    }

    # --- SYSTEM INFORMATION
    Run '01_system' {
        "Collected: $(Get-Date -Format o)"
        hostname
        systeminfo
        Get-CimInstance Win32_ComputerSystem | Format-List Name, Domain, Manufacturer, Model, UserName
        Get-CimInstance Win32_BIOS | Format-List SerialNumber, Version
    }

    # --- USER INFORMATION
    Run '02_users' {
        'whoami:'; whoami /all
        '--- net user'; net user
        '--- local Administrators'; net localgroup administrators
        '--- local users (Get-LocalUser)'
        try { Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, Description -AutoSize } catch { $_ }
        '--- domain admin groups (DC / domain members only)'
        net group 'Domain Admins' /domain 2>&1
        net group 'Enterprise Admins' /domain 2>&1
        '--- logged-on sessions'; query user 2>&1
        '--- netlogin (lastlogon, bad passwords)'
        Get-CimInstance Win32_NetworkLoginProfile | Format-Table Name, LastLogon, BadPasswordCount -AutoSize
    }

    # --- NETWORK INFORMATION
    Run '03_network' {
        '--- listening TCP + owning process'
        Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            '{0,-40} {1,6}  pid {2,-6} {3}' -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess, $p.Path
        }
        '--- established TCP + owning process'
        Get-NetTCPConnection -State Established | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            '{0}:{1} -> {2}:{3}  pid {4} {5}' -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.OwningProcess, $p.ProcessName
        }
        '--- UDP endpoints'
        Get-NetUDPEndpoint | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
        '--- netstat -nao'; netstat -nao
        '--- ipconfig /all'; ipconfig /all
        '--- route print'; route print
        '--- arp -a'; arp -a
        '--- DNS cache'; ipconfig /displaydns
        '--- WinHTTP proxy'; netsh winhttp show proxy
        '--- hosts file'; Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"
        '--- mapped drives (net use)'; net use
    }

    # --- SERVICE / PROCESS INFORMATION
    Run '04_services_processes' {
        '--- processes (path, parent, command line)'
        Get-CimInstance Win32_Process | Sort-Object ProcessId |
            Format-Table ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine -AutoSize -Wrap
        '--- tasklist /svc'; tasklist /svc
        '--- services (non-Microsoft paths first)'
        Get-CimInstance Win32_Service |
            Sort-Object @{e = { $_.PathName -match 'Windows\\System32|Microsoft' } }, Name |
            Format-Table Name, State, StartMode, StartName, PathName -AutoSize -Wrap
    }

    Run '05_scheduled_tasks' {
        '--- non-Microsoft scheduled tasks'
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
            $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
            '{0}{1}  [{2}]  RunAs={3}  -> {4}' -f $_.TaskPath, $_.TaskName, $_.State, $_.Principal.UserId, $a
        }
        '--- schtasks /query (all)'; schtasks /query /fo LIST
    }

    # --- POLICY, PATCH AND SETTINGS
    Run '06_policy_patches' {
        '--- gpresult /r'; gpresult /r 2>&1
        '--- hotfixes'; Get-HotFix | Sort-Object InstalledOn | Format-Table HotFixID, Description, InstalledOn -AutoSize
        '--- audit policy'; auditpol /get /category:*
        '--- firewall profiles'; netsh advfirewall show allprofiles
        '--- enabled inbound allow rules'
        Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
            Format-Table DisplayName, Profile, Program -AutoSize
        '--- Defender status'
        try { Get-MpComputerStatus | Format-List AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated } catch { 'Defender not available' }
        '--- environment'; Get-ChildItem Env: | Format-Table -AutoSize
    }

    # --- AUTORUN AND AUTOLOAD
    Run '07_autoruns' {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
        )
        foreach ($k in $runKeys) {
            if (Test-Path $k) {
                "--- $k"
                (Get-ItemProperty $k).PSObject.Properties |
                    Where-Object { $_.Name -notlike 'PS*' } |
                    ForEach-Object { '  {0} = {1}' -f $_.Name, $_.Value }
            }
        }
        '--- Winlogon (Shell / Userinit should be explorer.exe / userinit.exe)'
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
            Format-List Shell, Userinit, Taskman
        '--- AppInit_DLLs'
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' |
            Format-List AppInit_DLLs, LoadAppInit_DLLs
        '--- [extra] Image File Execution Options debuggers (sticky-keys style backdoors)'
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
            ForEach-Object {
                $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
                if ($d) { '  !! {0} -> Debugger = {1}' -f $_.PSChildName, $d }
            }
        '--- file associations (should be "%1" %*)'
        foreach ($c in 'exefile', 'batfile', 'cmdfile', 'comfile', 'htafile', 'piffile') {
            $p = "HKLM:\SOFTWARE\Classes\$c\shell\open\command"
            if (Test-Path $p) { '  {0}: {1}' -f $c, (Get-ItemProperty $p).'(default)' }
        }
        '--- startup folders'
        $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") +
            (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
        foreach ($f in $folders) {
            if (Test-Path $f) { Get-ChildItem $f -Force | ForEach-Object { '  ' + $_.FullName } }
        }
        '--- WMI startup'; Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location, User -AutoSize -Wrap
        '--- [extra] WMI event subscriptions (persistence)'
        Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Format-List *
        if (Get-Command autorunsc -ErrorAction SilentlyContinue) {
            '--- autorunsc -m (non-Microsoft)'; autorunsc -accepteula -nobanner -a * -m
        }
    }

    # --- FILES, DRIVES AND SHARES
    Run '08_files_shares' {
        '--- net share'; net share
        '--- net session'; net session 2>&1
        '--- volumes'; Get-CimInstance Win32_LogicalDisk | Format-Table DeviceID, FileSystem, Size, FreeSpace -AutoSize
        "--- exe/dll/ps1/bat/vbs/hta/js changed in the last $RecentDays days (users, temp, ProgramData, Windows\Temp)"
        $since = (Get-Date).AddDays(-$RecentDays)
        $roots = @('C:\Users', 'C:\ProgramData', "$env:SystemRoot\Temp", 'C:\inetpub', 'C:\PerfLogs') | Where-Object { Test-Path $_ }
        Get-ChildItem -Path $roots -Recurse -Force -File -ErrorAction SilentlyContinue `
            -Include *.exe, *.dll, *.ps1, *.bat, *.cmd, *.vbs, *.hta, *.js, *.jsp, *.aspx, *.php |
            Where-Object { $_.LastWriteTime -gt $since } |
            Sort-Object LastWriteTime -Descending |
            Format-Table LastWriteTime, Length, FullName -AutoSize -Wrap
        if (Get-Command sigcheck -ErrorAction SilentlyContinue) {
            '--- sigcheck: unsigned files in System32'; sigcheck -accepteula -nobanner -u -e "$env:SystemRoot\System32"
        }
    }

    # --- LOGS (key Security events from the last 24h)
    Run '09_security_events_24h' {
        $ids = 4624, 4625, 4648, 4672, 4720, 4722, 4724, 4728, 4732, 4738, 4740, 4756, 4697, 4698, 7045, 1102
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 500 -ErrorAction SilentlyContinue |
            Format-Table TimeCreated, Id, Message -AutoSize -Wrap
        '--- new services (System 7045)'
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue |
            Format-List TimeCreated, Message
    }

    # Export full event logs locally on the target (BTFM: wevtutil epl).
    $evtDir = Join-Path $env:SystemDrive 'btfm\evtx'
    New-Item -ItemType Directory -Path $evtDir -Force | Out-Null
    foreach ($log in 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational') {
        $file = Join-Path $evtDir (($log -replace '[/\\]', '_') + '.evtx')
        wevtutil epl $log $file /ow:true 2>$null | Out-Null
    }

    # Short summary of things worth a second look.
    $flags = New-Object System.Collections.Generic.List[string]
    try {
        $admins = Get-LocalGroupMember -Group Administrators | ForEach-Object { $_.Name }
        $flags.Add("Local Administrators: $($admins -join ', ')")
    } catch { }
    try {
        $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
        if ($g -and $g.Enabled) { $flags.Add('!! Guest account is ENABLED') }
    } catch { }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
        ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($d) { $flags.Add("!! IFEO debugger on $($_.PSChildName): $d") }
        }
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe,?$') { $flags.Add("!! Winlogon Shell = $($wl.Shell)") }
    if ($wl.Userinit -and $wl.Userinit -notmatch 'userinit\.exe,?$') { $flags.Add("!! Winlogon Userinit = $($wl.Userinit)") }
    $ports = (Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ', '
    $flags.Add("Listening TCP ports: $ports")
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } |
        ForEach-Object { $flags.Add("Non-Microsoft task: $($_.TaskPath)$($_.TaskName)") }
    $sections['00_SUMMARY'] = ($flags -join "`r`n")

    [pscustomobject]@{ Sections = $sections; EvtxDir = $evtDir }
}

# ============================================================ HARDEN (remote)
$HardenBlock = {
    param([bool]$DryRun, [bool]$DisableRDP, [bool]$DisableAdminShares, [bool]$DisableIPv6, [string[]]$DisableService)
    $ErrorActionPreference = 'Continue'
    $log = New-Object System.Collections.Generic.List[string]

    function Step([string]$Description, [scriptblock]$Action) {
        if ($DryRun) { $log.Add("WHATIF  $Description"); return }
        try { & $Action 2>&1 | Out-Null; $log.Add("OK      $Description") }
        catch { $log.Add("FAILED  $Description : $_") }
    }
    function SetReg([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
        Step "$Path\$Name = $Value" {
            if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        }
    }

    # Backups first so every change can be rolled back.
    $bk = Join-Path $env:SystemDrive ("btfm\backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Step "Back up firewall and registry to $bk" {
        New-Item -ItemType Directory -Path $bk -Force | Out-Null
        netsh advfirewall export "$bk\firewall.wfw" | Out-Null
        reg export 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' "$bk\lsa.reg" /y | Out-Null
        reg export 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' "$bk\terminal-server.reg" /y | Out-Null
        reg export 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' "$bk\lanmanserver.reg" /y | Out-Null
        auditpol /backup /file:"$bk\auditpol.csv" | Out-Null
    }

    # HOST SYSTEM FIREWALLS. Inbound is blocked except for existing allow rules,
    # so services that already have rules keep working. (The book's
    # "blockinboundalways" would ignore allow rules and break scored services.)
    # Keep every service that is listening right now reachable, even if it has
    # no firewall rule yet (the firewall may currently be off). Ports >= 49152
    # are dynamic RPC and already covered by Windows' built-in rules.
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' -and $_.LocalPort -lt 49152 } |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' -and $_.LocalPort -lt 49152 } |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    $log.Add("Listening now - kept open: TCP $($tcp -join ',') | UDP $($udp -join ',')")
    if ($tcp) {
        Step "Allow rule BTFM-keep-listening-TCP ($($tcp -join ','))" {
            Remove-NetFirewallRule -DisplayName 'BTFM-keep-listening-TCP' -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'BTFM-keep-listening-TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $tcp -Profile Any -ErrorAction Stop | Out-Null
        }
    }
    if ($udp) {
        Step "Allow rule BTFM-keep-listening-UDP ($($udp -join ','))" {
            Remove-NetFirewallRule -DisplayName 'BTFM-keep-listening-UDP' -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'BTFM-keep-listening-UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $udp -Profile Any -ErrorAction Stop | Out-Null
        }
    }
    Step 'Firewall ON for all profiles' { netsh advfirewall set allprofiles state on }
    Step 'Firewall policy blockinbound,allowoutbound' { netsh advfirewall set allprofiles firewallpolicy 'blockinbound,allowoutbound' }
    Step 'Firewall logging: dropped + allowed, 4 MB' {
        netsh advfirewall set allprofiles logging droppedconnections enable
        netsh advfirewall set allprofiles logging allowedconnections enable
        netsh advfirewall set allprofiles logging maxfilesize 4096
    }

    # STAND ALONE SYSTEM registry settings
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    SetReg $lsa 'LmCompatibilityLevel' 5     # NTLMv2 only, refuse LM & NTLM
    SetReg $lsa 'RestrictAnonymous' 1
    SetReg $lsa 'RestrictAnonymousSAM' 1
    SetReg $lsa 'NoLMHash' 1                 # stop storing LM hashes (pass-the-hash)
    SetReg $lsa 'DisableRestrictedAdmin' 0   # Restricted Admin RDP: no creds cached on host
    SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'DisableLocalMachineRunOnce' 1
    SetReg 'HKCU:\Control Panel\Accessibility\StickyKeys' 'Flags' '506' 'String'
    SetReg 'HKCU:\Control Panel\Accessibility\ToggleKeys' 'Flags' '58' 'String'
    SetReg 'HKCU:\Control Panel\Accessibility\Keyboard Response' 'Flags' '122' 'String'
    SetReg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'DisablePasswordCaching' 1

    # [extra] Remove debugger hijacks on accessibility tools (sticky-keys backdoor).
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($exe in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $k = Join-Path $ifeo $exe
        if ((Test-Path $k) -and (Get-ItemProperty $k -ErrorAction SilentlyContinue).Debugger) {
            Step "Remove IFEO Debugger on $exe" { Remove-ItemProperty -Path $k -Name Debugger -Force }
        }
    }

    # LOG AUDITING: bigger logs + success/failure auditing on all categories.
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' 'MaxSize' 0x19000
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize' 0x64000
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' 'MaxSize' 0x19000
    Step 'auditpol: success+failure on all categories' { auditpol /set /category:* /success:enable /failure:enable }
    # [extra] Command lines in 4688 events and PowerShell script block logging.
    SetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    SetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1

    # [extra] Make sure Defender real-time protection is on, if Defender exists.
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Step 'Defender real-time protection ON' { Set-MpPreference -DisableRealtimeMonitoring $false }
    }

    # Optional, can break scoring or remote access:
    if ($DisableRDP) {
        SetReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    }
    if ($DisableAdminShares) {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        SetReg $p 'AutoShareWks' 0
        SetReg $p 'AutoShareServer' 0
    }
    if ($DisableIPv6) {
        SetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' 255
    }
    foreach ($svc in $DisableService) {
        if (-not $svc) { continue }
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Step "Stop and disable service $svc" {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled
            }
        }
        else { $log.Add("SKIP    service $svc not found") }
    }

    if (-not $DryRun) { $log.Add("Rollback: netsh advfirewall import `"$bk\firewall.wfw`"; reg import `"$bk\lsa.reg`"; auditpol /restore /file:`"$bk\auditpol.csv`"") }
    $log.Add('Some settings (NoLMHash, LmCompatibilityLevel, IPv6) take full effect after a reboot / password change.')
    $log
}

# ============================================================ BLOCK (remote)
$BlockBlock = {
    param([bool]$DryRun, [string[]]$Domains, [string[]]$IPs)
    $out = New-Object System.Collections.Generic.List[string]
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    foreach ($d in $Domains) {
        if (-not $d) { continue }
        if (Select-String -Path $hosts -Pattern ("\s" + [regex]::Escape($d) + "\s*$") -Quiet) { $out.Add("SKIP    $d already in hosts"); continue }
        if ($DryRun) { $out.Add("WHATIF  hosts: 127.0.0.1 $d"); continue }
        Add-Content -Path $hosts -Value "127.0.0.1 $d" -Encoding ASCII
        $out.Add("OK      hosts: 127.0.0.1 $d")
    }
    if ($Domains -and -not $DryRun) {
        ipconfig /flushdns | Out-Null
        nbtstat -R 2>&1 | Out-Null
        $out.Add('OK      flushed DNS and NetBIOS caches')
    }
    foreach ($ip in $IPs) {
        if (-not $ip) { continue }
        foreach ($dir in 'in', 'out') {
            $name = "BTFM-block-$ip-$dir"
            if ($DryRun) { $out.Add("WHATIF  firewall: $name"); continue }
            Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            $direction = if ($dir -eq 'in') { 'Inbound' } else { 'Outbound' }
            try {
                New-NetFirewallRule -DisplayName $name -Direction $direction -Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Out-Null
                $out.Add("OK      firewall: $name")
            }
            catch { $out.Add("FAILED  firewall: $name : $_") }
        }
    }
    $out
}

# ============================================================ KILL (remote)
$KillBlock = {
    param([bool]$DryRun, [int[]]$Ids, [string[]]$Names)
    $out = New-Object System.Collections.Generic.List[string]
    $procs = @()
    if ($Ids) { $procs += Get-Process -Id $Ids -ErrorAction SilentlyContinue }
    if ($Names) { $procs += Get-Process -Name ($Names | ForEach-Object { $_ -replace '\.exe$', '' }) -ErrorAction SilentlyContinue }
    if (-not $procs) { return 'No matching processes found.' }
    $q = Join-Path $env:SystemDrive 'btfm\quarantine'
    if (-not $DryRun) { New-Item -ItemType Directory -Path $q -Force | Out-Null }
    foreach ($p in ($procs | Sort-Object Id -Unique)) {
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)"
        $path = $cim.ExecutablePath
        $out.Add("PID $($p.Id) $($p.ProcessName)  path=$path  parent=$($cim.ParentProcessId)  cmd=$($cim.CommandLine)")
        if ($DryRun) { $out.Add('  WHATIF would copy, hash and stop it'); continue }
        if ($path -and (Test-Path $path)) {
            $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            $dest = Join-Path $q ("{0}_{1}.bin" -f $p.Id, (Split-Path $path -Leaf))
            Copy-Item -Path $path -Destination $dest -Force -ErrorAction SilentlyContinue
            $out.Add("  SHA256 $hash  copied to $dest")
        }
        try { Stop-Process -Id $p.Id -Force; $out.Add('  STOPPED') } catch { $out.Add("  FAILED to stop: $_") }
    }
    $out.Add("Check for the persistence that started it (Triage section 07_autoruns), or it may come back.")
    $out
}

# ============================================================ PASSWORD (remote)
$PasswordBlock = {
    param([bool]$DryRun, [string[]]$Users, [System.Security.SecureString]$NewPassword, [bool]$UseAD, [string[]]$Protected)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($u in $Users) {
        if (-not $u) { continue }
        $hit = $Protected | Where-Object { $u -like $_ }
        if ($hit) { $out.Add("SKIP    $u is protected (matches '$hit') - leave white team / scoring accounts alone"); continue }
        if ($DryRun) { $out.Add("WHATIF  set password for $u"); continue }
        try {
            if ($UseAD) {
                Import-Module ActiveDirectory -ErrorAction Stop
                Set-ADAccountPassword -Identity $u -NewPassword $NewPassword -Reset
            }
            else { Set-LocalUser -Name $u -Password $NewPassword }
            $out.Add("OK      password changed for $u")
        }
        catch { $out.Add("FAILED  $u : $_") }
    }
    $out
}

# ================================================================== main
$targets = @(Resolve-Targets $Target)
if (-not $targets) { throw 'No targets given.' }
$dry = [bool]$WhatIfPreference

$newPw = $null
if ($Mode -eq 'Password') {
    if (-not $User) { throw '-Mode Password needs -User name1,name2' }
    if (-not $dry) {
        $newPw = Read-Host -AsSecureString 'New password'
        $confirm = Read-Host -AsSecureString 'Confirm new password'
        $a = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPw))
        $b = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
        if ($a -cne $b) { throw 'Passwords do not match.' }
        $a = $null; $b = $null
    }
}
if ($Mode -eq 'Block' -and -not ($BlockDomain -or $BlockIP)) { throw '-Mode Block needs -BlockDomain and/or -BlockIP' }
if ($Mode -eq 'Kill' -and -not ($ProcessId -or $ProcessName)) { throw '-Mode Kill needs -ProcessId and/or -ProcessName' }

switch ($Mode) {
    'Triage'   { $block = $TriageBlock;   $argList = @($RecentDays) }
    'Harden'   { $block = $HardenBlock;   $argList = @($dry, [bool]$DisableRDP, [bool]$DisableAdminShares, [bool]$DisableIPv6, [string[]]$DisableService) }
    'Block'    { $block = $BlockBlock;    $argList = @($dry, [string[]]$BlockDomain, [string[]]$BlockIP) }
    'Kill'     { $block = $KillBlock;     $argList = @($dry, [int[]]$ProcessId, [string[]]$ProcessName) }
    'Password' { $block = $PasswordBlock; $argList = @($dry, [string[]]$User, $newPw, [bool]$ADAccount, [string[]]$ProtectedUser) }
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

foreach ($t in $targets) {
    Write-Host "`n==== $Mode on $t $(if ($dry) { '(WhatIf - no changes)' })" -ForegroundColor Cyan
    $session = $null
    try {
        if (Test-IsLocal $t) {
            $result = Invoke-Command -ScriptBlock $block -ArgumentList $argList
            $hostLabel = $env:COMPUTERNAME
        }
        else {
            $sp = @{ ComputerName = $t; ErrorAction = 'Stop' }
            if ($Credential) { $sp.Credential = $Credential }
            $session = New-PSSession @sp
            $result = Invoke-Command -Session $session -ScriptBlock $block -ArgumentList $argList
            $hostLabel = $t
        }

        $dir = Join-Path $OutputDir ("{0}_{1}_{2}" -f ($hostLabel -replace '[^\w\.-]', '_'), $Mode, $Stamp)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null

        if ($Mode -eq 'Triage') {
            foreach ($name in $result.Sections.Keys) {
                $result.Sections[$name] | Set-Content -Path (Join-Path $dir "$name.txt") -Encoding UTF8
            }
            $evtDest = Join-Path $dir 'evtx'
            New-Item -ItemType Directory -Path $evtDest -Force | Out-Null
            if ($session) { Copy-Item -FromSession $session -Path "$($result.EvtxDir)\*" -Destination $evtDest -ErrorAction SilentlyContinue }
            else { Copy-Item -Path "$($result.EvtxDir)\*" -Destination $evtDest -ErrorAction SilentlyContinue }
            Write-Host $result.Sections['00_SUMMARY']
            Write-Host "Saved to $dir" -ForegroundColor Green
        }
        else {
            $result | ForEach-Object { Write-Host $_ }
            $result | Set-Content -Path (Join-Path $dir 'result.txt') -Encoding UTF8
            Write-Host "Log saved to $dir" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "$t : $_"
        if ($_ -match 'WinRM|WS-Management') {
            Write-Warning "Is WinRM on? On the target run: Enable-PSRemoting -Force. For IP targets from a non-domain machine also: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<ip>' -Concatenate"
        }
    }
    finally {
        if ($session) { Remove-PSSession $session }
    }
}
$newPw = $null
