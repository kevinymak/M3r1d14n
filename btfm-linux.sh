#!/usr/bin/env bash
# =============================================================================
# btfm-linux.sh - Blue Team Field Manual (BTFM) toolkit for Linux
#
# Triage, harden, block, kill and password changes, run on this machine or on
# remote targets over SSH. Commands come from the BTFM sections Protect (Linux),
# Log Auditing (Linux), Live Triage - Linux and Kill Malware Process. Lines
# marked [extra] are common competition additions that are not in the book.
#
# MODES
#   triage    Read-only. Collects system, user, network, service, autorun,
#             file and log information into an output folder.
#   harden    Changes settings. Backs up firewall rules first. Use -n to
#             preview without changing anything.
#   block     Sinkholes domains in /etc/hosts and blocks IPs in the firewall.
#   kill      Copies and hashes a process's binary, then kills it.
#   password  Sets a new password for the listed users (prompts once).
#
# TARGETS
#   -t local                 this machine (default)
#   -t 10.0.5.30             remote host over SSH (repeat -t or use commas)
#   -t admin@web01,db01      user@host also works
#   -f linux-hosts.txt       one target per line, # comments allowed
#
# EXAMPLES
#   sudo ./btfm-linux.sh -m triage
#   ./btfm-linux.sh -m triage -t 10.0.5.30,10.0.5.31 -u blueteam1
#   ./btfm-linux.sh -m harden -f linux-hosts.txt -n          # dry run
#   ./btfm-linux.sh -m harden -t web01 --allow-ports 22,80,443 --disable-service telnet.socket,vsftpd
#   ./btfm-linux.sh -m block -t web01 --domain evil.example --ip 203.0.113.7
#   ./btfm-linux.sh -m kill -t web01 --name nc,xmrig --quarantine
#   ./btfm-linux.sh -m password -t web01,db01 --user blueteam1,blueteam2
#
# Remote targets need SSH access and sudo rights; you may be asked for the
# sudo password once per host. Results are copied back to ./btfm-output/.
# =============================================================================
set -o pipefail
VERSION="1.0"
SCRIPT_PATH="$(readlink -f "$0")"

# ------------------------------------------------------------------ defaults
MODE=""
TARGETS=()
SSH_USER=""
SSH_KEY=""
SSH_PORT="22"
OUT_DIR="./btfm-output"
DRY_RUN=0
DAYS=7
ALLOW_PORTS=""
NO_FIREWALL=0
DISABLE_SERVICES=""
BLOCK_DOMAINS=""
BLOCK_IPS=""
KILL_PIDS=""
KILL_NAMES=""
QUARANTINE=0
PW_USERS=""
PROTECTED="whiteteam*,*score*,*scoring*"
LOCAL_RUN=0
RESULT_DIR=""
HASH_FILE=""

usage() { sed -n '3,35p' "$SCRIPT_PATH" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die()   { echo "ERROR: $*" >&2; exit 1; }
have()  { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------ arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)            MODE="${2,,}"; shift 2 ;;
    -t|--target)          IFS=',' read -r -a _t <<<"$2"; TARGETS+=("${_t[@]}"); shift 2 ;;
    -f|--targets-file)    [[ -f "$2" ]] || die "targets file not found: $2"
                          while IFS= read -r line || [[ -n "$line" ]]; do
                            line="${line%%#*}"; line="$(echo "$line" | xargs)"
                            [[ -n "$line" ]] && TARGETS+=("$line")
                          done <"$2"; shift 2 ;;
    -u|--ssh-user)        SSH_USER="$2"; shift 2 ;;
    -i|--ssh-key)         SSH_KEY="$2"; shift 2 ;;
    --ssh-port)           SSH_PORT="$2"; shift 2 ;;
    -o|--out)             OUT_DIR="$2"; shift 2 ;;
    -n|--dry-run)         DRY_RUN=1; shift ;;
    --days)               DAYS="$2"; shift 2 ;;
    --allow-ports)        ALLOW_PORTS="$2"; shift 2 ;;
    --no-firewall)        NO_FIREWALL=1; shift ;;
    --disable-service)    DISABLE_SERVICES="$2"; shift 2 ;;
    --domain)             BLOCK_DOMAINS="$2"; shift 2 ;;
    --ip)                 BLOCK_IPS="$2"; shift 2 ;;
    --pid)                KILL_PIDS="$2"; shift 2 ;;
    --name)               KILL_NAMES="$2"; shift 2 ;;
    --quarantine)         QUARANTINE=1; shift ;;
    --user)               PW_USERS="$2"; shift 2 ;;
    --protect)            PROTECTED="$2"; shift 2 ;;
    --local)              LOCAL_RUN=1; shift ;;          # internal: run here
    --result-dir)         RESULT_DIR="$2"; shift 2 ;;    # internal
    --hash-file)          HASH_FILE="$2"; shift 2 ;;     # internal
    -h|--help)            usage 0 ;;
    -V|--version)         echo "$VERSION"; exit 0 ;;
    *)                    echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

case "$MODE" in triage|harden|block|kill|password) ;; *) echo "Choose -m triage|harden|block|kill|password" >&2; usage 1 ;; esac
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=("local")
[[ "$MODE" == block && -z "$BLOCK_DOMAINS$BLOCK_IPS" ]] && die "block mode needs --domain and/or --ip"
[[ "$MODE" == kill && -z "$KILL_PIDS$KILL_NAMES" ]] && die "kill mode needs --pid and/or --name"
[[ "$MODE" == password && -z "$PW_USERS" ]] && die "password mode needs --user name1,name2"

# ------------------------------------------------------------------ helpers (run on the target)
LOG_FILE=""
log()  { echo "$*" | tee -a "${LOG_FILE:-/dev/null}"; }
step() {  # step "description" command args...
  local desc="$1"; shift
  if [[ $DRY_RUN -eq 1 ]]; then log "WHATIF  $desc"; return 0; fi
  if "$@" >>"${LOG_FILE:-/dev/null}" 2>&1; then log "OK      $desc"; else log "FAILED  $desc"; fi
}
section() {  # section NN_name  -> runs the function body, saves output
  local name="$1"; shift
  { echo "### $name   (collected $(date -Is 2>/dev/null || date))"; "$@"; } >"$RESULT_DIR/$name.txt" 2>&1
}
hdr() { echo; echo "--- $*"; }
run() { hdr "$*"; if have "$1"; then "$@" 2>&1; else echo "($1 not installed)"; fi; }
showfile() { for f in "$@"; do [[ -e "$f" ]] && { hdr "$f"; cat "$f" 2>&1; }; done; }

firewall_kind() {
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then echo ufw
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then echo firewalld
  elif have ufw; then echo ufw
  elif have iptables; then echo iptables
  else echo none; fi
}

proc_listeners() {  # fallback when ss/netstat are missing: read /proc/net directly
  local f proto
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [[ -r "$f" ]] || continue
    proto="${f##*/}"; proto="${proto%6}"
    awk -v proto="$proto" 'function hex(h,  i, n) { n=0; h=toupper(h)
          for (i=1; i<=length(h); i++) n = n*16 + index("0123456789ABCDEF", substr(h,i,1)) - 1
          return n }
      NR>1 {
        split($2, a, ":"); ip=a[1]; port=hex(a[2])
        if (proto=="tcp" && $4!="0A") next              # 0A = LISTEN
        if (proto=="udp" && $4!="07") next              # 07 = unconnected socket
        if (ip ~ /^..00007F$/ || ip=="00000000000000000000000001000000") ip="127.0.0.1"; else ip="0.0.0.0"
        print proto, ip ":" port }' "$f"
  done
}

listening_ports() {  # prints "port/proto" for non-loopback listeners
  if have ss; then
    ss -H -tuln 2>/dev/null | awk '{print $1, $5}'
  elif have netstat; then
    netstat -tuln 2>/dev/null | awk 'NR>2 {print $1, $4}'
  else
    proc_listeners
  fi | while read -r proto addr; do
    case "$addr" in 127.*|"[::1]"*|::1:*) continue ;; esac
    port="${addr##*:}"; [[ "$port" =~ ^[0-9]+$ ]] || continue
    case "$proto" in tcp*) echo "$port/tcp" ;; udp*) echo "$port/udp" ;; esac
  done | sort -u -t/ -k1,1n
}

# ================================================================== TRIAGE
t_system() {
  run date; run hostname; run uname -a; run uptime; run timedatectl
  showfile /etc/os-release
  run mount; run df -ah
}
t_users() {
  run w
  run last -n 50 -a
  run lastlog
  hdr "failed logins (lastb / faillog)"; { lastb -n 50 2>/dev/null || faillog -a 2>/dev/null; } | head -60
  showfile /etc/passwd /etc/group
  hdr "account password status (from /etc/shadow; hashes not copied)"
  awk -F: '{s="HASH"; if($2=="") s="!! EMPTY PASSWORD"; else if($2 ~ /^[!*]/) s="locked/no-login"; print $1": "s}' /etc/shadow 2>/dev/null
  hdr "UID 0 accounts"; awk -F: '($3 == 0) {print}' /etc/passwd
  hdr "accounts with a login shell"; grep -Ev '(nologin|false|sync|halt|shutdown)$' /etc/passwd
  showfile /etc/sudoers; for f in /etc/sudoers.d/*; do showfile "$f"; done
  hdr "sudo/wheel/admin group members"; getent group sudo wheel admin 2>/dev/null
  hdr "SSH authorized_keys (all users)"
  while IFS=: read -r u _ _ _ _ home _; do
    for k in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -s "$k" ]] && { echo "== $u ($k)"; cat "$k"; }
    done
  done </etc/passwd
  hdr "shell histories (last 40 lines each)"
  while IFS=: read -r u _ _ _ _ home _; do
    for h in "$home"/.*history; do [[ -f "$h" ]] && { echo "== $u $h"; tail -n 40 "$h"; }; done
  done </etc/passwd
}
t_network() {
  if have ip; then run ip addr; run ip route; run ip neigh; else run ifconfig -a; run route -n; run arp -a; fi
  if have ss; then run ss -tulpn; run ss -tanp state established
  elif have netstat; then run netstat -plantux
  else hdr "listeners from /proc/net (ss and netstat not installed)"; proc_listeners; fi
  run lsof -nP -i
  showfile /etc/hosts /etc/resolv.conf /etc/hosts.allow /etc/hosts.deny
  hdr "firewall"; run iptables -S; run nft list ruleset; run ufw status verbose; run firewall-cmd --list-all
}
t_processes() {
  run ps auxwwf
  hdr "[extra] processes whose binary was deleted from disk"
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    [[ "$exe" == *"(deleted)"* ]] && echo "!! PID ${p#/proc/}: $exe  cmd: $(tr '\0' ' ' <"$p/cmdline")"
  done
  run lsof +L1
  run lsmod
  hdr "running services"; if have systemctl; then systemctl list-units --type=service --state=running --no-pager; else service --status-all 2>&1; fi
  hdr "enabled services"; have systemctl && systemctl list-unit-files --state=enabled --no-pager
  have chkconfig && run chkconfig --list
}
t_autoruns() {
  hdr "user crontabs"
  while IFS=: read -r u _; do c="$(crontab -l -u "$u" 2>/dev/null)" && { echo "== $u"; echo "$c"; }; done </etc/passwd
  showfile /etc/crontab /etc/anacrontab
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$d" ]] && { hdr "ls -la $d"; ls -la "$d"; }
  done
  for f in /etc/cron.d/*; do showfile "$f"; done
  have systemctl && { hdr "systemd timers"; systemctl list-timers --all --no-pager; }
  hdr "[extra] systemd units changed in the last $DAYS days"
  find /etc/systemd /lib/systemd/system /usr/lib/systemd/system -name '*.service' -mtime "-$DAYS" -ls 2>/dev/null
  showfile /etc/rc.local /etc/ld.so.preload
  hdr "/etc/init.d"; ls -la /etc/init.d 2>/dev/null
  hdr "/etc/profile.d"; ls -la /etc/profile.d 2>/dev/null
  hdr "PAM config"; for f in /etc/pam.d/common-* /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd; do showfile "$f"; done
  hdr "[extra] PAM modules changed in the last $DAYS days"
  find /lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/*/security -name '*.so' -mtime "-$DAYS" -ls 2>/dev/null
  hdr "sshd effective settings"; have sshd && sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|port '
}
t_files() {
  local dirs=(/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /root /home /tmp /var/tmp /dev/shm /var/www /srv /opt)
  hdr "files modified in the last $DAYS days (system + web + home + temp)"
  find "${dirs[@]}" -xdev -type f -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %u:%g %m %s  %p\n' 2>/dev/null | sort -r | head -400
  hdr "executable files in /tmp, /var/tmp, /dev/shm"
  find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -ls 2>/dev/null
  hdr "hidden files/dirs in temp and web roots"
  find /tmp /var/tmp /dev/shm /var/www /srv -xdev -name '.*' ! -name '.' ! -name '..' -ls 2>/dev/null | head -100
  hdr "immutable files (lsattr) in key paths"
  have lsattr && lsattr -R /etc /bin /sbin /usr/bin /usr/sbin /root 2>/dev/null | grep -E '^[^ ]*i[^ ]* ' | head -100
  hdr "world-writable directories without sticky bit"
  find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | head -100
  hdr "[extra] SUID/SGID binaries"
  find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%TY-%Tm-%Td  %m %u  %p\n' 2>/dev/null | sort -r
  hdr "web roots: recently changed scripts (possible web shells)"
  find /var/www /srv /usr/share/nginx -xdev -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.py' -o -name '*.pl' -o -name '*.cgi' -o -name '*.sh' \) -mtime "-$DAYS" -ls 2>/dev/null
}
t_logs() {
  local auth=""; for f in /var/log/auth.log /var/log/secure; do [[ -f "$f" ]] && auth="$f"; done
  if [[ -n "$auth" ]]; then
    hdr "$auth: failures (last 100)"; grep -i "fail" "$auth" | tail -n 100
    hdr "$auth: accepted logins (last 100)"; grep -i "accepted" "$auth" | tail -n 100
    hdr "$auth: sudo (last 100)"; grep -i "sudo" "$auth" | tail -n 100
    hdr "$auth: user/group changes"; grep -Ei "useradd|usermod|groupadd|new user|password changed" "$auth" | tail -n 100
  elif have journalctl; then
    hdr "journal: auth failures (last 24h)"; journalctl --since "-24h" --no-pager 2>/dev/null | grep -Ei "fail|invalid user" | tail -n 150
    hdr "journal: sudo (last 24h)"; journalctl --since "-24h" --no-pager _COMM=sudo 2>/dev/null | tail -n 100
  fi
  hdr "cron activity"; grep -i cron /var/log/syslog /var/log/cron 2>/dev/null | tail -n 60
  hdr "web server errors / 404s"
  for f in /var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log; do
    [[ -f "$f" ]] && { echo "== $f"; grep ' 404 ' "$f" | grep -Ev 'favicon.ico|robots.txt' | tail -n 50; }
  done
  have aureport && run aureport --summary
  hdr "rootkit / audit tools installed (run manually, they are slow)"
  for t in chkrootkit rkhunter lynis maldet tiger; do have "$t" && echo "  $t: $(command -v "$t")"; done
}
t_summary() {
  echo "Host: $(hostname)   $(date)"
  echo "UID 0 accounts: $(awk -F: '($3==0){printf "%s ",$1}' /etc/passwd)"
  awk -F: '($3==0 && $1!="root"){print "!! extra UID 0 account: "$1}' /etc/passwd
  awk -F: '($2==""){print "!! empty password: "$1}' /etc/shadow 2>/dev/null
  echo "Login-shell users: $(grep -Ev '(nologin|false|sync|halt|shutdown)$' /etc/passwd | cut -d: -f1 | xargs)"
  echo "Sudo/wheel members: $(getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr '\n' ' ')"
  while IFS=: read -r u _ _ _ _ home _; do
    [[ -s "$home/.ssh/authorized_keys" ]] && echo "SSH keys present for: $u ($(grep -c . "$home/.ssh/authorized_keys") keys)"
  done </etc/passwd
  [[ -s /etc/ld.so.preload ]] && echo "!! /etc/ld.so.preload is set: $(cat /etc/ld.so.preload)"
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    [[ "$exe" == *"(deleted)"* ]] && echo "!! running deleted binary: PID ${p#/proc/} $exe"
  done
  echo "Listening ports: $(listening_ports | xargs)"
  n="$(find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null | wc -l)"
  [[ "$n" -gt 0 ]] && echo "!! $n executable file(s) in /tmp, /var/tmp or /dev/shm"
  echo "Firewall: $(firewall_kind)"
}

do_triage() {
  section 00_SUMMARY     t_summary
  section 01_system      t_system
  section 02_users       t_users
  section 03_network     t_network
  section 04_processes   t_processes
  section 05_autoruns    t_autoruns
  section 06_files       t_files
  section 07_logs        t_logs
  cat "$RESULT_DIR/00_SUMMARY.txt"
}

# ================================================================== HARDEN
do_harden() {
  local bk; bk="/root/btfm-backup-$(date +%Y%m%d-%H%M%S)"
  step "Back up firewall rules to $bk" sh -c "mkdir -p '$bk' && (iptables-save > '$bk/iptables.rules' 2>/dev/null; ip6tables-save > '$bk/ip6tables.rules' 2>/dev/null; nft list ruleset > '$bk/nft.rules' 2>/dev/null; cp -a /etc/ufw '$bk/' 2>/dev/null; cp -a /etc/firewalld '$bk/' 2>/dev/null; true)"

  if [[ $NO_FIREWALL -eq 0 ]]; then
    local ports
    if [[ -n "$ALLOW_PORTS" ]]; then
      ports="$(echo "$ALLOW_PORTS" | tr ',' '\n' | sed '/\//!s/$/\/tcp/' | sort -u)"
    else
      # Keep every service that is listening right now, so scored services stay up.
      ports="$(listening_ports)"
    fi
    if [[ -z "$ALLOW_PORTS" && -z "$ports" ]]; then
      log "STOP    could not detect any listening services, so the firewall was left alone."
      log "        Re-run with --allow-ports 22,80,443,... listing the scored services on this host."
      NO_FIREWALL=1
    fi
    ports="$(printf '%s\n22/tcp\n' "$ports" | grep . | sort -u -t/ -k1,1n)"   # never lock out SSH
    [[ $NO_FIREWALL -eq 1 ]] || log "Allowed inbound: $(echo "$ports" | xargs)"
    [[ $NO_FIREWALL -eq 1 ]] || case "$(firewall_kind)" in
      ufw)
        step "ufw: back up user rules" sh -c "cp /etc/ufw/user.rules /etc/ufw/user6.rules '$bk/' 2>/dev/null || cp /lib/ufw/user.rules /lib/ufw/user6.rules '$bk/' 2>/dev/null || true"
        for p in $ports; do step "ufw allow $p" ufw allow "$p"; done
        step "ufw default deny incoming / allow outgoing" sh -c "ufw default deny incoming && ufw default allow outgoing"
        step "ufw logging on" ufw logging on
        step "ufw enable" ufw --force enable ;;
      firewalld)
        for p in $ports; do step "firewalld allow $p" firewall-cmd --permanent --add-port="$p"; done
        step "firewalld log denied" firewall-cmd --set-log-denied=all
        step "firewalld reload" firewall-cmd --reload ;;
      iptables)
        step "iptables: allow loopback" sh -c "iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT"
        step "iptables: allow established" sh -c "iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT"
        for p in $ports; do
          step "iptables allow ${p}" sh -c "iptables -C INPUT -p ${p#*/} --dport ${p%/*} -j ACCEPT 2>/dev/null || iptables -A INPUT -p ${p#*/} --dport ${p%/*} -j ACCEPT"
        done
        step "iptables: log denied (5/min)" iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
        step "iptables: default policy INPUT DROP" iptables -P INPUT DROP
        log "NOTE    iptables rules are not saved across reboot. Save: iptables-save > /etc/iptables/rules.v4 (Debian) or service iptables save (RHEL)" ;;
      *) log "SKIP    no firewall tool found (ufw, firewalld, iptables)" ;;
    esac
  else
    log "SKIP    firewall (--no-firewall)"
  fi

  # DISABLE/STOP SERVICES
  for s in ${DISABLE_SERVICES//,/ }; do
    if have systemctl; then step "disable --now $s" systemctl disable --now "$s"
    else step "stop + disable $s" sh -c "service '$s' stop; update-rc.d '$s' disable 2>/dev/null || chkconfig '$s' off"; fi
  done

  # LOG AUDITING: auditd exec logging (book: auditctl -a exit,always -S execve)
  if have auditctl; then
    step "auditd: log every execve (64-bit)" auditctl -a exit,always -F arch=b64 -S execve -k btfm_exec
    step "auditd: log every execve (32-bit)" auditctl -a exit,always -F arch=b32 -S execve -k btfm_exec
    step "[extra] auditd: watch passwd/shadow/sudoers/ssh" sh -c "for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config; do auditctl -w \$f -p wa -k btfm_identity; done"
    log "        search later with: ausearch -k btfm_exec -i | tail ; ausearch -k btfm_identity -i"
  else
    log "SKIP    auditd not installed (apt/dnf install auditd if you have repo access)"
  fi
  have systemctl && have rsyslogd && step "make sure rsyslog is running" systemctl enable --now rsyslog

  # Report-only checks (changing these automatically could lock out the team)
  awk -F: '($3==0 && $1!="root"){print "REVIEW  extra UID 0 account: "$1" (remove with: userdel <name> or usermod -u <new uid>)"}' /etc/passwd | tee -a "${LOG_FILE:-/dev/null}"
  awk -F: '($2==""){print "REVIEW  empty password: "$1" (lock with: passwd -l <name>)"}' /etc/shadow 2>/dev/null | tee -a "${LOG_FILE:-/dev/null}"
  [[ -s /etc/ld.so.preload ]] && log "REVIEW  /etc/ld.so.preload is set: $(cat /etc/ld.so.preload)"
  log "Rollback: iptables-restore < $bk/iptables.rules   (or restore $bk/ufw, $bk/firewalld)"
}

# ================================================================== BLOCK
do_block() {
  for d in ${BLOCK_DOMAINS//,/ }; do
    if grep -Eq "[[:space:]]${d//./\\.}([[:space:]]|$)" /etc/hosts; then log "SKIP    $d already in /etc/hosts"
    else step "/etc/hosts: 127.0.0.1 $d" sh -c "echo '127.0.0.1 $d' >> /etc/hosts"; fi
  done
  if [[ -n "$BLOCK_DOMAINS" ]]; then
    have resolvectl && step "flush systemd-resolved cache" resolvectl flush-caches
    have nscd && step "flush nscd hosts cache" nscd -i hosts
    have systemctl && systemctl is-active --quiet dnsmasq 2>/dev/null && step "restart dnsmasq" systemctl restart dnsmasq
  fi
  local fw; fw="$(firewall_kind)"
  for ip in ${BLOCK_IPS//,/ }; do
    case "$fw" in
      ufw)       step "ufw deny from $ip" ufw insert 1 deny from "$ip"
                 step "ufw deny out to $ip" ufw insert 1 deny out to "$ip" ;;
      firewalld) step "firewalld drop $ip" firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip drop"
                 step "firewalld reload" firewall-cmd --reload ;;
      iptables)  step "iptables drop in from $ip" iptables -I INPUT 1 -s "$ip" -j DROP
                 step "iptables drop out to $ip" iptables -I OUTPUT 1 -d "$ip" -j DROP ;;
      *)         log "SKIP    no firewall tool to block $ip" ;;
    esac
  done
}

# ================================================================== KILL
do_kill() {
  local pids=() q="/root/btfm-quarantine"
  for p in ${KILL_PIDS//,/ }; do pids+=("$p"); done
  for n in ${KILL_NAMES//,/ }; do while read -r p; do [[ -n "$p" ]] && pids+=("$p"); done < <(pgrep -x "$n"); done
  [[ ${#pids[@]} -eq 0 ]] && { log "No matching processes found."; return; }
  [[ $DRY_RUN -eq 0 ]] && mkdir -p "$q" && chmod 700 "$q"
  for p in $(printf '%s\n' "${pids[@]}" | sort -un); do
    [[ -d "/proc/$p" ]] || { log "PID $p not running"; continue; }
    local exe cmd hash
    exe="$(readlink "/proc/$p/exe" 2>/dev/null)"
    cmd="$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)"
    log "PID $p  exe=$exe  user=$(stat -c %U "/proc/$p")  ppid=$(awk '/^PPid/{print $2}' "/proc/$p/status")  cmd=$cmd"
    if [[ $DRY_RUN -eq 1 ]]; then log "  WHATIF would copy, hash and kill it"; continue; fi
    # Book: cp /proc/<PID>/exe for later analysis (works even if the file was deleted)
    if cp "/proc/$p/exe" "$q/${p}_$(basename "${exe%% (deleted)}").elf" 2>/dev/null; then
      hash="$(sha256sum "$q/${p}_$(basename "${exe%% (deleted)}").elf" | cut -d' ' -f1)"
      log "  SHA256 $hash  copied to $q"
    fi
    kill -9 "$p" && log "  KILLED" || log "  FAILED to kill"
    # Book: chmod -x and move the binary to quarantine (opt-in)
    local orig="${exe%% (deleted)}"
    if [[ $QUARANTINE -eq 1 && -f "$orig" ]]; then
      chmod -x "$orig" && mv "$orig" "$q/" && log "  moved $orig to $q (chmod -x)"
    fi
  done
  log "Check how it started (triage 05_autoruns: cron, systemd, rc.local) or it may come back."
}

# ================================================================== PASSWORD
do_password() {
  [[ -n "$HASH_FILE" && -s "$HASH_FILE" ]] || [[ $DRY_RUN -eq 1 ]] || { log "FAILED  no password hash supplied"; return 1; }
  local hash=""; [[ -n "$HASH_FILE" && -s "$HASH_FILE" ]] && hash="$(cat "$HASH_FILE")"
  IFS=',' read -r -a pats <<<"$PROTECTED"
  for u in ${PW_USERS//,/ }; do
    local skip=""
    for pat in "${pats[@]}"; do
      # shellcheck disable=SC2053
      [[ "$u" == $pat ]] && skip="$pat"
    done
    if [[ -n "$skip" ]]; then log "SKIP    $u is protected (matches '$skip') - leave white team / scoring accounts alone"; continue; fi
    if ! id "$u" >/dev/null 2>&1; then log "SKIP    $u does not exist here"; continue; fi
    step "set password for $u" usermod -p "$hash" "$u"
  done
  [[ -n "$HASH_FILE" ]] && rm -f "$HASH_FILE"
}

# ================================================================== run on this machine
run_here() {
  [[ $EUID -eq 0 ]] || die "run as root (sudo) on the target"
  RESULT_DIR="${RESULT_DIR:-/root/btfm-$(hostname)-$MODE-$(date +%Y%m%d-%H%M%S)}"
  mkdir -p "$RESULT_DIR"; chmod 700 "$RESULT_DIR"
  LOG_FILE="$RESULT_DIR/result.log"
  [[ $DRY_RUN -eq 1 ]] && log "(dry run - no changes)"
  case "$MODE" in
    triage)   do_triage ;;
    harden)   do_harden ;;
    block)    do_block ;;
    kill)     do_kill ;;
    password) do_password ;;
  esac
}

if [[ $LOCAL_RUN -eq 1 ]]; then run_here; exit $?; fi

# ================================================================== controller: loop over targets
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_DIR"

PW_HASH=""
if [[ "$MODE" == password && $DRY_RUN -eq 0 ]]; then
  read -r -s -p "New password: " pw1; echo
  read -r -s -p "Confirm:      " pw2; echo
  [[ "$pw1" == "$pw2" && -n "$pw1" ]] || die "passwords empty or do not match"
  if have openssl; then PW_HASH="$(printf '%s' "$pw1" | openssl passwd -6 -stdin)"
  elif have mkpasswd; then PW_HASH="$(printf '%s' "$pw1" | mkpasswd -m sha-512 -s)"
  else die "need openssl or mkpasswd to hash the password"; fi
  unset pw1 pw2
fi

# Rebuild the argument list to hand to the target
pass_args=(-m "$MODE" --days "$DAYS" --protect "$PROTECTED")
[[ $DRY_RUN -eq 1 ]]        && pass_args+=(-n)
[[ -n "$ALLOW_PORTS" ]]     && pass_args+=(--allow-ports "$ALLOW_PORTS")
[[ $NO_FIREWALL -eq 1 ]]    && pass_args+=(--no-firewall)
[[ -n "$DISABLE_SERVICES" ]] && pass_args+=(--disable-service "$DISABLE_SERVICES")
[[ -n "$BLOCK_DOMAINS" ]]   && pass_args+=(--domain "$BLOCK_DOMAINS")
[[ -n "$BLOCK_IPS" ]]       && pass_args+=(--ip "$BLOCK_IPS")
[[ -n "$KILL_PIDS" ]]       && pass_args+=(--pid "$KILL_PIDS")
[[ -n "$KILL_NAMES" ]]      && pass_args+=(--name "$KILL_NAMES")
[[ $QUARANTINE -eq 1 ]]     && pass_args+=(--quarantine)
[[ -n "$PW_USERS" ]]        && pass_args+=(--user "$PW_USERS")

ssh_opts=(-p "$SSH_PORT" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
scp_opts=(-P "$SSH_PORT" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -q)
[[ -n "$SSH_KEY" ]] && { ssh_opts+=(-i "$SSH_KEY"); scp_opts+=(-i "$SSH_KEY"); }

for t in "${TARGETS[@]}"; do
  echo; echo "==== $MODE on $t $([[ $DRY_RUN -eq 1 ]] && echo '(dry run)')"
  case "$t" in
    local|localhost|127.0.0.1|"$(hostname)")
      label="$(hostname)"
      dest="$OUT_DIR/${label}_${MODE}_${STAMP}"
      hashf=""
      if [[ -n "$PW_HASH" ]]; then hashf="$(mktemp)"; printf '%s' "$PW_HASH" >"$hashf"; fi
      args=("${pass_args[@]}" --local --result-dir "$dest")
      [[ -n "$hashf" ]] && args+=(--hash-file "$hashf")
      if [[ $EUID -eq 0 ]]; then bash "$SCRIPT_PATH" "${args[@]}"; else sudo bash "$SCRIPT_PATH" "${args[@]}"; fi
      [[ $EUID -ne 0 ]] && sudo chown -R "$(id -u):$(id -g)" "$dest" 2>/dev/null
      echo "Saved to $dest"
      ;;
    *)
      host="$t"; [[ -n "$SSH_USER" && "$t" != *@* ]] && host="$SSH_USER@$t"
      label="${t#*@}"
      rid="btfm-$$-$RANDOM"
      rdir="/tmp/$rid"
      dest="$OUT_DIR/${label}_${MODE}_${STAMP}"
      # 1) copy the script (and password hash) over
      if ! ssh "${ssh_opts[@]}" "$host" "umask 077 && mkdir -p $rdir"; then echo "!! cannot SSH to $host"; continue; fi
      scp "${scp_opts[@]}" "$SCRIPT_PATH" "$host:$rdir/btfm.sh" || { echo "!! copy failed"; continue; }
      rargs=("${pass_args[@]}" --local --result-dir "$rdir/out")
      if [[ -n "$PW_HASH" ]]; then
        printf '%s' "$PW_HASH" | ssh "${ssh_opts[@]}" "$host" "umask 077 && cat > $rdir/h" && rargs+=(--hash-file "$rdir/h")
      fi
      # 2) run it with sudo (-t so sudo can ask for a password)
      ssh -t "${ssh_opts[@]}" "$host" "sudo bash $rdir/btfm.sh $(printf '%q ' "${rargs[@]}"); sudo chown -R \$(id -u):\$(id -g) $rdir/out 2>/dev/null"
      # 3) bring the results back and clean up
      mkdir -p "$dest"
      ssh "${ssh_opts[@]}" "$host" "tar -C $rdir/out -cf - ." | tar -C "$dest" -xf - 2>/dev/null \
        && echo "Saved to $dest" || echo "!! could not copy results back from $host"
      ssh "${ssh_opts[@]}" "$host" "rm -rf $rdir" >/dev/null 2>&1
      ;;
  esac
done
