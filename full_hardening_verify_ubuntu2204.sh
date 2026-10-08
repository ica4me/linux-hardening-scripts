#!/usr/bin/env bash
set -u

# Full one-shot hardening verification for Ubuntu 22.04 LTS.
# Read-only: this script does not modify the system.
# PermitRootLogin accepts: no OR prohibit-password.

GREEN='\e[0;32m'; RED='\e[0;31m'; CYAN='\e[0;36m'; YELLOW='\e[1;33m'; NC='\e[0m'
PASS_COUNT=0; FAIL_COUNT=0
pass(){ echo -e "${GREEN}[PASS] $*${NC}"; PASS_COUNT=$((PASS_COUNT+1)); }
fail(){ echo -e "${RED}[FAIL] $*${NC}"; FAIL_COUNT=$((FAIL_COUNT+1)); }
actual(){ echo -e "   ${YELLOW}Actual   : $*${NC}"; }
expected(){ echo -e "   ${CYAN}Expected : $*${NC}"; }

check_file(){
  local file="$1" regex="$2" label="$3" key="$4"
  if [[ ! -f "$file" ]]; then fail "File $file tidak ditemukan"; return; fi
  if grep -Eq "$regex" "$file"; then pass "$label"; else
    fail "$label"; expected "$label"
    local v; v=$(grep -Ei "^[[:space:]]*${key}([[:space:]=]|$)" "$file" 2>/dev/null | grep -Ev '^[[:space:]]*#' | head -n1)
    actual "${v:-NOT FOUND}"
  fi
}

check_rule(){
  local file="$1" rule="$2"
  if [[ ! -f "$file" ]]; then fail "File $file tidak ditemukan"; return; fi
  grep -Fqx -- "$rule" "$file" && pass "$rule" || { fail "Rule hilang/tidak sesuai di $file"; expected "$rule"; }
}

check_mount_opt(){
  local mp="$1" opt="$2" opts
  opts=$(findmnt -n -o OPTIONS "$mp" 2>/dev/null || true)
  grep -qw "$opt" <<< "${opts//,/ }" && pass "$mp has $opt" || { fail "$mp missing $opt"; actual "${opts:-UNKNOWN}"; }
}

header(){ echo -e "\n${CYAN}--- $* ---${NC}"; }

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN} FULL HARDENING VERIFICATION - UBUNTU 22.04 LTS${NC}"
echo -e "${CYAN}============================================================${NC}"

header "0. OPERATING SYSTEM"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  [[ "${ID,,}" == ubuntu && "${VERSION_ID:-}" == 22.04 ]] && pass "OS = ${PRETTY_NAME}" || { fail "OS bukan Ubuntu 22.04 LTS"; actual "${PRETTY_NAME:-UNKNOWN}"; }
else fail "/etc/os-release tidak ditemukan"; fi

header "1. PWQUALITY"
check_file /etc/security/pwquality.conf '^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14[[:space:]]*$' 'minlen = 14' minlen
check_file /etc/security/pwquality.conf '^[[:space:]]*dcredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' 'dcredit = -1' dcredit
check_file /etc/security/pwquality.conf '^[[:space:]]*ucredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' 'ucredit = -1' ucredit
check_file /etc/security/pwquality.conf '^[[:space:]]*ocredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' 'ocredit = -1' ocredit
check_file /etc/security/pwquality.conf '^[[:space:]]*lcredit[[:space:]]*=[[:space:]]*-1[[:space:]]*$' 'lcredit = -1' lcredit

header "2. LOGIN.DEFS"
check_file /etc/login.defs '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+90([[:space:]]|$)' 'PASS_MAX_DAYS 90' PASS_MAX_DAYS
check_file /etc/login.defs '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+1([[:space:]]|$)' 'PASS_MIN_DAYS 1' PASS_MIN_DAYS
check_file /etc/login.defs '^[[:space:]]*PASS_WARN_AGE[[:space:]]+7([[:space:]]|$)' 'PASS_WARN_AGE 7' PASS_WARN_AGE

header "3. FAILLOCK"
check_file /etc/security/faillock.conf '^[[:space:]]*deny[[:space:]]*=[[:space:]]*3[[:space:]]*$' 'deny = 3' deny
check_file /etc/security/faillock.conf '^[[:space:]]*fail_interval[[:space:]]*=[[:space:]]*900[[:space:]]*$' 'fail_interval = 900' fail_interval
check_file /etc/security/faillock.conf '^[[:space:]]*unlock_time[[:space:]]*=[[:space:]]*1800[[:space:]]*$' 'unlock_time = 1800' unlock_time

header "4. PAM CONFIGURATION"
check_file /etc/pam.d/common-password '^[[:space:]]*password[[:space:]]+required[[:space:]]+pam_pwhistory\.so[[:space:]]+remember=5([[:space:]]+use_authtok)?([[:space:]]|$)' 'pam_pwhistory remember=5 (use_authtok allowed)' pam_pwhistory.so
check_file /etc/pam.d/common-password '^[[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so[[:space:]]+retry=5([[:space:]]|$)' 'pam_pwquality retry=5' pam_pwquality.so
check_file /etc/pam.d/common-auth '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth([[:space:]]|$)' 'pam_faillock preauth' pam_faillock.so
check_file /etc/pam.d/common-auth '^[[:space:]]*auth[[:space:]]+\[success=1[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so[[:space:]]+nullok([[:space:]]|$)' 'common-auth pam_unix nullok' pam_unix.so
check_file /etc/pam.d/common-account '^[[:space:]]*account[[:space:]]+\[success=1[[:space:]]+new_authtok_reqd=done[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so([[:space:]]|$)' 'common-account pam_unix' pam_unix.so

header "5. SSHD CONFIGURATION"
SSHD=/etc/ssh/sshd_config
if [[ -f "$SSHD" ]]; then
  p=$(stat -c '%U:%G %a' "$SSHD" 2>/dev/null || true)
  [[ "$p" == 'root:root 600' ]] && pass 'sshd_config permission = root:root 600' || { fail 'sshd_config permission'; expected 'root:root 600'; actual "${p:-UNKNOWN}"; }
else fail "$SSHD tidak ditemukan"; fi
check_file "$SSHD" '^[[:space:]]*Protocol[[:space:]]+2[[:space:]]*$' 'Protocol 2' Protocol
check_file "$SSHD" '^[[:space:]]*Ciphers[[:space:]]+aes128-ctr,aes192-ctr,aes256-ctr[[:space:]]*$' 'Ciphers configured' Ciphers
check_file "$SSHD" '^[[:space:]]*MACs[[:space:]]+hmac-sha2-512-etm@openssh\.com,hmac-sha2-256-etm@openssh\.com,hmac-sha2-512,hmac-sha2-256[[:space:]]*$' 'MACs configured' MACs
check_file "$SSHD" '^[[:space:]]*KexAlgorithms[[:space:]]+curve25519-sha256@libssh\.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256[[:space:]]*$' 'KexAlgorithms configured' KexAlgorithms
check_file "$SSHD" '^[[:space:]]*LogLevel[[:space:]]+VERBOSE[[:space:]]*$' 'LogLevel VERBOSE' LogLevel
check_file "$SSHD" '^[[:space:]]*LoginGraceTime[[:space:]]+60[[:space:]]*$' 'LoginGraceTime 60' LoginGraceTime

# Exception requested: PermitRootLogin no OR prohibit-password are both valid.
if grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+(no|prohibit-password)[[:space:]]*$' "$SSHD" 2>/dev/null; then
  v=$(grep -E '^[[:space:]]*PermitRootLogin[[:space:]]+' "$SSHD" | head -n1 | xargs)
  pass "$v (accepted)"
else
  fail 'PermitRootLogin'
  expected 'PermitRootLogin no OR PermitRootLogin prohibit-password'
  v=$(grep -E '^[[:space:]]*PermitRootLogin[[:space:]]+' "$SSHD" 2>/dev/null | head -n1 | xargs)
  actual "${v:-NOT FOUND}"
fi

check_file "$SSHD" '^[[:space:]]*MaxAuthTries[[:space:]]+4[[:space:]]*$' 'MaxAuthTries 4' MaxAuthTries
check_file "$SSHD" '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no[[:space:]]*$' 'PermitEmptyPasswords no' PermitEmptyPasswords
check_file "$SSHD" '^[[:space:]]*AllowTcpForwarding[[:space:]]+no[[:space:]]*$' 'AllowTcpForwarding no' AllowTcpForwarding
check_file "$SSHD" '^[[:space:]]*X11Forwarding[[:space:]]+no[[:space:]]*$' 'X11Forwarding no' X11Forwarding
check_file "$SSHD" '^[[:space:]]*ClientAliveInterval[[:space:]]+300[[:space:]]*$' 'ClientAliveInterval 300' ClientAliveInterval
check_file "$SSHD" '^[[:space:]]*ClientAliveCountMax[[:space:]]+3[[:space:]]*$' 'ClientAliveCountMax 3' ClientAliveCountMax
check_file "$SSHD" '^[[:space:]]*MaxStartups[[:space:]]+10:30:60[[:space:]]*$' 'MaxStartups 10:30:60' MaxStartups
if command -v sshd >/dev/null 2>&1; then
  sshd -t 2>/dev/null && pass 'sshd syntax valid' || fail 'sshd syntax invalid'
  er=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print tolower($2);exit}')
  [[ "$er" == no || "$er" == prohibit-password || "$er" == without-password ]] && pass "Effective PermitRootLogin = $er" || { fail 'Effective PermitRootLogin'; actual "${er:-UNKNOWN}"; }
else fail 'sshd command tidak ditemukan'; fi

header "6. AUDITD RULES"
check_rule /etc/audit/rules.d/50-time-change.rules '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change'
check_rule /etc/audit/rules.d/50-time-change.rules '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change'
check_rule /etc/audit/rules.d/50-time-change.rules '-a always,exit -F arch=b64 -S clock_settime -k time-change'
check_rule /etc/audit/rules.d/50-time-change.rules '-a always,exit -F arch=b32 -S clock_settime -k time-change'
check_rule /etc/audit/rules.d/50-time-change.rules '-w /etc/localtime -p wa -k time-change'
for r in '/etc/group' '/etc/passwd' '/etc/gshadow' '/etc/shadow' '/etc/security/opasswd'; do check_rule /etc/audit/rules.d/50-identity.rules "-w $r -p wa -k identity"; done
check_rule /etc/audit/rules.d/50-system-locale.rules '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale'
check_rule /etc/audit/rules.d/50-system-locale.rules '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale'
for r in '/etc/issue' '/etc/issue.net' '/etc/hosts' '/etc/network'; do check_rule /etc/audit/rules.d/50-system-locale.rules "-w $r -p wa -k system-locale"; done
check_rule /etc/audit/rules.d/50-MAC-policy.rules '-w /etc/apparmor/ -p wa -k MAC-policy'
check_rule /etc/audit/rules.d/50-MAC-policy.rules '-w /etc/apparmor.d/ -p wa -k MAC-policy'
for r in '/var/log/faillog' '/var/log/lastlog' '/var/log/tallylog'; do check_rule /etc/audit/rules.d/50-logins.rules "-w $r -p wa -k logins"; done
check_rule /etc/audit/rules.d/50-session.rules '-w /var/run/utmp -p wa -k session'
check_rule /etc/audit/rules.d/50-session.rules '-w /var/log/wtmp -p wa -k logins'
check_rule /etc/audit/rules.d/50-session.rules '-w /var/log/btmp -p wa -k logins'
check_rule /etc/audit/rules.d/50-perm_mod.rules '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod'
check_rule /etc/audit/rules.d/50-perm_mod.rules '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod'
check_rule /etc/audit/rules.d/50-perm_mod.rules '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod'
check_rule /etc/audit/rules.d/50-perm_mod.rules '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod'
check_rule /etc/audit/rules.d/50-perm_mod.rules '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod'
check_rule /etc/audit/rules.d/50-perm_mod.rules '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod'
check_rule /etc/audit/rules.d/50-access.rules '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access'
check_rule /etc/audit/rules.d/50-access.rules '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access'
check_rule /etc/audit/rules.d/50-access.rules '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access'
check_rule /etc/audit/rules.d/50-access.rules '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access'
check_rule /etc/audit/rules.d/50-delete.rules '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete'
check_rule /etc/audit/rules.d/50-delete.rules '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete'
check_rule /etc/audit/rules.d/50-scope.rules '-w /etc/sudoers -p wa -k scope'
check_rule /etc/audit/rules.d/50-scope.rules '-w /etc/sudoers.d/ -p wa -k scope'
check_rule /etc/audit/rules.d/50-actions.rules '-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions'
check_rule /etc/audit/rules.d/50-actions.rules '-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions'
command -v augenrules >/dev/null 2>&1 && { augenrules --check >/dev/null 2>&1 && pass 'Audit rules compilation valid' || fail 'Audit rules compilation invalid'; } || fail 'augenrules tidak ditemukan'

header "7. TMP MOUNT"
check_file /etc/systemd/system/tmp.mount '^[[:space:]]*What[[:space:]]*=[[:space:]]*tmpfs[[:space:]]*$' 'What=tmpfs' What
check_file /etc/systemd/system/tmp.mount '^[[:space:]]*Where[[:space:]]*=[[:space:]]*/tmp[[:space:]]*$' 'Where=/tmp' Where
check_file /etc/systemd/system/tmp.mount '^[[:space:]]*Options[[:space:]]*=[[:space:]]*mode=1777,strictatime,nosuid,nodev,noexec[[:space:]]*$' 'Options=mode=1777,strictatime,nosuid,nodev,noexec' Options
if mountpoint -q /tmp; then
  pass '/tmp is mounted'
  [[ $(findmnt -n -o FSTYPE /tmp 2>/dev/null) == tmpfs ]] && pass '/tmp filesystem = tmpfs' || fail '/tmp filesystem bukan tmpfs'
  for o in nosuid nodev noexec; do check_mount_opt /tmp "$o"; done
  m=$(stat -c '%a' /tmp 2>/dev/null || true); [[ "$m" == 1777 ]] && pass '/tmp permission = 1777' || { fail '/tmp permission'; actual "${m:-UNKNOWN}"; }
else fail '/tmp bukan dedicated mount'; fi

header "8. FSTAB / DEV SHM / VAR TMP"
check_file /etc/fstab '^[[:space:]]*tmpfs[[:space:]]+/dev/shm[[:space:]]+tmpfs[[:space:]]+defaults,noexec,nodev,nosuid,seclabel[[:space:]]+0[[:space:]]+0[[:space:]]*$' 'tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0' /dev/shm
check_file /etc/fstab '^[[:space:]]*/tmp[[:space:]]+/var/tmp[[:space:]]+none[[:space:]]+rw,noexec,nosuid,nodev,bind[[:space:]]+0[[:space:]]+0[[:space:]]*$' '/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0' /var/tmp
findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1 && pass '/etc/fstab syntax valid' || fail '/etc/fstab syntax invalid'
if mountpoint -q /dev/shm; then
  pass '/dev/shm is mounted'
  [[ $(findmnt -n -o FSTYPE /dev/shm 2>/dev/null) == tmpfs ]] && pass '/dev/shm filesystem = tmpfs' || fail '/dev/shm filesystem bukan tmpfs'
  for o in nodev nosuid noexec; do check_mount_opt /dev/shm "$o"; done
  m=$(stat -c '%a' /dev/shm 2>/dev/null || true); [[ "$m" == 1777 ]] && pass '/dev/shm permission = 1777' || { fail '/dev/shm permission'; actual "${m:-UNKNOWN}"; }
else fail '/dev/shm tidak mounted'; fi
if mountpoint -q /var/tmp; then pass '/var/tmp is mounted'; for o in nodev nosuid noexec; do check_mount_opt /var/tmp "$o"; done; else fail '/var/tmp bukan dedicated/bind mount'; fi

header "9. STICKY BIT & WORLD-WRITABLE DIRECTORIES"
unsecured=$(df --local -P 2>/dev/null | awk 'NR>1{print $6}' | sort -u | while read -r fs; do [[ -d "$fs" ]] && find "$fs" -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null; done | sort -u)
[[ -z "$unsecured" ]] && pass 'Tidak ada direktori world-writable tanpa sticky bit' || { fail 'Ditemukan direktori world-writable tanpa sticky bit'; echo "$unsecured"; }

header "10. /ETC/ISSUE PERMISSIONS"
if [[ -e /etc/issue ]]; then
  f=$(readlink -e /etc/issue 2>/dev/null || echo /etc/issue); p=$(stat -c '%U:%G %A' "$f" 2>/dev/null || true)
  [[ "$p" == 'root:root -rw-r--r--' || "$p" == 'root:root -rw-------' ]] && pass "/etc/issue permission aman ($p)" || { fail '/etc/issue permission'; actual "${p:-UNKNOWN}"; }
else fail '/etc/issue tidak ditemukan'; fi

echo -e "\n${CYAN}============================================================${NC}"
echo -e "${CYAN}RINGKASAN HASIL${NC}"
echo -e "${GREEN}TOTAL PASS : $PASS_COUNT${NC}"
echo -e "${RED}TOTAL FAIL : $FAIL_COUNT${NC}"
echo -e "${CYAN}============================================================${NC}"
(( FAIL_COUNT == 0 )) && { echo -e "${GREEN}OVERALL RESULT : PASS${NC}"; exit 0; } || { echo -e "${RED}OVERALL RESULT : FAIL${NC}"; exit 1; }
