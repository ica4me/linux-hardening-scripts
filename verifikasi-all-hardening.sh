bash << 'EOF'
# Definisi Warna
GREEN='\e[0;32m'
RED='\e[0;31m'
CYAN='\e[0;36m'
YELLOW='\e[1;33m'
NC='\e[0m' # No Color

# Inisialisasi Penghitung
count_benar=0
count_salah=0

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}   PENGECEKAN HARDENING (FULL STRICT - EXPECTED vs ACTUAL)${NC}"
echo -e "${CYAN}==========================================================${NC}"

# Fungsi untuk check file (Umum)
check_file() {
    local file=$1
    local regex=$2
    local expected=$3
    local key=$4
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}[❌ SALAH] File $file tidak ditemukan!${NC}"
        ((count_salah++))
        return
    fi
    
    if grep -q -E "$regex" "$file"; then
        echo -e "${GREEN}[✅ BENAR] $expected${NC}"
        ((count_benar++))
    else
        echo -e "${RED}[❌ SALAH] Konfigurasi tidak sesuai pada file $file${NC}"
        echo -e "   ${CYAN}Expected : $expected${NC}"
        
        local actual=$(grep -E "^[[:space:]]*$key" "$file" | head -n 1)
        if [ -z "$actual" ]; then
            actual=$(grep -E "$key" "$file" | grep -v "^#" | head -n 1)
        fi
        
        if [ -z "$actual" ]; then
             echo -e "   ${YELLOW}Actual   : (Parameter '$key' tidak ditemukan / dikomentari '#' )${NC}"
        else
             actual=$(echo "$actual" | tr -s ' ' | sed 's/^[ \t]*//')
             echo -e "   ${YELLOW}Actual   : $actual${NC}"
        fi
        ((count_salah++))
    fi
}

# Fungsi spesifik untuk check file auditd rules (Baris per Baris)
check_audit_rule() {
    local file=$1
    local expected=$2
    local key=$3
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}[❌ SALAH] File $file tidak ditemukan!${NC}"
        ((count_salah++))
        return
    fi
    
    # Ubah format expected menjadi regex aman (escape dot & bracket, ubah spasi jadi dinamis)
    local regex="^[[:space:]]*$(echo "$expected" | sed -e 's/\./\\./g' -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/ /[[:space:]]+/g')"
    
    if grep -q -E "$regex" "$file"; then
        echo -e "${GREEN}[✅ BENAR] $expected${NC}"
        ((count_benar++))
    else
        echo -e "${RED}[❌ SALAH] Rule tidak sesuai / hilang di $file${NC}"
        echo -e "   ${CYAN}Expected : $expected${NC}"
        
        local actual=$(grep -E "$key" "$file" | head -n 1)
        if [ -z "$actual" ]; then
            echo -e "   ${YELLOW}Actual   : (Baris rule dengan kunci '$key' tidak ditemukan)${NC}"
        else
            actual=$(echo "$actual" | tr -s ' ' | sed 's/^[ \t]*//')
            echo -e "   ${YELLOW}Actual   : $actual${NC}"
        fi
        ((count_salah++))
    fi
}

echo -e "\n${CYAN}--- 1. PWQUALITY (/etc/security/pwquality.conf) ---${NC}"
check_file "/etc/security/pwquality.conf" "^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14" "minlen = 14" "minlen"
check_file "/etc/security/pwquality.conf" "^[[:space:]]*dcredit[[:space:]]*=[[:space:]]*-1" "dcredit = -1" "dcredit"
check_file "/etc/security/pwquality.conf" "^[[:space:]]*ucredit[[:space:]]*=[[:space:]]*-1" "ucredit = -1" "ucredit"
check_file "/etc/security/pwquality.conf" "^[[:space:]]*ocredit[[:space:]]*=[[:space:]]*-1" "ocredit = -1" "ocredit"
check_file "/etc/security/pwquality.conf" "^[[:space:]]*lcredit[[:space:]]*=[[:space:]]*-1" "lcredit = -1" "lcredit"

echo -e "\n${CYAN}--- 2. LOGIN.DEFS (/etc/login.defs) ---${NC}"
check_file "/etc/login.defs" "^[[:space:]]*PASS_MAX_DAYS[[:space:]]+90" "PASS_MAX_DAYS 90" "PASS_MAX_DAYS"
check_file "/etc/login.defs" "^[[:space:]]*PASS_MIN_DAYS[[:space:]]+1" "PASS_MIN_DAYS 1" "PASS_MIN_DAYS"
check_file "/etc/login.defs" "^[[:space:]]*PASS_WARN_AGE[[:space:]]+7" "PASS_WARN_AGE 7" "PASS_WARN_AGE"

echo -e "\n${CYAN}--- 3. FAILLOCK (/etc/security/faillock.conf) ---${NC}"
check_file "/etc/security/faillock.conf" "^[[:space:]]*deny[[:space:]]*=[[:space:]]*3" "deny = 3" "deny"
check_file "/etc/security/faillock.conf" "^[[:space:]]*fail_interval[[:space:]]*=[[:space:]]*900" "fail_interval = 900" "fail_interval"
check_file "/etc/security/faillock.conf" "^[[:space:]]*unlock_time[[:space:]]*=[[:space:]]*1800" "unlock_time = 1800" "unlock"

echo -e "\n${CYAN}--- 4. PAM CONFIGURATION (/etc/pam.d/) ---${NC}"
check_file "/etc/pam.d/common-password" "^[[:space:]]*password[[:space:]]+required[[:space:]]+pam_pwhistory\.so[[:space:]]+remember=5" "password required pam_pwhistory.so remember=5" "pam_pwhistory.so"
check_file "/etc/pam.d/common-password" "^[[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so[[:space:]]+retry=5" "password requisite pam_pwquality.so retry=5" "pam_pwquality.so"
check_file "/etc/pam.d/common-auth" "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth" "auth required pam_faillock.so preauth" "pam_faillock.so preauth"
check_file "/etc/pam.d/common-auth" "^[[:space:]]*auth[[:space:]]+\[success=1[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so[[:space:]]+nullok" "auth [success=1 default=ignore] pam_unix.so nullok" "pam_unix.so nullok"
check_file "/etc/pam.d/common-account" "^[[:space:]]*account[[:space:]]+\[success=1[[:space:]]+new_authtok_reqd=done[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so" "account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so" "pam_unix.so"

echo -e "\n${CYAN}--- 5. SSHD CONFIGURATION (/etc/ssh/sshd_config) ---${NC}"
if [ -f "/etc/ssh/sshd_config" ]; then
    actual_perm=$(stat -c "%U:%G %a" /etc/ssh/sshd_config 2>/dev/null)
    if [ "$actual_perm" == "root:root 600" ]; then
        echo -e "${GREEN}[✅ BENAR] Permission sshd_config adalah root:root 600${NC}"
        ((count_benar++))
    else
        echo -e "${RED}[❌ SALAH] Permission /etc/ssh/sshd_config salah!${NC}"
        echo -e "   ${CYAN}Expected : root:root 600${NC}"
        echo -e "   ${YELLOW}Actual   : $actual_perm${NC}"
        ((count_salah++))
    fi
else
    echo -e "${RED}[❌ SALAH] File /etc/ssh/sshd_config tidak ditemukan!${NC}"
    ((count_salah++))
fi

check_file "/etc/ssh/sshd_config" "^[[:space:]]*Protocol[[:space:]]+2" "Protocol 2" "Protocol"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*LogLevel[[:space:]]+VERBOSE" "LogLevel VERBOSE" "LogLevel"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*LoginGraceTime[[:space:]]+60" "LoginGraceTime 60" "LoginGraceTime"
# Bagian ini sudah diedit agar membolehkan prohibit-password
check_file "/etc/ssh/sshd_config" "^[[:space:]]*PermitRootLogin[[:space:]]+prohibit-password" "PermitRootLogin prohibit-password" "PermitRootLogin"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*MaxAuthTries[[:space:]]+4" "MaxAuthTries 4" "MaxAuthTries"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*PermitEmptyPasswords[[:space:]]+no" "PermitEmptyPasswords no" "PermitEmptyPasswords"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*AllowTcpForwarding[[:space:]]+no" "AllowTcpForwarding no" "AllowTcpForwarding"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*X11Forwarding[[:space:]]+no" "X11Forwarding no" "X11Forwarding"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*ClientAliveInterval[[:space:]]+300" "ClientAliveInterval 300" "ClientAliveInterval"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*ClientAliveCountMax[[:space:]]+3" "ClientAliveCountMax 3" "ClientAliveCountMax"
check_file "/etc/ssh/sshd_config" "^[[:space:]]*MaxStartups[[:space:]]+10:30:60" "MaxStartups 10:30:60" "MaxStartups"

echo -e "\n${CYAN}--- 6. AUDITD RULES (PENGECEKAN PER BARIS) ---${NC}"
echo -e "${YELLOW}>> 50-time-change.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-time-change.rules" "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" "adjtimex.*b64"
check_audit_rule "/etc/audit/rules.d/50-time-change.rules" "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" "adjtimex.*b32"
check_audit_rule "/etc/audit/rules.d/50-time-change.rules" "-a always,exit -F arch=b64 -S clock_settime -k time-change" "clock_settime.*b64"
check_audit_rule "/etc/audit/rules.d/50-time-change.rules" "-a always,exit -F arch=b32 -S clock_settime -k time-change" "clock_settime.*b32"
check_audit_rule "/etc/audit/rules.d/50-time-change.rules" "-w /etc/localtime -p wa -k time-change" "/etc/localtime"

echo -e "\n${YELLOW}>> 50-identity.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-identity.rules" "-w /etc/group -p wa -k identity" "/etc/group"
check_audit_rule "/etc/audit/rules.d/50-identity.rules" "-w /etc/passwd -p wa -k identity" "/etc/passwd"
check_audit_rule "/etc/audit/rules.d/50-identity.rules" "-w /etc/gshadow -p wa -k identity" "/etc/gshadow"
check_audit_rule "/etc/audit/rules.d/50-identity.rules" "-w /etc/shadow -p wa -k identity" "/etc/shadow"
check_audit_rule "/etc/audit/rules.d/50-identity.rules" "-w /etc/security/opasswd -p wa -k identity" "/etc/security/opasswd"

echo -e "\n${YELLOW}>> 50-system-locale.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-system-locale.rules" "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" "sethostname.*b64"
check_audit_rule "/etc/audit/rules.d/50-system-locale.rules" "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" "sethostname.*b32"
check_audit_rule "/etc/audit/rules.d/50-system-locale.rules" "-w /etc/issue -p wa -k system-locale" "/etc/issue"
check_audit_rule "/etc/audit/rules.d/50-system-locale.rules" "-w /etc/issue.net -p wa -k system-locale" "/etc/issue.net"
check_audit_rule "/etc/audit/rules.d/50-system-locale.rules" "-w /etc/hosts -p wa -k system-locale" "/etc/hosts"
check_audit_rule "/etc/audit/rules.d/50-system-locale.rules" "-w /etc/network -p wa -k system-locale" "/etc/network"

echo -e "\n${YELLOW}>> 50-MAC-policy.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-MAC-policy.rules" "-w /etc/apparmor/ -p wa -k MAC-policy" "/etc/apparmor/"
check_audit_rule "/etc/audit/rules.d/50-MAC-policy.rules" "-w /etc/apparmor.d/ -p wa -k MAC-policy" "/etc/apparmor.d/"

echo -e "\n${YELLOW}>> 50-logins.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-logins.rules" "-w /var/log/faillog -p wa -k logins" "/var/log/faillog"
check_audit_rule "/etc/audit/rules.d/50-logins.rules" "-w /var/log/lastlog -p wa -k logins" "/var/log/lastlog"
check_audit_rule "/etc/audit/rules.d/50-logins.rules" "-w /var/log/tallylog -p wa -k logins" "/var/log/tallylog"

echo -e "\n${YELLOW}>> 50-session.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-session.rules" "-w /var/run/utmp -p wa -k session" "/var/run/utmp"
check_audit_rule "/etc/audit/rules.d/50-session.rules" "-w /var/log/wtmp -p wa -k logins" "/var/log/wtmp"
check_audit_rule "/etc/audit/rules.d/50-session.rules" "-w /var/log/btmp -p wa -k logins" "/var/log/btmp"

echo -e "\n${YELLOW}>> 50-perm_mod.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-perm_mod.rules" "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" "chmod.*b64"
check_audit_rule "/etc/audit/rules.d/50-perm_mod.rules" "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" "chmod.*b32"
check_audit_rule "/etc/audit/rules.d/50-perm_mod.rules" "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" "chown.*b64"
check_audit_rule "/etc/audit/rules.d/50-perm_mod.rules" "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" "chown.*b32"
check_audit_rule "/etc/audit/rules.d/50-perm_mod.rules" "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" "setxattr.*b64"
check_audit_rule "/etc/audit/rules.d/50-perm_mod.rules" "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" "setxattr.*b32"

echo -e "\n${YELLOW}>> 50-access.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-access.rules" "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" "EACCES.*b64"
check_audit_rule "/etc/audit/rules.d/50-access.rules" "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" "EACCES.*b32"
check_audit_rule "/etc/audit/rules.d/50-access.rules" "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" "EPERM.*b64"
check_audit_rule "/etc/audit/rules.d/50-access.rules" "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" "EPERM.*b32"

echo -e "\n${YELLOW}>> 50-delete.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-delete.rules" "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" "unlink.*b64"
check_audit_rule "/etc/audit/rules.d/50-delete.rules" "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" "unlink.*b32"

echo -e "\n${YELLOW}>> 50-scope.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-scope.rules" "-w /etc/sudoers -p wa -k scope" "/etc/sudoers"
check_audit_rule "/etc/audit/rules.d/50-scope.rules" "-w /etc/sudoers.d/ -p wa -k scope" "/etc/sudoers.d/"

echo -e "\n${YELLOW}>> 50-actions.rules${NC}"
check_audit_rule "/etc/audit/rules.d/50-actions.rules" "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions" "execve.*b64"
check_audit_rule "/etc/audit/rules.d/50-actions.rules" "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions" "execve.*b32"

echo -e "\n${CYAN}--- 7. TMP MOUNT (/etc/systemd/system/tmp.mount) ---${NC}"
check_file "/etc/systemd/system/tmp.mount" "^[[:space:]]*What=tmpfs" "What=tmpfs" "What"
check_file "/etc/systemd/system/tmp.mount" "^[[:space:]]*Where=/tmp" "Where=/tmp" "Where"
check_file "/etc/systemd/system/tmp.mount" "^[[:space:]]*Options=mode=1777,strictatime,nosuid,nodev,noexec" "Options=mode=1777,strictatime,nosuid,nodev,noexec" "Options"

echo -e "\n${CYAN}--- 8. FSTAB (/etc/fstab) ---${NC}"
check_file "/etc/fstab" "^[[:space:]]*tmpfs[[:space:]]+/dev/shm[[:space:]]+tmpfs[[:space:]]+defaults,noexec,nodev,nosuid,seclabel[[:space:]]+0[[:space:]]+0" "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" "/dev/shm"
check_file "/etc/fstab" "^[[:space:]]*/tmp[[:space:]]+/var/tmp[[:space:]]+none[[:space:]]+rw,noexec,nosuid,nodev,bind[[:space:]]+0[[:space:]]+0" "/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0" "/var/tmp"

echo -e "\n${CYAN}--- 9. STICKY BIT & WORLD WRITABLE DIRECTORIES ---${NC}"
unsecured_dirs=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)
if [ -z "$unsecured_dirs" ]; then
    echo -e "${GREEN}[✅ BENAR] Tidak ada direktori world-writable tanpa sticky bit.${NC}"
    ((count_benar++))
else
    echo -e "${RED}[❌ SALAH] Ditemukan direktori world-writable tanpa sticky bit:${NC}"
    echo -e "   ${CYAN}Expected : (Tidak ada / kosong)${NC}"
    echo -e "   ${YELLOW}Actual   :\n$unsecured_dirs${NC}"
    ((count_salah++))
fi

echo -e "\n${CYAN}--- 10. /ETC/ISSUE PERMISSIONS ---${NC}"
if [ -f /etc/issue ]; then
    issue_perm=$(stat -c "%U:%G %A" $(readlink -e /etc/issue))
    if [[ "$issue_perm" == "root:root -rw-r--r--" || "$issue_perm" == "root:root -rw-------" ]]; then
        echo -e "${GREEN}[✅ BENAR] Permission /etc/issue aman ($issue_perm)${NC}"
        ((count_benar++))
    else
        echo -e "${RED}[❌ SALAH] Permission /etc/issue saat ini salah!${NC}"
        echo -e "   ${CYAN}Expected : root:root -rw-r--r-- (atau -rw-------)${NC}"
        echo -e "   ${YELLOW}Actual   : $issue_perm${NC}"
        ((count_salah++))
    fi
else
    echo -e "${RED}[❌ SALAH] File /etc/issue tidak ditemukan!${NC}"
    ((count_salah++))
fi

echo -e "\n${CYAN}==========================================================${NC}"
echo -e "${CYAN}                 RINGKASAN HASIL                          ${NC}"
echo -e "${CYAN}==========================================================${NC}"
echo -e "${GREEN}  TOTAL BENAR : $count_benar ${NC}"
echo -e "${RED}  TOTAL SALAH : $count_salah ${NC}"
echo -e "${CYAN}==========================================================${NC}"
EOF