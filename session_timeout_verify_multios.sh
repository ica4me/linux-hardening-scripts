#!/usr/bin/env bash
set -u

# Ubuntu 22.04 SSH hardening verification.
# Read-only; does not modify SSH configuration.

SSHD_CONFIG="/etc/ssh/sshd_config"
PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

[[ -r /etc/os-release ]] || { echo "[FAIL] /etc/os-release not found"; exit 1; }
. /etc/os-release
[[ "${ID,,}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] || { echo "[FAIL] This verifier is intended for Ubuntu 22.04 LTS."; exit 1; }

SSHD_BIN="$(command -v sshd || true)"
[[ -n "${SSHD_BIN}" ]] || SSHD_BIN="/usr/sbin/sshd"

echo "============================================================"
echo " Ubuntu 22.04 SSH Hardening Verification"
echo "============================================================"
echo

echo "--- File Security ---"
OWNER="$(stat -c '%U:%G' "${SSHD_CONFIG}" 2>/dev/null)"
MODE="$(stat -c '%a' "${SSHD_CONFIG}" 2>/dev/null)"
[[ "${OWNER}" == "root:root" ]] && pass "sshd_config owner = root:root" || fail "sshd_config owner = ${OWNER:-UNKNOWN}"
[[ "${MODE}" == "600" ]] && pass "sshd_config permission = 600" || fail "sshd_config permission = ${MODE:-UNKNOWN}"

echo
echo "--- Syntax & Service ---"
[[ -x "${SSHD_BIN}" ]] && "${SSHD_BIN}" -t 2>/dev/null && pass "sshd configuration syntax valid" || fail "sshd configuration syntax invalid"
systemctl is-active --quiet ssh && pass "ssh service active" || fail "ssh service inactive"

echo
echo "--- Main /etc/ssh/sshd_config ---"
check_main() {
    local regex="$1" description="$2"
    grep -Eq "${regex}" "${SSHD_CONFIG}" && pass "${description}" || fail "${description}"
}

check_main '^[[:space:]]*Ciphers[[:space:]]+aes128-ctr,aes192-ctr,aes256-ctr[[:space:]]*$' "Ciphers configured"
check_main '^[[:space:]]*MACs[[:space:]]+hmac-sha2-512-etm@openssh\.com,hmac-sha2-256-etm@openssh\.com,hmac-sha2-512,hmac-sha2-256[[:space:]]*$' "MACs configured"
check_main '^[[:space:]]*KexAlgorithms[[:space:]]+curve25519-sha256@libssh\.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256[[:space:]]*$' "KexAlgorithms configured"
check_main '^[[:space:]]*LogLevel[[:space:]]+VERBOSE[[:space:]]*$' "LogLevel = VERBOSE"
check_main '^[[:space:]]*LoginGraceTime[[:space:]]+60[[:space:]]*$' "LoginGraceTime = 60"
check_main '^[[:space:]]*PermitRootLogin[[:space:]]+prohibit-password[[:space:]]*$' "PermitRootLogin = prohibit-password"
check_main '^[[:space:]]*MaxAuthTries[[:space:]]+4[[:space:]]*$' "MaxAuthTries = 4"
check_main '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no[[:space:]]*$' "PermitEmptyPasswords = no"
check_main '^[[:space:]]*AllowTcpForwarding[[:space:]]+no[[:space:]]*$' "AllowTcpForwarding = no"
check_main '^[[:space:]]*X11Forwarding[[:space:]]+no[[:space:]]*$' "X11Forwarding = no"
check_main '^[[:space:]]*ClientAliveInterval[[:space:]]+300[[:space:]]*$' "ClientAliveInterval = 300"
check_main '^[[:space:]]*ClientAliveCountMax[[:space:]]+3[[:space:]]*$' "ClientAliveCountMax = 3"
check_main '^[[:space:]]*MaxStartups[[:space:]]+10:30:60[[:space:]]*$' "MaxStartups = 10:30:60"

if grep -Eq '^[[:space:]]*Protocol[[:space:]]+' "${SSHD_CONFIG}"; then
    fail "Legacy Protocol directive is present"
else
    pass "No legacy Protocol directive (OpenSSH 8.9 is SSHv2-only)"
fi

echo
echo "--- Effective SSH Configuration ---"
EFFECTIVE="$("${SSHD_BIN}" -T 2>/dev/null || true)"
check_effective() {
    local regex="$1" description="$2"
    grep -Eq "${regex}" <<< "${EFFECTIVE}" && pass "${description}" || fail "${description}"
}

check_effective '^ciphers aes128-ctr,aes192-ctr,aes256-ctr$' "Effective Ciphers correct"
check_effective '^macs hmac-sha2-512-etm@openssh\.com,hmac-sha2-256-etm@openssh\.com,hmac-sha2-512,hmac-sha2-256$' "Effective MACs correct"
check_effective '^kexalgorithms curve25519-sha256@libssh\.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256$' "Effective KexAlgorithms correct"
check_effective '^loglevel verbose$' "Effective LogLevel = VERBOSE"
check_effective '^logingracetime 60$' "Effective LoginGraceTime = 60"
check_effective '^permitrootlogin (prohibit-password|without-password)$' "Effective PermitRootLogin = prohibit-password"
check_effective '^maxauthtries 4$' "Effective MaxAuthTries = 4"
check_effective '^permitemptypasswords no$' "Effective PermitEmptyPasswords = no"
check_effective '^allowtcpforwarding no$' "Effective AllowTcpForwarding = no"
check_effective '^x11forwarding no$' "Effective X11Forwarding = no"
check_effective '^clientaliveinterval 300$' "Effective ClientAliveInterval = 300"
check_effective '^clientalivecountmax 3$' "Effective ClientAliveCountMax = 3"
check_effective '^maxstartups 10:30:60$' "Effective MaxStartups = 10:30:60"

echo
echo "--- ClientAlive Lines ---"
grep -E '^[[:space:]]*ClientAlive' "${SSHD_CONFIG}" || true

echo
echo "============================================================"
if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "============================================================"
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "============================================================"
    exit 1
fi
