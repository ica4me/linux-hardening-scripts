#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform login banner hardening.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Policy:
# - Replace /etc/issue with the approved DATACOMM usage warning
# - Remove OS/version disclosure from the local login banner
# - Owner: root:root
# - Permission: 0644

ISSUE="/etc/issue"
BACKUP_ROOT="/var/backups/login-banner"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log()  { echo "[INFO] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"

case "${OS_ID}" in
    ubuntu)
        [[ "${OS_VER}" == "22.04" || "${OS_VER}" == "24.04" ]] ||
            fail "Unsupported Ubuntu version: ${OS_VER}"
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] ||
            fail "Unsupported Debian version: ${OS_VER}"
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] ||
            fail "Unsupported RHEL version: ${OS_VER}"
        ;;
    *)
        fail "Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        ;;
esac

for cmd in stat readlink grep; do
    command -v "${cmd}" >/dev/null 2>&1 ||
        fail "${cmd} not found."
done

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying Login Banner Hardening ==="

mkdir -p "${BACKUP_DIR}"

# Preserve the current file content even if /etc/issue is a symlink.
if [[ -e "${ISSUE}" || -L "${ISSUE}" ]]; then
    cp -aL "${ISSUE}" "${BACKUP_DIR}/issue"
fi

log "Backup created: ${BACKUP_DIR}"

# If /etc/issue is a broken symlink, replace it with a regular managed file.
if [[ -L "${ISSUE}" && ! -e "${ISSUE}" ]]; then
    rm -f "${ISSUE}"
fi

cat > "${ISSUE}" <<'BANNER'
==========================================================================
                            ****USAGE WARNING****
                         DATACOMM PRIVATE PROPRIETARY

This is a private computer system. This computer system, including all
related equipment, networks, and network devices (specifically including
Internet access) are provided only for authorized use. This computer
system may be monitored for all lawful purposes, including to ensure
that its use is authorized, for management of the system, to facilitate
protection against unauthorized access, and to verify security
procedures, survivability, and operational security. Monitoring includes
active attacks by authorized entities to test or verify the security of
this system. During monitoring, information may be examined, recorded,
copied and used for authorized purposes. All information, including
personal information, placed or sent over this system may be monitored.

Use of this computer system, authorized or unauthorized, constitutes
consent to monitoring of this system. Unauthorized use may subject you to
criminal prosecution. Evidence of unauthorized use collected during
monitoring may be used for administrative, criminal, or other adverse
action. Use of this system constitutes consent to monitoring for these
purposes.

==========================================================================
BANNER

REAL_ISSUE="$(readlink -e "${ISSUE}" 2>/dev/null || true)"
[[ -n "${REAL_ISSUE}" && -f "${REAL_ISSUE}" ]] ||
    fail "Unable to resolve ${ISSUE}."

chown root:root "${REAL_ISSUE}"
chmod 0644 "${REAL_ISSUE}"

# Validate required content.
grep -Fq "USAGE WARNING" "${REAL_ISSUE}" ||
    fail "Usage warning text missing."

grep -Fq "DATACOMM PRIVATE PROPRIETARY" "${REAL_ISSUE}" ||
    fail "DATACOMM proprietary notice missing."

grep -Fq "consent to monitoring" "${REAL_ISSUE}" ||
    fail "Monitoring consent notice missing."

# The managed banner must not expose common OS/version escape sequences.
if grep -Eq '\\[nrlmsSv]' "${REAL_ISSUE}"; then
    fail "OS/login escape sequence detected in ${ISSUE}."
fi

log "=== Login Banner Hardening Applied Successfully ==="
log "Backup location: ${BACKUP_DIR}"
log "Run /root/login_banner_verifikasi.sh"
