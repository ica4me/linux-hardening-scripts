#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform /dev/shm hardening.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Policy:
# - /dev/shm remains tmpfs
# - nodev, nosuid, noexec
# - mode 1777
# - persistent through /etc/fstab

FSTAB="/etc/fstab"
SHM="/dev/shm"

BACKUP_ROOT="/var/backups/shm-hardening"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log()  { echo "[INFO] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."
[[ -f "${FSTAB}" ]] || fail "${FSTAB} not found."

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

for cmd in findmnt mount mountpoint stat; do
    command -v "${cmd}" >/dev/null 2>&1 ||
        fail "${cmd} not found."
done

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying /dev/shm Hardening ==="

mkdir -p "${BACKUP_DIR}"

cp -a "${FSTAB}" "${BACKUP_DIR}/fstab"
findmnt "${SHM}" > "${BACKUP_DIR}/shm-findmnt-before.txt" 2>/dev/null || true
mount | grep -E ' on /dev/shm ' > "${BACKUP_DIR}/shm-mount-before.txt" 2>/dev/null || true

log "Backup created: ${BACKUP_DIR}"

# Remove all active /dev/shm entries from fstab to keep the configuration
# deterministic and idempotent. Commented entries are preserved.
awk '
    /^[[:space:]]*#/ { print; next }
    NF >= 2 && $2 == "/dev/shm" { next }
    { print }
' "${FSTAB}" > "${FSTAB}.tmp"

cat >> "${FSTAB}.tmp" <<'EOF'

# Hardened shared memory
tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0
EOF

chown --reference="${FSTAB}" "${FSTAB}.tmp" 2>/dev/null || chown root:root "${FSTAB}.tmp"
chmod --reference="${FSTAB}" "${FSTAB}.tmp" 2>/dev/null || chmod 0644 "${FSTAB}.tmp"
mv "${FSTAB}.tmp" "${FSTAB}"

# Validate fstab before changing the runtime mount.
findmnt --verify --tab-file "${FSTAB}" >/dev/null ||
    fail "/etc/fstab validation failed."

mkdir -p "${SHM}"

if mountpoint -q "${SHM}"; then
    FSTYPE="$(findmnt -n -o FSTYPE "${SHM}" 2>/dev/null || true)"

    [[ "${FSTYPE}" == "tmpfs" ]] ||
        fail "${SHM} is mounted as ${FSTYPE:-UNKNOWN}, expected tmpfs."

    mount -o remount,defaults,noexec,nodev,nosuid,seclabel "${SHM}" ||
        fail "Failed to remount ${SHM}."
else
    mount "${SHM}" ||
        fail "Failed to mount ${SHM} from /etc/fstab."
fi

chown root:root "${SHM}"
chmod 1777 "${SHM}"

# Runtime validation.
FSTYPE="$(findmnt -n -o FSTYPE "${SHM}" 2>/dev/null || true)"
OPTIONS="$(findmnt -n -o OPTIONS "${SHM}" 2>/dev/null || true)"

[[ "${FSTYPE}" == "tmpfs" ]] ||
    fail "${SHM} filesystem is ${FSTYPE:-UNKNOWN}, expected tmpfs."

for option in nodev nosuid noexec; do
    if ! grep -qw "${option}" <<< "${OPTIONS//,/ }"; then
        fail "${SHM} missing runtime option: ${option}"
    fi
done

MODE="$(stat -c '%a' "${SHM}" 2>/dev/null || true)"
OWNER="$(stat -c '%U:%G' "${SHM}" 2>/dev/null || true)"

[[ "${MODE}" == "1777" ]] ||
    fail "${SHM} permission is ${MODE:-UNKNOWN}, expected 1777."

[[ "${OWNER}" == "root:root" ]] ||
    fail "${SHM} owner is ${OWNER:-UNKNOWN}, expected root:root."

log "=== /dev/shm Hardening Applied Successfully ==="
log "Backup location: ${BACKUP_DIR}"
log "Run /root/shm_hardening_verifikasi.sh"
