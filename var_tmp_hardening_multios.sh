#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform /var/tmp hardening using a bind mount from /tmp.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Policy:
# - /var/tmp is bind-mounted from /tmp
# - rw, nodev, nosuid, noexec
# - owner root:root
# - mode 1777
# - persistent through /etc/fstab
#
# IMPORTANT:
# This policy intentionally makes /var/tmp use the same backing storage as /tmp.
# If /tmp is tmpfs, /var/tmp will also become non-persistent across reboot.

FSTAB="/etc/fstab"
TMP_DIR="/tmp"
VAR_TMP_DIR="/var/tmp"

BACKUP_ROOT="/var/backups/var-tmp-hardening"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."
[[ -f "${FSTAB}" ]] || fail "${FSTAB} not found."
[[ -d "${TMP_DIR}" ]] || fail "${TMP_DIR} not found."

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

for cmd in findmnt mount mountpoint stat awk; do
    command -v "${cmd}" >/dev/null 2>&1 ||
        fail "${cmd} not found."
done

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying /var/tmp Hardening ==="

mkdir -p "${BACKUP_DIR}"
cp -a "${FSTAB}" "${BACKUP_DIR}/fstab"

findmnt "${VAR_TMP_DIR}" > "${BACKUP_DIR}/var-tmp-findmnt-before.txt" 2>/dev/null || true
findmnt "${TMP_DIR}" > "${BACKUP_DIR}/tmp-findmnt-before.txt" 2>/dev/null || true

mkdir -p "${VAR_TMP_DIR}"
chmod 1777 "${VAR_TMP_DIR}"
chown root:root "${VAR_TMP_DIR}"

log "Backup created: ${BACKUP_DIR}"

# Remove all active /var/tmp entries from fstab to keep the configuration
# deterministic and idempotent. Commented entries are preserved.
awk '
    /^[[:space:]]*#/ { print; next }
    NF >= 2 && $2 == "/var/tmp" { next }
    { print }
' "${FSTAB}" > "${FSTAB}.tmp"

cat >> "${FSTAB}.tmp" <<'EOF'

# Hardened /var/tmp bind mount
/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0
EOF

chown --reference="${FSTAB}" "${FSTAB}.tmp" 2>/dev/null || chown root:root "${FSTAB}.tmp"
chmod --reference="${FSTAB}" "${FSTAB}.tmp" 2>/dev/null || chmod 0644 "${FSTAB}.tmp"
mv "${FSTAB}.tmp" "${FSTAB}"

findmnt --verify --tab-file "${FSTAB}" >/dev/null ||
    fail "/etc/fstab validation failed."

same_bind_target() {
    local src_id dst_id

    src_id="$(stat -Lc '%d:%i' "${TMP_DIR}" 2>/dev/null || true)"
    dst_id="$(stat -Lc '%d:%i' "${VAR_TMP_DIR}" 2>/dev/null || true)"

    [[ -n "${src_id}" && "${src_id}" == "${dst_id}" ]]
}

# Safety: never unmount an unrelated existing /var/tmp mount automatically.
if mountpoint -q "${VAR_TMP_DIR}"; then
    if same_bind_target; then
        log "${VAR_TMP_DIR} is already bind-mounted from ${TMP_DIR}."
    else
        CURRENT_SOURCE="$(findmnt -n -o SOURCE "${VAR_TMP_DIR}" 2>/dev/null || true)"
        CURRENT_FSTYPE="$(findmnt -n -o FSTYPE "${VAR_TMP_DIR}" 2>/dev/null || true)"

        fail "${VAR_TMP_DIR} is already an unrelated mount (source=${CURRENT_SOURCE:-UNKNOWN}, fstype=${CURRENT_FSTYPE:-UNKNOWN}). Refusing to unmount it automatically."
    fi
else
    mount --bind "${TMP_DIR}" "${VAR_TMP_DIR}" ||
        fail "Failed to bind mount ${TMP_DIR} to ${VAR_TMP_DIR}."
fi

# Apply independent VFS security flags to the bind mount.
mount -o remount,bind,rw,noexec,nosuid,nodev "${VAR_TMP_DIR}" ||
    fail "Failed to apply security mount options to ${VAR_TMP_DIR}."

chmod 1777 "${VAR_TMP_DIR}"
chown root:root "${VAR_TMP_DIR}"

# Runtime validation.
mountpoint -q "${VAR_TMP_DIR}" ||
    fail "${VAR_TMP_DIR} is not mounted."

same_bind_target ||
    fail "${VAR_TMP_DIR} is not bind-mounted from ${TMP_DIR}."

OPTIONS="$(findmnt -n -o OPTIONS "${VAR_TMP_DIR}" 2>/dev/null || true)"

for option in nodev nosuid noexec; do
    if ! grep -qw "${option}" <<< "${OPTIONS//,/ }"; then
        fail "${VAR_TMP_DIR} missing runtime option: ${option}"
    fi
done

OWNER="$(stat -c '%U:%G' "${VAR_TMP_DIR}" 2>/dev/null || true)"
MODE="$(stat -c '%a' "${VAR_TMP_DIR}" 2>/dev/null || true)"

[[ "${OWNER}" == "root:root" ]] ||
    fail "${VAR_TMP_DIR} owner is ${OWNER:-UNKNOWN}, expected root:root."

[[ "${MODE}" == "1777" ]] ||
    fail "${VAR_TMP_DIR} permission is ${MODE:-UNKNOWN}, expected 1777."

TMP_FSTYPE="$(findmnt -n -o FSTYPE "${TMP_DIR}" 2>/dev/null || true)"
VAR_TMP_FSTYPE="$(findmnt -n -o FSTYPE "${VAR_TMP_DIR}" 2>/dev/null || true)"

if [[ -n "${TMP_FSTYPE}" && "${TMP_FSTYPE}" == "${VAR_TMP_FSTYPE}" ]]; then
    log "${VAR_TMP_DIR} filesystem matches ${TMP_DIR}: ${TMP_FSTYPE}"
else
    warn "Unable to confirm matching filesystem type: /tmp=${TMP_FSTYPE:-UNKNOWN}, /var/tmp=${VAR_TMP_FSTYPE:-UNKNOWN}"
fi

log "=== /var/tmp Hardening Applied Successfully ==="
log "Backup location: ${BACKUP_DIR}"
log "Run /root/var_tmp_hardening_verifikasi.sh"
