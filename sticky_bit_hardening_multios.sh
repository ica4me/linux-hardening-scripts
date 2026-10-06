#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform sticky-bit hardening.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Policy:
# Every world-writable directory on supported local filesystems
# must have the sticky bit set.
#
# The script does not change ownership and does not remove write access.
# It only adds the sticky bit where required.

SUPPORTED_FS_REGEX='^(ext2|ext3|ext4|xfs|btrfs|tmpfs)$'

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

for cmd in findmnt find chmod stat sort awk; do
    command -v "${cmd}" >/dev/null 2>&1 ||
        fail "${cmd} not found."
done

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "=== Applying Sticky Bit Hardening ==="

FIXED=0
SCANNED_MOUNTS=0

# Build a unique list of eligible local mount points.
mapfile -t MOUNTPOINTS < <(
    findmnt -rn -o TARGET,FSTYPE 2>/dev/null |
    awk -v re="${SUPPORTED_FS_REGEX}" '
        $2 ~ re {
            $1=$1
            print $1
        }
    ' |
    sort -u
)

if (( ${#MOUNTPOINTS[@]} == 0 )); then
    fail "No supported local filesystems found."
fi

for mountpoint in "${MOUNTPOINTS[@]}"; do
    [[ -d "${mountpoint}" ]] || continue
    SCANNED_MOUNTS=$((SCANNED_MOUNTS + 1))

    while IFS= read -r -d '' dir; do
        chmod a+t -- "${dir}"
        MODE="$(stat -c '%a' "${dir}" 2>/dev/null || true)"
        echo "[FIXED] ${dir} mode=${MODE:-UNKNOWN}"
        FIXED=$((FIXED + 1))
    done < <(
        find "${mountpoint}" \
            -xdev \
            -type d \
            -perm -0002 \
            ! -perm -1000 \
            -print0 2>/dev/null
    )
done

# Explicitly enforce sticky bit on the critical temporary directories
# when they are world-writable.
for dir in /tmp /var/tmp /dev/shm; do
    [[ -d "${dir}" ]] || continue

    if find "${dir}" -maxdepth 0 -type d -perm -0002 ! -perm -1000 -print -quit 2>/dev/null |
       grep -q .; then
        chmod a+t -- "${dir}"
        MODE="$(stat -c '%a' "${dir}" 2>/dev/null || true)"
        echo "[FIXED] ${dir} mode=${MODE:-UNKNOWN}"
        FIXED=$((FIXED + 1))
    fi
done

log "Mount points scanned: ${SCANNED_MOUNTS}"
log "Directories fixed: ${FIXED}"
log "=== Sticky Bit Hardening Applied Successfully ==="
log "Run /root/sticky_bit_hardening_verifikasi.sh"
