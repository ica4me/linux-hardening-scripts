#!/usr/bin/env bash
set -u

# Cross-platform sticky-bit hardening verification.
# Supported:
# - Ubuntu 22.04 / 24.04
# - Debian 12 / 13
# - RHEL 9 / 10.x
#
# Read-only: this script does not modify the system.

SUPPORTED_FS_REGEX='^(ext2|ext3|ext4|xfs|btrfs|tmpfs)$'

PASS_COUNT=0
FAIL_COUNT=0
CHECK_COUNT=0
MOUNT_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

[[ -r /etc/os-release ]] || {
    echo "[FAIL] /etc/os-release not found"
    exit 1
}

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"

case "${OS_ID}" in
    ubuntu)
        [[ "${OS_VER}" == "22.04" || "${OS_VER}" == "24.04" ]] || {
            echo "[FAIL] Unsupported Ubuntu version: ${OS_VER}"
            exit 1
        }
        ;;
    debian)
        [[ "${OS_MAJOR}" == "12" || "${OS_MAJOR}" == "13" ]] || {
            echo "[FAIL] Unsupported Debian version: ${OS_VER}"
            exit 1
        }
        ;;
    rhel)
        [[ "${OS_MAJOR}" == "9" || "${OS_MAJOR}" == "10" ]] || {
            echo "[FAIL] Unsupported RHEL version: ${OS_VER}"
            exit 1
        }
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

echo "================================================"
echo " DBalance Cross-Platform Sticky Bit Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo "================================================"
echo

echo "--- World-Writable Directories ---"

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

for mountpoint in "${MOUNTPOINTS[@]}"; do
    [[ -d "${mountpoint}" ]] || continue
    MOUNT_COUNT=$((MOUNT_COUNT + 1))

    while IFS= read -r -d '' dir; do
        CHECK_COUNT=$((CHECK_COUNT + 1))
        MODE="$(stat -c '%a' "${dir}" 2>/dev/null || true)"

        if find "${dir}" \
            -maxdepth 0 \
            -type d \
            -perm -0002 \
            -perm -1000 \
            -print -quit 2>/dev/null |
            grep -q .
        then
            pass "${dir} mode=${MODE:-UNKNOWN}"
        else
            fail "${dir} mode=${MODE:-UNKNOWN} missing sticky bit"
        fi
    done < <(
        find "${mountpoint}" \
            -xdev \
            -type d \
            -perm -0002 \
            -print0 2>/dev/null
    )
done

echo
echo "--- Critical Directories ---"

for dir in /tmp /var/tmp /dev/shm; do
    if [[ -d "${dir}" ]]; then
        MODE="$(stat -c '%a' "${dir}" 2>/dev/null || true)"
        OWNER="$(stat -c '%U:%G' "${dir}" 2>/dev/null || true)"

        if find "${dir}" \
            -maxdepth 0 \
            -type d \
            -perm -0002 \
            -perm -1000 \
            -print -quit 2>/dev/null |
            grep -q .
        then
            pass "${dir} sticky bit set (mode=${MODE:-UNKNOWN}, owner=${OWNER:-UNKNOWN})"
        else
            fail "${dir} sticky bit missing or directory is not world-writable (mode=${MODE:-UNKNOWN})"
        fi
    else
        fail "${dir} does not exist"
    fi
done

echo
echo "--- Scan Summary ---"

if (( MOUNT_COUNT > 0 )); then
    pass "Supported mount points scanned = ${MOUNT_COUNT}"
else
    fail "No supported mount points scanned"
fi

# CHECK_COUNT may legitimately be zero on a minimal system if no
# world-writable directories are present outside the critical directories.
echo "World-writable directories discovered: ${CHECK_COUNT}"

echo
echo "================================================"

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "DIRECTORIES    : ${CHECK_COUNT}"
    echo "MOUNTS SCANNED : ${MOUNT_COUNT}"
    echo "FAILED CHECKS  : 0"
    echo "================================================"
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "DIRECTORIES    : ${CHECK_COUNT}"
    echo "MOUNTS SCANNED : ${MOUNT_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "================================================"
    exit 1
fi
