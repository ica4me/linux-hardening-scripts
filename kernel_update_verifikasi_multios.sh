#!/usr/bin/env bash
set -u

# Cross-platform kernel update verification.
#
# Supported:
# - Ubuntu 20.04 / 22.04 / 24.04 / 26.04
# - Debian 11 / 12 / 13
# - RHEL 9 / 10.x
# - Rocky Linux 9 / 10.x
# - AlmaLinux 9 / 10.x
# - Fedora
#
# Read-only: this script does not modify or reboot the system.

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() { echo "[PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
warn() { echo "[WARN] $*"; WARN_COUNT=$((WARN_COUNT + 1)); }

[[ -r /etc/os-release ]] || {
    echo "[FAIL] /etc/os-release not found"
    exit 1
}

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"
RUNNING_KERNEL="$(uname -r)"
ARCH="$(uname -m)"

case "${OS_ID}" in
    ubuntu)
        case "${OS_VER}" in
            20.04|22.04|24.04|26.04) ;;
            *) echo "[FAIL] Unsupported Ubuntu version: ${OS_VER}"; exit 1 ;;
        esac
        FAMILY="apt"
        ;;
    debian)
        case "${OS_MAJOR}" in
            11|12|13) ;;
            *) echo "[FAIL] Unsupported Debian version: ${OS_VER}"; exit 1 ;;
        esac
        FAMILY="apt"
        ;;
    rhel)
        case "${OS_MAJOR}" in
            9|10) ;;
            *) echo "[FAIL] Unsupported RHEL version: ${OS_VER}"; exit 1 ;;
        esac
        FAMILY="dnf"
        ;;
    rocky)
        case "${OS_MAJOR}" in
            9|10) ;;
            *) echo "[FAIL] Unsupported Rocky Linux version: ${OS_VER}"; exit 1 ;;
        esac
        FAMILY="dnf"
        ;;
    almalinux)
        case "${OS_MAJOR}" in
            9|10) ;;
            *) echo "[FAIL] Unsupported AlmaLinux version: ${OS_VER}"; exit 1 ;;
        esac
        FAMILY="dnf"
        ;;
    fedora)
        FAMILY="dnf"
        ;;
    *)
        echo "[FAIL] Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        exit 1
        ;;
esac

echo "================================================"
echo " Cross-Platform Kernel Update Verification"
echo " OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
echo " Architecture: ${ARCH}"
echo "================================================"
echo

echo "--- Running Kernel ---"
pass "Running kernel = ${RUNNING_KERNEL}"

echo
echo "--- Installed Kernel ---"

LATEST_BOOT_KERNEL="$(
    find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null |
    sed 's/^vmlinuz-//' |
    sort -V |
    tail -n 1
)"

if [[ -n "${LATEST_BOOT_KERNEL}" ]]; then
    pass "Newest kernel in /boot = ${LATEST_BOOT_KERNEL}"
else
    fail "Unable to determine newest installed kernel from /boot"
fi

if [[ -n "${LATEST_BOOT_KERNEL}" && "${RUNNING_KERNEL}" == "${LATEST_BOOT_KERNEL}" ]]; then
    pass "Newest installed kernel is currently running"
else
    warn "Reboot required: running=${RUNNING_KERNEL}, newest=${LATEST_BOOT_KERNEL:-UNKNOWN}"
fi

echo
echo "--- Package Manager Status ---"

if [[ "${FAMILY}" == "apt" ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        pass "APT available"
    else
        fail "APT not found"
    fi

    if [[ "${OS_ID}" == "ubuntu" ]]; then
        META_FOUND=0
        for pkg in \
            linux-virtual \
            linux-generic \
            "linux-generic-hwe-${OS_VER}" \
            linux-aws \
            linux-azure \
            linux-gcp \
            linux-oracle \
            linux-kvm
        do
            if dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null |
               grep -q "install ok installed"; then
                pass "Installed Ubuntu kernel meta package = ${pkg}"
                META_FOUND=1
                break
            fi
        done

        if (( META_FOUND == 0 )); then
            warn "No known Ubuntu kernel meta package detected"
        fi
    else
        DPKG_ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
        case "${DPKG_ARCH}" in
            amd64) IMAGE_META="linux-image-amd64" ;;
            arm64) IMAGE_META="linux-image-arm64" ;;
            *) IMAGE_META="" ;;
        esac

        if [[ -n "${IMAGE_META}" ]] &&
           dpkg-query -W -f='${Status}' "${IMAGE_META}" 2>/dev/null |
           grep -q "install ok installed"; then
            pass "Debian kernel meta package installed = ${IMAGE_META}"
        else
            warn "Debian kernel meta package not detected"
        fi
    fi

else
    if command -v dnf >/dev/null 2>&1; then
        pass "DNF available"
    else
        fail "DNF not found"
    fi

    if rpm -q kernel-core >/dev/null 2>&1; then
        RPM_LATEST="$(
            rpm -q kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null |
            sort -V |
            tail -n 1
        )"
        pass "Latest installed kernel-core = ${RPM_LATEST}"
    elif rpm -q kernel >/dev/null 2>&1; then
        RPM_LATEST="$(
            rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null |
            sort -V |
            tail -n 1
        )"
        pass "Latest installed kernel package = ${RPM_LATEST}"
    else
        fail "No RPM kernel package detected"
    fi
fi

echo
echo "--- Boot Files ---"

BOOT_COUNT="$(
    find /boot -maxdepth 1 -type f -name 'vmlinuz-*' 2>/dev/null |
    wc -l
)"

if [[ "${BOOT_COUNT}" =~ ^[0-9]+$ ]] && (( BOOT_COUNT > 0 )); then
    pass "Kernel boot images found = ${BOOT_COUNT}"
else
    fail "No kernel boot image found"
fi

if [[ -r "/boot/config-${RUNNING_KERNEL}" ]]; then
    pass "Running kernel config exists"
else
    warn "Running kernel config not found at /boot/config-${RUNNING_KERNEL}"
fi

echo
echo "================================================"

if (( FAIL_COUNT == 0 )); then
    echo "OVERALL RESULT : PASS"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "WARNINGS       : ${WARN_COUNT}"
    echo "FAILED CHECKS  : 0"

    if (( WARN_COUNT > 0 )); then
        echo "STATUS         : PASS WITH WARNING"
    else
        echo "STATUS         : FULL PASS"
    fi

    echo "================================================"
    exit 0
else
    echo "OVERALL RESULT : FAIL"
    echo "PASSED CHECKS  : ${PASS_COUNT}"
    echo "WARNINGS       : ${WARN_COUNT}"
    echo "FAILED CHECKS  : ${FAIL_COUNT}"
    echo "================================================"
    exit 1
fi
