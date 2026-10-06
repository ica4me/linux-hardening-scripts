#!/usr/bin/env bash
set -Eeuo pipefail

# Cross-platform kernel update script.
#
# Supported:
# - Ubuntu 20.04 / 22.04 / 24.04 / 26.04
# - Debian 11 / 12 / 13
# - RHEL 9 / 10.x
# - Rocky Linux 9 / 10.x
# - AlmaLinux 9 / 10.x
# - Fedora (DNF-based releases)
#
# Goal:
# - Update/install only kernel-related packages from configured repositories.
# - Do not perform a full operating-system upgrade.
# - Preserve the current Ubuntu kernel flavour where possible.
#
# IMPORTANT:
# - A reboot is normally required before the new kernel becomes active.
# - This script does NOT reboot automatically unless AUTO_REBOOT=1 is set.
#
# Example:
#   sudo bash kernel_update_multios.sh
#   sudo env AUTO_REBOOT=1 bash kernel_update_multios.sh

BACKUP_ROOT="/var/backups/kernel-update"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

AUTO_REBOOT="${AUTO_REBOOT:-0}"

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root."
[[ -r /etc/os-release ]] || fail "/etc/os-release not found."

# shellcheck disable=SC1091
. /etc/os-release

OS_ID="${ID,,}"
OS_VER="${VERSION_ID:-unknown}"
OS_MAJOR="${OS_VER%%.*}"
ARCH="$(uname -m)"
RUNNING_KERNEL="$(uname -r)"

case "${OS_ID}" in
    ubuntu)
        case "${OS_VER}" in
            20.04|22.04|24.04|26.04) ;;
            *) fail "Unsupported Ubuntu version: ${OS_VER}" ;;
        esac
        FAMILY="apt"
        ;;
    debian)
        case "${OS_MAJOR}" in
            11|12|13) ;;
            *) fail "Unsupported Debian version: ${OS_VER}" ;;
        esac
        FAMILY="apt"
        ;;
    rhel)
        case "${OS_MAJOR}" in
            9|10) ;;
            *) fail "Unsupported RHEL version: ${OS_VER}" ;;
        esac
        FAMILY="dnf"
        ;;
    rocky)
        case "${OS_MAJOR}" in
            9|10) ;;
            *) fail "Unsupported Rocky Linux version: ${OS_VER}" ;;
        esac
        FAMILY="dnf"
        ;;
    almalinux)
        case "${OS_MAJOR}" in
            9|10) ;;
            *) fail "Unsupported AlmaLinux version: ${OS_VER}" ;;
        esac
        FAMILY="dnf"
        ;;
    fedora)
        FAMILY="dnf"
        ;;
    *)
        fail "Unsupported OS: ${PRETTY_NAME:-${OS_ID}}"
        ;;
esac

mkdir -p "${BACKUP_DIR}"

{
    echo "OS=${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
    echo "ARCH=${ARCH}"
    echo "RUNNING_KERNEL=${RUNNING_KERNEL}"
    echo
    echo "=== /etc/os-release ==="
    cat /etc/os-release
} > "${BACKUP_DIR}/pre-update-info.txt"

log "Detected OS: ${PRETTY_NAME:-${OS_ID} ${OS_VER}}"
log "Architecture: ${ARCH}"
log "Running kernel: ${RUNNING_KERNEL}"
log "Backup/info directory: ${BACKUP_DIR}"
log "=== Updating Kernel Packages Only ==="

ubuntu_detect_meta() {
    local installed_meta=""
    local candidate=""

    # Prefer an already-installed kernel meta package so the current flavour
    # and cloud/vendor kernel track are not changed unexpectedly.
    while IFS= read -r candidate; do
        if dpkg-query -W -f='${Status}' "${candidate}" 2>/dev/null |
           grep -q "install ok installed"; then
            installed_meta="${candidate}"
            break
        fi
    done < <(
        printf '%s\n' \
            "linux-virtual" \
            "linux-generic" \
            "linux-generic-hwe-${OS_VER}" \
            "linux-aws" \
            "linux-azure" \
            "linux-gcp" \
            "linux-oracle" \
            "linux-kvm"
    )

    if [[ -n "${installed_meta}" ]]; then
        echo "${installed_meta}"
        return 0
    fi

    # Fall back to the running kernel flavour.
    case "${RUNNING_KERNEL}" in
        *-virtual) echo "linux-virtual" ;;
        *-aws)     echo "linux-aws" ;;
        *-azure)   echo "linux-azure" ;;
        *-gcp)     echo "linux-gcp" ;;
        *-oracle)  echo "linux-oracle" ;;
        *-kvm)     echo "linux-kvm" ;;
        *)         echo "linux-generic" ;;
    esac
}

if [[ "${FAMILY}" == "apt" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    if [[ "${OS_ID}" == "ubuntu" ]]; then
        KERNEL_META="$(ubuntu_detect_meta)"
        log "Ubuntu kernel meta package: ${KERNEL_META}"

        # Installing the meta package updates the matching kernel track without
        # upgrading unrelated user-space packages.
        apt-get install -y "${KERNEL_META}"

        # Install matching headers meta package when it exists.
        HEADER_META=""
        case "${KERNEL_META}" in
            linux-virtual)            HEADER_META="linux-headers-virtual" ;;
            linux-generic)            HEADER_META="linux-headers-generic" ;;
            linux-generic-hwe-*)      HEADER_META="${KERNEL_META/linux-generic/linux-headers-generic}" ;;
            linux-aws)                HEADER_META="linux-headers-aws" ;;
            linux-azure)              HEADER_META="linux-headers-azure" ;;
            linux-gcp)                HEADER_META="linux-headers-gcp" ;;
            linux-oracle)             HEADER_META="linux-headers-oracle" ;;
            linux-kvm)                HEADER_META="linux-headers-kvm" ;;
        esac

        if [[ -n "${HEADER_META}" ]] &&
           apt-cache show "${HEADER_META}" >/dev/null 2>&1; then
            apt-get install -y "${HEADER_META}"
        fi
    else
        DPKG_ARCH="$(dpkg --print-architecture)"

        case "${DPKG_ARCH}" in
            amd64)
                IMAGE_META="linux-image-amd64"
                HEADER_META="linux-headers-amd64"
                ;;
            arm64)
                IMAGE_META="linux-image-arm64"
                HEADER_META="linux-headers-arm64"
                ;;
            *)
                fail "Unsupported Debian architecture for automatic kernel meta selection: ${DPKG_ARCH}"
                ;;
        esac

        log "Debian kernel meta packages: ${IMAGE_META}, ${HEADER_META}"
        apt-get install -y "${IMAGE_META}" "${HEADER_META}"
    fi

else
    command -v dnf >/dev/null 2>&1 ||
        fail "dnf not found."

    dnf -y makecache

    RPM_KERNEL_PACKAGES=()

    for pkg in kernel kernel-core kernel-modules kernel-modules-core kernel-modules-extra; do
        if rpm -q "${pkg}" >/dev/null 2>&1 ||
           dnf -q list --available "${pkg}" >/dev/null 2>&1; then
            RPM_KERNEL_PACKAGES+=("${pkg}")
        fi
    done

    (( ${#RPM_KERNEL_PACKAGES[@]} > 0 )) ||
        fail "No kernel packages found in installed packages or enabled repositories."

    log "Kernel packages: ${RPM_KERNEL_PACKAGES[*]}"

    # dnf install selects the newest available version while leaving unrelated
    # packages untouched.
    dnf -y install "${RPM_KERNEL_PACKAGES[@]}"
fi

log "=== Kernel Package Update Completed ==="

LATEST_BOOT_KERNEL="$(
    find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null |
    sed 's/^vmlinuz-//' |
    sort -V |
    tail -n 1
)"

if [[ -n "${LATEST_BOOT_KERNEL}" ]]; then
    log "Newest kernel found in /boot: ${LATEST_BOOT_KERNEL}"
else
    warn "Unable to determine newest kernel from /boot."
fi

if [[ -n "${LATEST_BOOT_KERNEL}" && "${RUNNING_KERNEL}" == "${LATEST_BOOT_KERNEL}" ]]; then
    log "The newest installed kernel is already running."
    REBOOT_REQUIRED=0
else
    warn "A newer/different kernel is installed but is not active yet."
    warn "Current kernel : ${RUNNING_KERNEL}"
    warn "Newest kernel  : ${LATEST_BOOT_KERNEL:-UNKNOWN}"
    warn "Reboot is required to activate the new kernel."
    REBOOT_REQUIRED=1
fi

if [[ "${AUTO_REBOOT}" == "1" && "${REBOOT_REQUIRED}" == "1" ]]; then
    log "AUTO_REBOOT=1: rebooting system now..."
    sync
    systemctl reboot
fi

log "Run kernel_update_verifikasi_multios.sh after reboot."
