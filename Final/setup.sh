#!/usr/bin/env bash
# One-time KAIS baseline setup.
#
# Builds syscall_reporter, dumps /proc/syscall_live, writes syscall.txt,
# installs it to /etc/syscall_monitor/, then optionally removes setup-only
# artifacts (this script, syscall_reporter, syscall_optimizer).
#
# Runtime (every boot): kaslr_offset.ko + hashed_syscall_reporter.ko + syscall_monitor.py
#
# Usage:
#   sudo ./setup.sh              # setup + remove setup-only files (default)
#   sudo ./setup.sh --keep-tools # leave reporter/optimizer/setup for re-runs

set -euo pipefail

KEEP_TOOLS=0
[[ "${1:-}" == "--keep-tools" ]] && KEEP_TOOLS=1

BASELINE_DIR="/etc/syscall_monitor"
BASELINE_FILE="${BASELINE_DIR}/syscall.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root: sudo $0"

command -v python3 >/dev/null || die "python3 not found"
[[ -f "${SCRIPT_DIR}/syscall_optimizer.py" ]] || die "syscall_optimizer.py not found in ${SCRIPT_DIR}"
[[ -f "${SCRIPT_DIR}/syscall_reporter.c" ]] || die "syscall_reporter.c not found in ${SCRIPT_DIR}"

if [[ ! -r "/boot/System.map-$(uname -r)" ]]; then
    die "cannot read /boot/System.map-$(uname -r) (install kernel headers / map?)"
fi

echo "[*] Building kernel modules..."
make -C "${SCRIPT_DIR}" all

REPORTER_KO="${SCRIPT_DIR}/syscall_reporter.ko"
[[ -f "${REPORTER_KO}" ]] || die "build failed: ${REPORTER_KO} missing"

if lsmod | awk '{print $1}' | grep -qx 'syscall_reporter'; then
    echo "[*] syscall_reporter already loaded"
else
    echo "[*] Loading syscall_reporter.ko..."
    insmod "${REPORTER_KO}"
fi

cleanup_reporter() {
    if lsmod | awk '{print $1}' | grep -qx 'syscall_reporter'; then
        echo "[*] Unloading syscall_reporter.ko..."
        rmmod syscall_reporter || true
    fi
}
trap cleanup_reporter EXIT

[[ -r /proc/syscall_live ]] || die "/proc/syscall_live not available after insmod"

echo "[*] Generating syscall.txt..."
cd "${SCRIPT_DIR}"
python3 syscall_optimizer.py

[[ -s "${SCRIPT_DIR}/syscall.txt" ]] || die "syscall.txt empty — optimizer found no symbols"

COUNT="$(wc -l < "${SCRIPT_DIR}/syscall.txt" | tr -d ' ')"
[[ "${COUNT}" -ge 10 ]] || die "syscall.txt suspiciously small (${COUNT} lines); aborting"

echo "[*] Installing baseline (${COUNT} symbols) -> ${BASELINE_FILE}"
install -d -m 755 "${BASELINE_DIR}"
install -m 644 "${SCRIPT_DIR}/syscall.txt" "${BASELINE_FILE}"

echo "[+] Baseline installed: ${BASELINE_FILE} (${COUNT} entries)"
echo "[+] Keep loaded at runtime: kaslr_offset.ko, hashed_syscall_reporter.ko"
echo "[+] Monitor with: sudo python3 ${SCRIPT_DIR}/syscall_monitor.py"

if [[ "${KEEP_TOOLS}" -eq 1 ]]; then
    echo "[*] --keep-tools: leaving setup.sh, syscall_reporter, syscall_optimizer in place"
    exit 0
fi

echo "[*] Removing one-time setup artifacts..."
cleanup_reporter
trap - EXIT

rmmod syscall_reporter 2>/dev/null || true

# Stop linking syscall_reporter into future builds
if grep -q 'syscall_reporter.o' "${SCRIPT_DIR}/Makefile" 2>/dev/null; then
    sed -i '/syscall_reporter\.o/d' "${SCRIPT_DIR}/Makefile"
    make -C "${SCRIPT_DIR}" clean 2>/dev/null || true
fi

rm -f \
    "${SCRIPT_DIR}/syscall_reporter.ko" \
    "${SCRIPT_DIR}/syscall_reporter.o" \
    "${SCRIPT_DIR}/syscall_reporter.mod" \
    "${SCRIPT_DIR}/syscall_reporter.mod.c" \
    "${SCRIPT_DIR}/syscall_reporter.mod.o" \
    "${SCRIPT_DIR}/.syscall_reporter.ko.cmd" \
    "${SCRIPT_DIR}/.syscall_reporter.o.cmd" \
    "${SCRIPT_DIR}/syscall_reporter.c" \
    "${SCRIPT_DIR}/syscall_optimizer.py" \
    "${SCRIPT_DIR}/syscall.txt"

SETUP_SELF="${SCRIPT_DIR}/setup.sh"
rm -f "${SETUP_SELF}"

echo "[+] Setup complete. One-time tools removed."
echo "    Re-baseline after kernel upgrade: restore tools from git, then run setup again."
