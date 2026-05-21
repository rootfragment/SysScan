#!/usr/bin/env python3
"""
Usage:
  sudo python3 syscall_monitor.py                     # live terminal monitor, 3s interval
  sudo python3 syscall_monitor.py -t 10              # live terminal monitor, 10s interval
  sudo python3 syscall_monitor.py --daemon           # install systemd service (3s)
  sudo python3 syscall_monitor.py --daemon -t 30     # daemon, 30s interval
  sudo python3 syscall_monitor.py --remove-daemon    # uninstall the service
"""

import os
import sys
import time
import signal
import logging
import hashlib
import argparse
import subprocess
import shutil

from datetime import datetime
from pathlib import Path


# Constants 
BASELINE_FILE    = "/etc/syscall_monitor/syscall.txt"
PROC_KASLR       = "/proc/kaslr_offset"
PROC_LIVE_HASH   = "/proc/syscall_hash_live"
DEFAULT_LOG_FILE = "/var/log/syscall_monitor.log"
DAEMON_UNIT      = "/etc/systemd/system/syscall_monitor.service"
SELF             = os.path.abspath(__file__)


# ANSI helpers 
RESET       = "\033[0m"
BOLD        = "\033[1m"
DIM         = "\033[2m"
RED         = "\033[38;5;196m"
GREEN       = "\033[38;5;82m"
YELLOW      = "\033[38;5;220m"
CYAN        = "\033[38;5;51m"
WHITE       = "\033[38;5;255m"
GREY        = "\033[38;5;244m"
DARK_GREY   = "\033[38;5;238m"

HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"
CLEAR       = "\033[2J\033[H"
CLEAR_LINE  = "\033[2K"

def w(text):
    sys.stdout.write(text)

def flush():
    sys.stdout.flush()

def term_width():
    return shutil.get_terminal_size((80, 24)).columns

def move_to(row: int):
    w(f"\033[{row};1H")


BANNER_LINES = [
    r"  __  ___      ___       __       _______. ",
    r" |  |/  /     /   \     |  |     /       | ",
    r" |  '  /     /  ^  \    |  |    |   (----` ",
    r" |    <     /  /_\  \   |  |     \   \     ",
    r" |  .  \   /  _____  \  |  | .----)   |    ",
    r" |__|\__\ /__/     \__\ |__| |_______/     ",
]
```

BANNER_HEIGHT = len(BANNER_LINES) + 2

def print_banner():
    w(CLEAR)
    w(HIDE_CURSOR)
    for line in BANNER_LINES:
        w(f"{CYAN}{BOLD}{line}{RESET}\n")
    w(f"{GREY}  kernel-level automated integrity scanner{RESET}\n")
    w("\n")
    flush()


def draw_status(last_check: str, status_ok: bool, n_syscalls: int,
                n_findings: int, interval: int, scans_run: int,
                phase: str, countdown: int):
    

    row   = BANNER_HEIGHT + 1
    width = min(term_width() - 2, 52)
    bar   = "─" * width


    move_to(row);     w(CLEAR_LINE)
    w(f"  {WHITE}{BOLD}KAIS — Syscall Integrity Monitor{RESET}\n")


    move_to(row + 1); w(CLEAR_LINE)
    w(f"  {DARK_GREY}{bar}{RESET}\n")


    move_to(row + 2); w(CLEAR_LINE)
    ts_str = last_check if last_check else "—"
    w(f"  {GREY}Last check   :{RESET}  {WHITE}{ts_str}{RESET}\n")


    move_to(row + 3); w(CLEAR_LINE)
    if phase == "checking":
        status_str = f"{YELLOW}  Checking integrity…{RESET}"
    elif status_ok:
        status_str = f"{GREEN}  Stable   All {n_syscalls} syscalls intact{RESET}"
    else:
        status_str = f"{RED}{BOLD} Tainted  {n_findings} anomaly/anomalies detected!{RESET}"
    w(f"  {GREY}Status       :{RESET}  {status_str}\n")

    
    move_to(row + 4); w(CLEAR_LINE)
    w(f"  {GREY}Interval     :{RESET}  {WHITE}{interval}s{RESET}"
      f"  {DARK_GREY}|{RESET}  {GREY}Scans run: {WHITE}{scans_run}{RESET}\n")


    move_to(row + 5); w(CLEAR_LINE)
    w(f"  {DARK_GREY}{bar}{RESET}\n")

    move_to(row + 6); w(CLEAR_LINE)
    if phase == "checking":
        w(f"  {DIM}Running scan…{RESET}\n")
    else:
        w(f"  {DIM}Next check in {countdown}s…{RESET}\n")

    flush()


def restore_terminal():
    w(SHOW_CURSOR)
    w("\n")
    flush()



def setup_logging(log_path: str, file_only: bool = False) -> logging.Logger:
    log = logging.getLogger("syscall_monitor")

    if log.handlers:
        return log

    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    log.addHandler(fh)

    if not file_only:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        log.addHandler(sh)

    return log


#Core helpers 
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def read_kaslr(log: logging.Logger) -> int:
    try:
        val = Path(PROC_KASLR).read_text().strip()
        if val.startswith(("0x", "0X")):
            return int(val, 16)
        raise ValueError(f"Unexpected value: {val!r}")
    except FileNotFoundError:
        log.error(f"{PROC_KASLR} not found — is kaslr_offset module loaded?")
        sys.exit(1)
    except Exception as e:
        log.error(f"Cannot read KASLR offset: {e}")
        sys.exit(1)


def load_baseline(log: logging.Logger) -> dict[str, str]:
    if not Path(BASELINE_FILE).exists():
        log.error(f"Baseline not found: {BASELINE_FILE} (run setup.sh first)")
        sys.exit(1)

    offset = read_kaslr(log)
    log.debug(f"KASLR offset this boot: {hex(offset)}")   

    baseline = {}
    with open(BASELINE_FILE) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                log.warning(f"Baseline line {lineno} malformed, skipping: {line!r}")
                continue
            name, static_hex = parts
            try:
                runtime_addr = (int(static_hex, 16) + offset) & 0xFFFFFFFFFFFFFFFF
            except ValueError:
                log.warning(f"Bad address on line {lineno}: {static_hex!r}")
                continue
            baseline[name] = sha256_hex(f"{runtime_addr:x}")

    log.debug(f"Baseline: {len(baseline)} entries")
    return baseline


def load_live(log: logging.Logger) -> dict[str, str]:
    if not Path(PROC_LIVE_HASH).exists():
        log.error(
            f"{PROC_LIVE_HASH} not found — "
            f"is hashed_syscall_reporter module loaded?"
        )
        sys.exit(1)

    live = {}
    with open(PROC_LIVE_HASH) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            name = parts[0].split("+")[0].split("[")[0].strip()
            h = parts[1]
            if name and h and name not in live:
                live[name] = h

    log.debug(f"Live table: {len(live)} entries")
    return live


# Comparison
def compare(baseline: dict, live: dict, log: logging.Logger) -> list[dict]:
    findings = []
    ts = datetime.now().isoformat(timespec="seconds")

    for name, expected in baseline.items():
        if name not in live:
            findings.append({
                "time": ts, "syscall": name,
                "reason": "MISSING_FROM_LIVE",
                "expected": expected, "got": None
            })
            log.warning(f"[HOOK?] {name} — absent from live table (expected {expected[:16]}…)")
            continue
        got = live[name]
        if got != expected:
            findings.append({
                "time": ts, "syscall": name,
                "reason": "HASH_MISMATCH",
                "expected": expected, "got": got
            })
            log.warning(
                f"[HOOKED] {name}\n"
                f"           expected : {expected}\n"
                f"           live     : {got}"
            )

    for name, got in live.items():
        if name not in baseline:
            findings.append({
                "time": ts, "syscall": name,
                "reason": "UNEXPECTED_IN_LIVE",
                "expected": None, "got": got
            })
            log.warning(f"[EXTRA] {name} — in live table but not in baseline")

    return findings



def watch_gui(interval: int, log: logging.Logger):
    print_banner()

    running    = True
    scans_run  = 0
    last_check = None
    status_ok  = True
    n_findings = 0
    n_syscalls = 0

    def _stop(sig, _):
        nonlocal running
        log.info(f"Received signal {sig}, stopping.")
        running = False

    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    while running:
        draw_status(last_check, status_ok, n_syscalls, n_findings,
                    interval, scans_run, phase="checking", countdown=0)

        baseline   = load_baseline(log)
        live       = load_live(log)
        findings   = compare(baseline, live, log)

        n_findings = len(findings)
        n_syscalls = len(baseline)
        status_ok  = n_findings == 0
        last_check = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scans_run += 1

        log.info(f"Scan #{scans_run}: {n_findings} issue(s) found")

       
        for remaining in range(interval, 0, -1):
            if not running:
                break
            draw_status(last_check, status_ok, n_syscalls, n_findings,
                        interval, scans_run, phase="idle", countdown=remaining)
            time.sleep(1)

    restore_terminal()
    log.info("Monitor stopped.")


# Daemon background worker 
def run_daemon_worker(interval: int, log: logging.Logger):
    """Silent scan loop invoked by the systemd service unit."""
    running = True

    def _stop(sig, _):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    scans_run = 0
    while running:
        baseline   = load_baseline(log)
        live       = load_live(log)
        findings   = compare(baseline, live, log)
        scans_run += 1
        n = len(findings)
        if n:
            log.warning(f"Scan #{scans_run}: {n} issue(s) detected")
        else:
            log.info(f"Scan #{scans_run}: all syscall hashes match")

        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

    log.info("Daemon worker stopped.")



def _require_root():
    if os.geteuid() != 0:
        print("ERROR: daemon management requires root.", file=sys.stderr)
        sys.exit(1)


def install_daemon(interval: int, log: logging.Logger, log_path: str):
    _require_root()

    unit = f"""\
[Unit]
Description=KAIS Syscall Integrity Monitor
Documentation=file://{SELF}
After=systemd-modules-load.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {SELF} --daemon-worker -t {interval} --log {log_path}
Restart=on-failure
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    Path(DAEMON_UNIT).write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"],                              check=True)
    subprocess.run(["systemctl", "enable", "--now", "syscall_monitor.service"], check=True)

    print(f"[+] Service unit written : {DAEMON_UNIT}")
    print("[+] Service enabled and started.")
    print("\n  Status:   systemctl status syscall_monitor")
    print("  Logs:     journalctl -u syscall_monitor -f")
    print(f"  Log file: {log_path}\n")


def remove_daemon(log: logging.Logger):
    _require_root()
    subprocess.run(["systemctl", "stop",    "syscall_monitor.service"], check=False)
    subprocess.run(["systemctl", "disable", "syscall_monitor.service"], check=False)
    Path(DAEMON_UNIT).unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    log.info("Daemon service removed.")


# CLI
def main():
    p = argparse.ArgumentParser(
        prog="syscall_monitor.py",
        description="KAIS — Kernel-level Automated Integrity Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 syscall_monitor.py              # live terminal monitor, 3s interval (default)
  sudo python3 syscall_monitor.py -t 10        # live terminal monitor, 10s interval
  sudo python3 syscall_monitor.py --daemon     # install systemd service, 3s interval
  sudo python3 syscall_monitor.py --daemon -t 30
  sudo python3 syscall_monitor.py --remove-daemon
"""
    )

    p.add_argument(
        "-t", "--interval", type=int, default=3, metavar="SECS",
        help="Scan interval in seconds (default: 3)"
    )
    p.add_argument(
        "--daemon", action="store_true",
        help="Install and start as a systemd daemon (no terminal output)"
    )
    p.add_argument(
        "--remove-daemon", action="store_true",
        help="Stop and remove the systemd daemon"
    )
    p.add_argument(
        "--daemon-worker", action="store_true",
        help=argparse.SUPPRESS   
    )
    p.add_argument(
        "--log", default=DEFAULT_LOG_FILE, metavar="PATH",
        help=f"Log file path (default: {DEFAULT_LOG_FILE})"
    )

    args = p.parse_args()

    if os.geteuid() != 0:
        print("ERROR: must be run as root.", file=sys.stderr)
        sys.exit(1)

    if args.remove_daemon:
        log = setup_logging(args.log, file_only=True)
        remove_daemon(log)
        return

    if args.daemon:
        log = setup_logging(args.log, file_only=True)
        install_daemon(args.interval, log, args.log)
        return


    if args.daemon_worker:
        log = setup_logging(args.log, file_only=True)
        run_daemon_worker(args.interval, log)
        return

    log = setup_logging(args.log, file_only=True)   
    watch_gui(args.interval, log)


if __name__ == "__main__":
    main()
