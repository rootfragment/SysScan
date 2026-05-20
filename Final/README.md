# Out-of-Band Kernel Attestation

A Linux kernel syscall integrity attestation framework designed to detect syscall table tampering, syscall hooks, and runtime kernel modifications by validating live syscall state against a trusted static kernel reference.

This project combines:

- Linux kernel modules
- KASLR-aware address reconstruction
- Runtime syscall hashing
- Static kernel symbol reconciliation
- Continuous integrity monitoring

It was built as a response to a fundamental weakness in many syscall-hook detectors:

> if malware executes before the detector initializes, the detector may unknowingly trust already-compromised kernel state.

Instead of treating the running kernel as the source of truth, this project shifts trust toward the static kernel image (`System.map`) and reconstructs expected runtime syscall addresses dynamically.

---

# Why

The original motivation came from a practical failure case in traditional syscall hook detectors.

Most syscall integrity monitors work like this:

```text
running kernel -> generate baseline
running kernel -> compare against baseline
```

The problem is obvious once malware gains kernel execution *before* the detector starts:

- syscall hooks may already exist
- the syscall table may already be modified
- kernel symbols may already be manipulated
- the detector's baseline becomes poisoned from the start

At that point, the detector is effectively validating compromised state against itself.

This project attempts to eliminate that circular trust problem.

The core idea is:

> the running kernel should not be the primary source of truth.

Instead:

- trusted static syscall addresses are extracted from `System.map`
- the current boot's KASLR slide is calculated independently
- expected runtime syscall addresses are reconstructed dynamically
- live syscall table entries are hashed and compared against reconstructed expectations

Conceptually, the verification flow becomes:

```text
expected_runtime_address =
    static_system_map_address + verified_kaslr_offset
```

The monitor then compares:

```text
expected runtime syscall target
vs
actual live syscall target
```

This does **not** make the system immune to kernel-level attackers.

A sufficiently privileged rootkit could still:

- forge `/proc` output
- patch the monitoring modules
- hook kernel crypto APIs
- manipulate symbol resolution
- tamper with integrity checks directly

However, the project intentionally changes the trust model from:

```text
"trust current kernel state"
```

to:

```text
"verify current kernel state against a static external reference"
```

That architectural shift is the central purpose of the project.

---

# What This Project Does

The framework performs runtime syscall attestation by:

1. Reading trusted syscall symbol addresses from `System.map`
2. Calculating the current boot's KASLR offset
3. Reconstructing expected runtime syscall addresses
4. Reading the live syscall table directly from kernel memory
5. Hashing live syscall addresses
6. Comparing expected vs actual runtime state
7. Reporting mismatches, missing entries, and unexpected syscall targets

The monitoring logic is intentionally transparent and minimal.

This project is primarily intended for:

- kernel security research
- educational experimentation
- syscall integrity auditing
- rootkit detection research
- Linux internals learning

---

# Components

## 1. `syscall_reporter.c`

Exports live syscall symbols from the kernel syscall table through:

```text
/proc/syscall_live
```

The module:

- Resolves `kallsyms_lookup_name`
- Locates `sys_call_table`
- Iterates over all syscalls
- Prints symbol names using `sprint_symbol()`

Example output:

```text
__x64_sys_read+0x0/0x20
__x64_sys_write+0x0/0x20
```

This module is primarily used to generate the initial syscall baseline.

---

## 2. `hashed_syscall_reporter.c`

Exports SHA-256 hashes of live syscall runtime addresses through:

```text
/proc/syscall_hash_live
```

For every syscall:

- Runtime address is read from `sys_call_table`
- Address is converted to hexadecimal
- SHA-256 hash is generated in-kernel
- Symbol name + hash are exported

Example:

```text
__x64_sys_openat e3b0c44298fc1...
```

This avoids exposing raw runtime addresses directly to userspace while still allowing integrity verification.

---

## 3. `kaslr_offset.c`

Computes the current kernel KASLR slide by comparing:

```text
runtime symbol address
vs
trusted static symbol address
```

It validates consistency across multiple syscall anchors.

Output is exposed through:

```text
/proc/kaslr_offset
```

Possible states:

| State | Meaning |
|---|---|
| Valid offset | All anchors resolved consistently |
| Mismatch | Possible tampering or inconsistent runtime state |
| Unresolved | Symbols could not be resolved |
| No anchors | Invalid configuration |

This module is essential because runtime kernel addresses change every boot under KASLR.

---

## 4. `syscall_optimizer.py`

Generates a trusted syscall baseline by correlating:

- `/proc/syscall_live`
- `/boot/System.map-*`

Output:

```text
syscall.txt
```

Format:

```text
symbol_name static_address
```

This baseline becomes the trusted static reference used during verification.

---

## 5. `syscall_monitor.py`

The primary monitoring component.

It:

- Reads the trusted baseline
- Reads current KASLR offset
- Reconstructs expected runtime syscall addresses
- Hashes reconstructed addresses
- Compares them against live syscall hashes

Findings include:

| Detection | Meaning |
|---|---|
| `HASH_MISMATCH` | Runtime syscall target differs from expectation |
| `MISSING_FROM_LIVE` | Expected syscall absent from runtime table |
| `UNEXPECTED_IN_LIVE` | Unknown syscall target present |

Supports:

- One-shot scans
- Continuous monitoring
- Systemd daemon installation
- Persistent logging

---

# Architecture Overview

```text
             +--------------------+
             |  System.map        |
             +---------+----------+
                       |
                       v
          +------------------------+
          | syscall_optimizer.py   |
          +-----------+------------+
                      |
                      v
             syscall.txt baseline
                      |
                      v
       +------------------------------+
       | syscall_monitor.py           |
       +---------------+--------------+
                       |
         +-------------+-------------+
         |                           |
         v                           v
/proc/kaslr_offset       /proc/syscall_hash_live
         |                           |
         +-------------+-------------+
                       |
                       v
             Runtime Verification
```

---

# Security Model

This project assumes:

- the static kernel image is trustworthy
- `System.map` matches the running kernel
- kernel modules can still load
- `kallsyms_lookup_name` remains recoverable
- `/proc` output is not fully forged
- the baseline was generated from a clean system

The framework is **not** resistant against fully privileged kernel adversaries.

It is best viewed as:

> a runtime kernel integrity attestation experiment,
> not a complete anti-rootkit platform.

---

# Important Limitations

A sufficiently advanced attacker could still:

- patch the monitoring modules themselves
- forge `/proc` output
- intercept `seq_file`
- patch kernel crypto routines
- manipulate `kallsyms`
- hide syscall table modifications selectively
- bypass integrity checks entirely

This project does not attempt to provide:

- hardware-backed attestation
- hypervisor isolation
- secure boot verification
- TPM-backed trust chains
- memory forensics resistance

The verification still occurs inside the same kernel trust domain.

---

# Building

Example:

```bash
make
```

Requirements:

- Linux kernel headers
- GCC / build-essential
- Root privileges for module loading

---

# Example Workflow

## Load modules

```bash
sudo insmod syscall_reporter.ko
sudo insmod hashed_syscall_reporter.ko
sudo insmod kaslr_offset.ko
```

---

## Generate baseline

```bash
sudo python3 syscall_optimizer.py
```

Move baseline:

```bash
sudo mkdir -p /etc/syscall_monitor
sudo mv syscall.txt /etc/syscall_monitor/
```

---

## Run monitor

One-shot scan:

```bash
sudo python3 syscall_monitor.py
```

Continuous mode:

```bash
sudo python3 syscall_monitor.py -t 10
```

Install daemon:

```bash
sudo python3 syscall_monitor.py --daemon
```

---

# Example Detection Output

```text
[HOOKED] __x64_sys_openat
expected : 3f4ac9...
live     : d2be91...
```

---

# Kernel Compatibility Notes

This project depends heavily on:

- `kallsyms_lookup_name`
- `kprobes`
- syscall table layout assumptions
- exported kernel internals

Modern hardened kernels may:

- restrict symbol resolution
- block unsigned modules
- remove kallsyms visibility
- randomize internal structures further

Compatibility is therefore kernel-version dependent.

---

# Ethical Notice

This project operates at kernel level and interacts with sensitive internal kernel structures.

Use responsibly and only on systems you own or are authorized to test.

---
