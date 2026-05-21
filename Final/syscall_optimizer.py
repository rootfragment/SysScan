import os
import platform

PROC_LIVE_TABLE = "/proc/syscall_live"
OUTPUT_FILE = "syscall.txt"

def load_system_map():
    release = platform.release()
    path = f"/boot/System.map-{release}"
    mapping = {}
    if not os.path.exists(path):
        print(f"Error: {path} not found.")
        return mapping
    
    try:
        with open(path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    addr, t, name = parts[0], parts[1], parts[2]

                    if t.lower() in ('t', 'w'): 
                        mapping[name] = addr 
    except PermissionError:
        print(f"Error: Permission denied reading {path}. Try running with sudo.")
        return None
    return mapping

def main():
    sys_map = load_system_map()
    if sys_map is None: return

    if not os.path.exists(PROC_LIVE_TABLE):
        print(f"Error: {PROC_LIVE_TABLE} not found. Is the syscall_reporter module loaded?")
        return

    count = 0
    seen_names = set()
    
    with open(PROC_LIVE_TABLE, "r") as f_in, open(OUTPUT_FILE, "w") as f_out:
        for line in f_in:
            parts = [p.strip() for p in line.split("+")]
            if len(parts) < 2: continue
            
            symbol_raw = parts[0]

            if symbol_raw in sys_map:

                static_addr = sys_map[symbol_raw]
                
                if symbol_raw not in seen_names:
                    f_out.write(f"{symbol_raw} {static_addr}\n")
                    seen_names.add(symbol_raw)
                    count += 1
                   

    print(f"[*] Successfully identified {count} runtime syscalls.")
    print(f"[*] Generated {OUTPUT_FILE} using STATIC addresses ")

if __name__ == "__main__":
    main()
