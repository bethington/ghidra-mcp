#!/usr/bin/env python3
"""
Memory State Dumper and Restorer
Comprehensive tool for capturing and restoring program memory state
"""

import psutil
import os
import pickle
import mmap
import struct
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging

@dataclass
class MemoryRegion:
    """Represents a memory region with its properties"""
    start: int
    end: int
    permissions: str
    path: Optional[str]
    data: bytes

@dataclass
class ProcessState:
    """Complete process state snapshot"""
    pid: int
    name: str
    memory_regions: Dict[int, MemoryRegion]
    registers: Dict[str, Any]  # Would need debugger integration
    threads: Dict[int, Dict[str, Any]]
    timestamp: float

class MemoryDumper:
    """Handles memory dumping operations"""

    def __init__(self, pid: int):
        self.pid = pid
        self.process = psutil.Process(pid)

    def dump_memory_regions(self) -> Dict[int, MemoryRegion]:
        """Dump all readable memory regions"""
        regions = {}

        try:
            for map_info in self.process.memory_maps():
                start = int(map_info.addr.split('-')[0], 16)
                end = int(map_info.addr.split('-')[1], 16)

                # Only dump readable regions
                if 'r' in map_info.perms:
                    try:
                        # Read memory region
                        data = self.process.memory()[start:end]
                        regions[start] = MemoryRegion(
                            start=start,
                            end=end,
                            permissions=map_info.perms,
                            path=map_info.path,
                            data=data
                        )
                    except (psutil.AccessDenied, OSError):
                        # Skip regions we can't read
                        continue

        except psutil.AccessDenied:
            raise PermissionError(f"Cannot access memory of process {self.pid}")

        return regions

    def dump_process_state(self) -> ProcessState:
        """Create complete process state snapshot"""
        memory_regions = self.dump_memory_regions()

        # Get thread information
        threads = {}
        for thread in self.process.threads():
            threads[thread.id] = {
                'user_time': thread.user_time,
                'system_time': thread.system_time
            }

        return ProcessState(
            pid=self.pid,
            name=self.process.name(),
            memory_regions=memory_regions,
            registers={},  # Would need ptrace/debugger
            threads=threads,
            timestamp=psutil.time.time()
        )

class MemoryRestorer:
    """Handles memory restoration operations"""

    def __init__(self, target_pid: int):
        self.target_pid = target_pid
        self.target_process = psutil.Process(target_pid)

    def restore_memory_region(self, region: MemoryRegion) -> bool:
        """Restore a single memory region"""
        try:
            # Open process memory for writing
            with open(f"/proc/{self.target_pid}/mem", "rb+") as mem_file:
                # Seek to region start
                mem_file.seek(region.start)
                # Write the data
                mem_file.write(region.data)
            return True
        except (PermissionError, OSError, IOError):
            logging.error(f"Failed to restore memory region 0x{region.start:x}")
            return False

    def restore_process_state(self, state: ProcessState) -> bool:
        """Restore complete process state"""
        success_count = 0
        total_count = len(state.memory_regions)

        for region_start, region in state.memory_regions.items():
            if self.restore_memory_region(region):
                success_count += 1

        logging.info(f"Restored {success_count}/{total_count} memory regions")
        return success_count == total_count

def main():
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(description="Memory State Dumper/Restorer")
    parser.add_argument("pid", type=int, help="Process ID")
    parser.add_argument("--dump", type=str, help="Dump state to file")
    parser.add_argument("--restore", type=str, help="Restore state from file")

    args = parser.parse_args()

    if args.dump:
        dumper = MemoryDumper(args.pid)
        state = dumper.dump_process_state()

        with open(args.dump, 'wb') as f:
            pickle.dump(state, f)

        print(f"Dumped process {args.pid} state to {args.dump}")

    elif args.restore:
        with open(args.restore, 'rb') as f:
            state = pickle.load(f)

        restorer = MemoryRestorer(args.pid)
        success = restorer.restore_process_state(state)

        print(f"Restoration {'successful' if success else 'failed'}")

if __name__ == "__main__":
    main()