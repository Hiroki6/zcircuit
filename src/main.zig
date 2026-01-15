const std = @import("std");
const zcircuit = @import("zcircuit.zig");
const windows = std.os.windows;

pub fn main() !void {
    const z_circuit = zcircuit.ZCircuit.init() orelse {
        return;
    };

    var base_addr: usize = 0; // 0 means "Let the Kernel choose the address"
    var size: usize = 4096; // Request 1 page (4096 bytes)

    const syscall = z_circuit.getSyscall("NtAllocateVirtualMemory") orelse {
        return;
    };
    const status = zcircuit.do_syscall(syscall.ssn, syscall.address, .{
        0xFFFFFFFFFFFFFFFF, // ProcessHandle (Current)
        &base_addr, // BaseAddress
        0, // ZeroBits
        &size, // RegionSize
        0x3000, // AllocationType (MEM_COMMIT | MEM_RESERVE)
        0x40, // Protect (PAGE_EXECUTE_READWRITE)
    });
    if (status == windows.NTSTATUS.SUCCESS) {
        // base_addr now contains the actual address of the allocated memory!
        std.debug.print("Memory allocated at: 0x{x}\n", .{base_addr});
    }
}
