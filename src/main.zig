const std = @import("std");
const zcircuit = @import("zcircuit.zig");

pub fn main() !void {
    const z_circuit = zcircuit.ZCircuit.init() orelse {
        return;
    };

    var base_addr: usize = 0; // 0 means "Let the Kernel choose the address"
    var size: usize = 4096; // Request 1 page (4096 bytes)

    const funcNameHash = comptime zcircuit.hashName("NtAllocateVirtualMemory");
    const system_call_number = z_circuit.getSysId(funcNameHash) orelse {
        return;
    };
    const status = zcircuit.syscall(system_call_number, .{
        0xFFFFFFFFFFFFFFFF, // ProcessHandle (Current)
        &base_addr, // BaseAddress
        0, // ZeroBits
        &size, // RegionSize
        0x3000, // AllocationType (MEM_COMMIT | MEM_RESERVE)
        0x40, // Protect (PAGE_EXECUTE_READWRITE)
    });
    if (status == 0) {
        // base_addr now contains the actual address of the allocated memory!
        std.debug.print("Memory allocated at: 0x{x}\n", .{base_addr});
    }
    std.debug.print("{}", .{status});
}
