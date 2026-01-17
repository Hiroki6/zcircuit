const std = @import("std");
const zc = @import("zcircuit");
const windows = std.os.windows;

pub fn main() !void {
    const my_circuit = zc.Zcircuit(.{ .seed = 0xABCD1234 });

    var circuit = try my_circuit.init();

    var base_addr: usize = 0;
    var size: usize = 4096;

    const syscall = circuit.getSyscall("NtAllocateVirtualMemory", .{ .indirect_syscall = false }) orelse {
        return;
    };
    const status = syscall.call(.{
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
