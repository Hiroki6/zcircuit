const std = @import("std");
const zc = @import("zcircuit");
const windows = std.os.windows;

pub fn main() !void {
    const my_circuit = zc.Zcircuit(.{ .seed = 0xABCD1234 });
    var circuit = try my_circuit.init("ntdll.dll");

    const current_process = @as(windows.HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));

    var base_addr: usize = 0;
    var size: usize = 0x1000;

    const status = circuit.syscall("NtAllocateVirtualMemory", .{
        current_process,
        &base_addr,
        0,
        &size,
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x04, // PAGE_READWRITE
    });

    if (status == windows.NTSTATUS.SUCCESS) {
        std.debug.print("[+] Allocated 0x{x} bytes at 0x{x}\n", .{ size, base_addr });
    } else {
        std.debug.print("[-] NtAllocateVirtualMemory failed: 0x{x}\n", .{@intFromEnum(status)});
        return;
    }

    _ = circuit.syscall("NtFreeVirtualMemory", .{
        current_process,
        &base_addr,
        &size,
        0x8000, // MEM_RELEASE
    });
    std.debug.print("[+] Memory freed\n", .{});
}
