const std = @import("std");
const windows = std.os.windows;
const ntdll = @import("ntdll.zig");

comptime {
    asm (
        \\.intel_syntax noprefix
        \\.data
        \\  wSystemCall: .long 0
        \\  qSyscallInsAdress: .quad 0
        \\
        \\.text
        \\.global hells_gate
        \\.global hell_descent
        \\
        \\hells_gate:
        \\  mov dword ptr [rip + wSystemCall], ecx
        \\  mov qword ptr [rip + qSyscallInsAdress], rdx
        \\  ret
        \\
        \\hell_descent:
        \\  mov r10, rcx
        \\  mov eax, dword ptr [rip + wSystemCall]
        \\  jmp qword ptr [rip + qSyscallInsAdress]
        \\  ret
    );
}

const DOWN: usize = 32;
const RANGE: usize = 255;
const SEARCH_RANGE: usize = 255;

pub const ZCircuitError = error{
    UnsupportedArchitecture,
    NtdllInitFailed,
};

pub const ZCircuit = struct {
    nt_dll: ntdll.NtDll,

    pub fn init() ZCircuitError!ZCircuit {
        if (comptime @import("builtin").target.cpu.arch != .x86_64) {
            return ZCircuitError.UnsupportedArchitecture;
        }
        const nt_dll = ntdll.NtDll.init() orelse return ZCircuitError.NtdllInitFailed;
        return ZCircuit{ .nt_dll = nt_dll };
    }

    pub fn getSyscall(self: ZCircuit, comptime func_name: [*:0]const u8) ?Syscall {
        const func_name_hash = comptime hashName(func_name);
        const module_address = @intFromPtr(self.nt_dll.table_entry.DllBase);
        const pdw_address_of_functions = @as([*]u32, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfFunctions));
        const pdw_address_of_names = @as([*]u32, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfNames));
        const pdw_address_of_name_ordinales = @as([*]u16, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfNameOrdinals));
        var syscall = Syscall{ .address = 0, .ssn = 0 };
        for (0..self.nt_dll.export_directory.NumberOfNames) |cx| {
            const function_address = @as([*]u8, @ptrFromInt(module_address + pdw_address_of_functions[pdw_address_of_name_ordinales[cx]]));
            const name_ptr: [*:0]const u8 = @ptrFromInt(module_address + pdw_address_of_names[cx]);
            if (hashName(name_ptr) == func_name_hash) {
                syscall.address = @intFromPtr(function_address);
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
                    syscall.ssn = (@as(u16, high) << 8) | low;
                    break;
                }

                // TartarusGate
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
                            syscall.ssn = ((@as(u16, high) << 8) | low) - @as(u16, @intCast(i));
                            break;
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
                            syscall.ssn = ((@as(u16, high) << 8) | low) + @as(u16, @intCast(i));
                            break;
                        }
                    }
                }
            }
        }

        if (syscall.ssn == 0) {
            return null;
        }

        // HellsHall
        // search for 'syscall' instruction of another syscall function
        const start_ptr: [*]u8 = @ptrFromInt(syscall.address);
        const search_base = start_ptr + SEARCH_RANGE;
        for (0..RANGE) |z| {
            if (search_base[z] == 0x0f and search_base[z + 1] == 0x05) {
                syscall.address = @intFromPtr(search_base + z);
                break;
            }
        }

        return syscall;
    }

    inline fn hashName(name: [*:0]const u8) u32 {
        var h: u32 = 5381;
        var i: usize = 0;
        while (name[i] != 0) : (i += 1) {
            h = (h << 5) +% h +% @as(u32, name[i]);
        }
        return h;
    }
};

pub const Syscall = extern struct {
    address: usize,
    ssn: u16,
};

pub fn do_syscall(callid: u16, syscall_addr: usize, args: anytype) windows.NTSTATUS {
    const ArgsType = @TypeOf(args);
    const args_info = @typeInfo(ArgsType);

    if (args_info != .@"struct" or !args_info.@"struct".is_tuple) {
        @compileError("Expected a tuple of arguments, e.g., .{arg1, arg2}");
    }

    if (args.len > 11) @compileError("Too many arguments for this syscall implementation");

    hells_gate(callid, syscall_addr);
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
extern fn hells_gate(syscall_number: u32, address: usize) void;
extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) callconv(.c) windows.NTSTATUS;
