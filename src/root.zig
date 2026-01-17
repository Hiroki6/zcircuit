const std = @import("std");
const windows = std.os.windows;
const ntdll = @import("ntdll.zig");
const asm_impl = @import("asm.zig");
const utils = @import("utils.zig");
const testing = std.testing;

const STUB_SIZE: usize = 32;
const RANGE: usize = 255;
const SEARCH_RANGE: usize = 255;

pub const Config = struct { seed: u32 = 5381, search_neighbor: bool = true, indirect_syscall: bool = true };

pub const ZcircuitError = ntdll.NtDllError || error{
    UnsupportedArchitecture,
};

pub fn Zcircuit(comptime config: Config) type {
    return struct {
        const Self = @This();
        nt_dll: ntdll.NtDll,

        pub fn init() ZcircuitError!Self {
            if (comptime @import("builtin").target.cpu.arch != .x86_64) {
                return ZcircuitError.UnsupportedArchitecture;
            }
            const nt_dll = try ntdll.NtDll.init();
            return Self{ .nt_dll = nt_dll };
        }

        pub fn getSyscall(self: Self, comptime func_name: [*:0]const u8, options: struct { search_neighbor: bool = config.search_neighbor, indirect_syscall: bool = config.indirect_syscall }) ?Syscall {
            const func_name_hash = comptime utils.crc32(func_name, config.seed);
            const module_address = @intFromPtr(self.nt_dll.table_entry.DllBase);
            const pdw_address_of_functions = @as([*]u32, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfFunctions));
            const pdw_address_of_names = @as([*]u32, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfNames));
            const pdw_address_of_name_ordinales = @as([*]u16, @ptrFromInt(module_address + self.nt_dll.export_directory.AddressOfNameOrdinals));
            var syscall = Syscall{ .address = 0, .ssn = 0 };
            for (0..self.nt_dll.export_directory.NumberOfNames) |cx| {
                const function_address = @as([*]u8, @ptrFromInt(module_address + pdw_address_of_functions[pdw_address_of_name_ordinales[cx]]));
                const name_ptr: [*:0]const u8 = @ptrFromInt(module_address + pdw_address_of_names[cx]);
                if (utils.crc32(name_ptr, config.seed) == func_name_hash) {
                    syscall.address = @intFromPtr(function_address);
                    // Hell's Gate
                    if (isCleanStub(function_address)) {
                        syscall.ssn = extractSsn(function_address);
                    }

                    if (!options.search_neighbor) {
                        break;
                    }
                    // TartarusGate
                    // search neighboring syscall if hooked
                    if (function_address[0] == 0xe9 or function_address[3] == 0xe9) {
                        for (1..RANGE) |i| {
                            const down_addr = function_address + i * STUB_SIZE;
                            if (isCleanStub(down_addr)) {
                                syscall.ssn = extractSsn(down_addr) - @as(u16, @intCast(i));
                                break;
                            }
                            const up_addr = function_address - (i * STUB_SIZE);
                            if (isCleanStub(up_addr)) {
                                syscall.ssn = extractSsn(up_addr) + @as(u16, @intCast(i));
                                break;
                            }
                        }
                    }
                }
            }

            if (syscall.ssn == 0) {
                return null;
            }

            if (!options.indirect_syscall) {
                return syscall;
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

        // helper to verify if a memory location looks like a clean syscall stub
        inline fn isCleanStub(ptr: [*]u8) bool {
            return ptr[0] == 0x4c and ptr[1] == 0x8b and ptr[2] == 0xd1 and
                ptr[3] == 0xb8 and ptr[6] == 0x00 and ptr[7] == 0x00;
        }

        // helper to extract the SSN from a known clean stub
        inline fn extractSsn(ptr: [*]u8) u16 {
            const low: u16 = ptr[4];
            const high: u16 = ptr[5];
            return (high << 8) | low;
        }
    };
}

pub const Syscall = extern struct {
    ssn: u16,
    address: usize,

    pub fn call(self: Syscall, args: anytype) windows.NTSTATUS {
        const ArgsType = @TypeOf(args);
        const args_info = @typeInfo(ArgsType);

        if (args_info != .@"struct" or !args_info.@"struct".is_tuple) {
            @compileError("Expected a tuple of arguments, e.g., .{arg1, arg2}");
        }

        if (args.len > 11) @compileError("Too many arguments for this syscall implementation");

        asm_impl.hells_gate(self.ssn, self.address);
        return asm_impl.hell_descent(
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
};

test "Syscall resolution" {
    const MyCircuit = Zcircuit(.{ .seed = 0x1337 });
    var circuit = try MyCircuit.init();

    // Verify we can find a standard syscall
    const syscall = circuit.getSyscall("NtAllocateVirtualMemory", .{});

    try testing.expect(syscall != null);
    try testing.expect(syscall.?.ssn > 0);
    try testing.expect(syscall.?.address != 0);
}
