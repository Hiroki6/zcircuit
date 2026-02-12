const windows = @import("std").os.windows;

pub extern fn hells_gate(syscall_number: u32, address: usize) void;
pub extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) callconv(.c) windows.NTSTATUS;
