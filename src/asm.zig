const windows = @import("std").os.windows;

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

pub extern fn hells_gate(syscall_number: u32, address: usize) void;
pub extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) callconv(.c) windows.NTSTATUS;
