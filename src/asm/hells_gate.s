.intel_syntax noprefix
.data
  wSystemCall: .long 0
  qSyscallInsAdress: .quad 0

.text
.global hells_gate
.global hell_descent

hells_gate:
  mov dword ptr [rip + wSystemCall], ecx
  mov qword ptr [rip + qSyscallInsAdress], rdx
  ret

hell_descent:
  mov r10, rcx
  mov eax, dword ptr [rip + wSystemCall]
  jmp qword ptr [rip + qSyscallInsAdress]
  ret
 