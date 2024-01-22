;
;                          Shadow-Box
;                         ------------
;      Lightweight Hypervisor-Based Kernel Protector
;
;               Copyright (C) 2017 Seunghun Han
;

; This software has GPL v2 license. See the GPL_LICENSE file.

[bits 64]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Exported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global sb_enable_vmx
global sb_disable_vmx
global sb_start_vmx
global sb_clear_vmcs
global sb_load_vmcs
global sb_read_vmcs
global sb_write_vmcs
global sb_stop_vmx
global sb_get_cr0
global sb_set_cr0
global sb_get_cr2
global sb_get_cr3
global sb_set_cr3
global sb_get_cr4
global sb_set_cr4
global sb_get_cr8
global sb_get_cs
global sb_get_ss
global sb_get_ds
global sb_get_es
global sb_get_fs
global sb_get_gs
global sb_get_tr
global sb_get_dr7
global sb_get_rflags
global sb_get_ldtr
global sb_rdmsr
global sb_wrmsr
global sb_vm_launch
global sb_resume
global sb_calc_vm_exit_callback_addr
global sb_vm_exit_callback_stub
global sb_invd
global sb_flush_gdtr
global sb_gen_int
global sb_pause_loop
global sb_vm_call
global sb_restore_context_from_stack
global sb_int_callback_stub
global sb_int_with_error_callback_stub
global sb_int_nmi_callback_stub

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Imported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
extern sb_vm_exit_callback
extern sb_vm_resume_fail_callback
extern sb_int_callback
extern sb_int_with_error_callback
extern sb_int_nmi_callback

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PUSHAQ 0
	push rbp
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro

%macro POPAQ 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rbp
%endmacro

; Enable VMX.
sb_enable_vmx:
	endbr64
	mov rax, cr4
	bts rax, 13
	mov cr4, rax
	ret

; Disable VMX.
sb_disable_vmx:
	endbr64
	mov rax, cr4
	btc rax, 13
	mov cr4, rax
	ret

; Start VMX.
sb_start_vmx:
	endbr64
	;call disable_A20
	vmxon [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	;call enable_A20
	ret

; Clear VMCS.
sb_clear_vmcs:
	endbr64
	vmclear [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Load VMCS.
sb_load_vmcs:
	endbr64
	vmptrld [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Write data to VMCS.
sb_write_vmcs:
	endbr64
	vmwrite rdi, rsi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Read data from VMCS.
sb_read_vmcs:
	endbr64
	vmread [rsi], rdi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Stop VMX.
sb_stop_vmx:
	endbr64
	vmxoff
	ret

; Get CR0.
sb_get_cr0:
	endbr64
	mov rax, cr0
	ret

; Set CR0.
sb_set_cr0:
	endbr64
	mov cr0, rdi
	ret

; Get CR2.
sb_get_cr2:
	endbr64
	mov rax, cr2
	ret

; Get CR3.
sb_get_cr3:
	endbr64
	mov rax, cr3
	ret

; Set CR3.
sb_set_cr3:
	endbr64
	mov cr3, rdi
	ret

; Get CR4.
sb_get_cr4:
	endbr64
	mov rax, cr4
	ret

; Set CR4.
sb_set_cr4:
	endbr64
	mov cr4, rdi
	ret

; Get CR8.
sb_get_cr8:
	endbr64
	mov rax, cr8
	ret

; Get CS.
sb_get_cs:
	endbr64
	mov rax, cs
	ret

; Get SS.
sb_get_ss:
	endbr64
	mov rax, ss
	ret

; Get DS.
sb_get_ds:
	endbr64
	mov rax, ds
	ret

; Get ES.
sb_get_es:
	endbr64
	mov rax, es
	ret

; Get FS.
sb_get_fs:
	endbr64
	mov rax, fs
	ret

; Get GS.
sb_get_gs:
	endbr64
	mov rax, gs
	ret

; Get TR.
sb_get_tr:
	endbr64
	str rax
	ret

; Get DR7.
sb_get_dr7:
	endbr64
	mov rax, dr7
	ret

; Get RFLAGS.
sb_get_rflags:
	endbr64
	pushfq
	pop rax
	ret

; Get LDTR.
sb_get_ldtr:
	endbr64
	sldt rax
	ret

; Read MSR.
sb_rdmsr:
	endbr64
	push rdx
	push rcx

	xor rdx, rdx
	xor rax, rax

	mov ecx, edi
	rdmsr

	shl rdx, 32
	or rax, rdx

	pop rcx
	pop rdx
	ret

; Write MSR.
sb_wrmsr:
	endbr64
	push rdx
	push rcx

	mov rdx, rsi
	shr rdx, 32
	mov eax, esi

	mov ecx, edi
	wrmsr

	pop rcx
	pop rdx
	ret

; Launch VM.
sb_vm_launch:
	endbr64
	push rbx

	; For seamless interoperation, set RSP of the guest to the host.
	mov rbx, 0x681C		; RSP
	mov rax, rsp
	vmwrite rbx, rax
	
	; Get current RIP.
	;call .get_rip
;.get_rip:
	;pop rax
	lea rax, [.get_rip]
.get_rip:
	
	mov rbx, 0x681E		; RIP
	add rax, (.success - .get_rip)
	vmwrite rbx, rax

	vmlaunch

	; Process fail.
	pop rbx

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	pop rbx
	mov rax, 0
	ret

; Stub of VM exit callback.
;
; When VM exit occur, RFLAGS is cleared except bit 1.
sb_vm_exit_callback_stub:
	endbr64
	; Start line of the host.
	; Now the core is in the host.
	PUSHAQ
	
	; RDI has the pointer of the guest context structure.
	mov rdi, rsp

	call sb_vm_exit_callback
	
	; Resume the guest.
	POPAQ
	vmresume

	; Error occur.
	mov rdi, rax
	call sb_vm_resume_fail_callback

.hang:
	jmp .hang
	ret

; Resume VM.
sb_vm_resume:
	endbr64
	vmresume

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	mov rax, 0
	ret

; Get current RIP.
sb_get_rip:
	endbr64
	pop rax
	push rax
	ret

; Process INVD.
sb_invd:
	endbr64
	invd
	ret

; Flush GDTR.
sb_flush_gdtr:
	endbr64
	push rax

	mov ax, ss
	mov ss, ax

	pop rax
	ret

; Generate interrupt 0xF8.
sb_gen_int:
	endbr64
	push rax
	mov rax, rdi
	sti
	int 0xf8
	pop rax
	ret

; Pause CPU.
sb_pause_loop:
	endbr64
	pause
	ret

; Call vmcall.
;	VMcall argument:
;		rax: service number
;		rbx: argument
;	Result:
;		rax: return value
sb_vm_call:
	endbr64
	push rbx

	mov rax, rdi
	mov rbx, rsi

	vmcall

	pop rbx
	ret

; Restore context from stack(vm_full_context).
sb_restore_context_from_stack:
	endbr64
	mov rsp, rdi
	
	pop rax			; cr4
	;mov cr4, rax

	pop rax			; cr3
	mov cr3, rax

	pop rax			; cr0
	;mov cr0, rax

	pop rax			; tr
	;ltr ax

	pop rax			; lldt
	;lldt ax

	pop rax			; gs
	;mov gs, ax

	pop rax			; fs
	mov fs, ax

	pop rax			; es
	mov es, ax

	pop rax			; ds
	mov ds, ax

	pop rax			; cs
	;ignore cs

	POPAQ			; Restore GP register.
	popfq			; Restore RFLAGS.

	ret				; Return to RIP.

; Stub for interrupt without an error code
; EFLAGS		<- RSP + 16
; CS			<- RSP + 8
; EIP 			<- RSP
 sb_int_callback_stub:
	endbr64
	PUSHAQ

	call sb_int_callback

	POPAQ
	iretq

; Stub for interrupt with error code
; EFLAGS		<- RSP + 24
; CS			<- RSP + 16
; EIP			<- RSP + 8
; Error Code 	<- RSP
sb_int_with_error_callback_stub:
	endbr64
	PUSHAQ

	call sb_int_with_error_callback

	POPAQ
	add rsp, 8		; Remove error code from stack
	iretq

; Stub for NMI interrupt
; EFLAGS		<- RSP + 16
; CS			<- RSP + 8
; EIP 			<- RSP
sb_int_nmi_callback_stub:
	endbr64
	PUSHAQ

	call sb_int_nmi_callback

	POPAQ
	iretq

