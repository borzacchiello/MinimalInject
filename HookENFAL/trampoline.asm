;;trampoline.asm

.386
PUBLIC _trampoline

_CODE SEGMENT dword public 'CODE' use32
ASSUME CS:_CODE

_trampoline PROC near
	mov  eax, [esp + 8];
	push esi;
	push edi;
	push edx;
	push ecx;
	push ebx;
	push eax;
	call DWORD PTR [esp + 24];
	pop  eax;
	pop  ebx;
	pop  ecx;
	pop  edx;
	pop  edi;
	pop  esi;
	add esp, 12; // restore parameters
	push [esp - 8];
	ret;

_trampoline ENDP

_CODE ENDS
END
