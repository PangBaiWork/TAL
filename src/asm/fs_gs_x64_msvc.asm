; fs_gs_x64_msvc.asm
; MASM-compatible assembly for MSVC x64
; Exposes same symbols for linking with MSVC (or ml64).
;
; Windows x64 calling convention: return value in RAX.

.code

; Define exported procedures (do not declare them as EXTERN here)
PUBLIC get_fs_selector
get_fs_selector PROC
    xor rax, rax
    ; read 16-bit FS selector into AX
    mov rax, fs
    ret
get_fs_selector ENDP

PUBLIC get_gs_selector
get_gs_selector PROC
    xor rax, rax
    mov rax, gs
    ret
get_gs_selector ENDP

PUBLIC get_fs_base
get_fs_base PROC
    xor rax, rax
    ; On Windows x64, GS:0 points to TEB in user-mode (on modern Windows)
    ; Try read GS:0 into RAX (TEB base). If FS is used instead in your environment,
    ; replace with mov rax, fs:[0]
    mov rax, qword ptr gs:[96]
    ret
get_fs_base ENDP

PUBLIC get_gs_base
get_gs_base PROC
    xor rax, rax
    mov rax, qword ptr gs:[96]
    ret
get_gs_base ENDP

END
