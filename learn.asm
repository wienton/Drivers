section .bss
number resd 1

section .data 
fmt db "%d", 0

section .text 
extern scanf 
global main 

main:
  sub rsp, 8
  mov edi, fmt 
  mov rsi, number 
  xor eax, eax 
  call scanf 

  mov edi, fmt 
  mov esi, [number]
  xor eax, eax 
  call printf 

  add rsp, 8
  ret
