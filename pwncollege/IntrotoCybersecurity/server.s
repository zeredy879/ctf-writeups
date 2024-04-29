    .section .data
sockaddr_in:
    .short 2                    
    .short 0x5000                 
    .long 0                     
    .zero 8                     

read_request: .space 1024            

read_request_count: .quad 1024       

read_file: .space 1024            

read_file_count: .quad 1024       

http_response: .ascii "HTTP/1.0 200 OK\r\n\r\n"

    .section .bss
socketFD:
    .skip 4                     
    .section .text
    .global _start

_start:   
    movl $41, %eax              
    movl $2, %edi               
    movl $1, %esi               
    xorl %edx, %edx             
    syscall
    movl %eax, socketFD(%rip)   
   
    movl $49, %eax              
    movl socketFD(%rip), %edi   
    leaq sockaddr_in(%rip), %rsi 
    movl $16, %edx              
    syscall
    
    movl $50, %eax
    movl $3, %edi
    movl $0, %esi
    syscall    

loop:   
    movl $43, %eax
    movl $3, %edi
    movl $0, %esi
    movl $0, %edx
    syscall
    
    movl $57, %eax
    syscall

    cmp $0, %eax
    je child
    
    mov $3, %rax                      
    mov $4, %rdi                      
    syscall                               
    
    jmp loop
    

child: 
    mov $3, %rdi
    mov $3, %rax
    syscall

    mov $0, %rax                      
    mov $4, %rdi                      
    lea read_request(%rip), %rsi      
    mov read_request_count, %rdx      
    syscall                           
    mov %rax, %r10

    lea read_request(%rip), %rsi  
    xor %rax, %rax                
    xor %rdx, %rdx                

    cmpb $'P', (%rsi)
    je post_child


find_first_space:
    lodsb                    
    cmp $' ', %al            
    je skip_first_space                        
    jmp find_first_space     

skip_first_space:
    mov %rsi, %rdi

find_second_space:
    lodsb                    
    cmp $' ', %al            
    je replace_with_null                   
    jmp find_second_space    


replace_with_null:
    dec %rsi                 
    movb $0, (%rsi)          
    
    mov $0, %rsi
    mov $2, %rax
    syscall
    
    mov $3, %rdi
    lea read_file(%rip), %rsi      
    mov read_file_count, %rdx      
    mov $0, %rax
    syscall

    mov %rax, %r9
    
    mov $3, %rdi
    mov $3, %rax
    syscall
    
    mov $1, %rax                      
    mov $4, %rdi                      
    lea http_response(%rip), %rsi     
    mov $19, %rdx        
    syscall                           

    
    mov $4, %rdi
    lea read_file(%rip), %rsi      
    mov %r9, %rdx      
    mov $1, %rax
    syscall

    
    movl $60, %eax              
    xorl %edi, %edi             
    syscall    

post_child:

post_find_first_space:
    lodsb                    
    cmp $' ', %al            
    je post_skip_first_space      
    jmp post_find_first_space     

post_skip_first_space:
    mov %rsi, %rdi

post_find_second_space:
    lodsb                    
    cmp $' ', %al            
    je post_replace_with_null                           
    jmp post_find_second_space    


post_replace_with_null:
    dec %rsi                 
    movb $0, (%rsi)          

    mov $65, %rsi
    mov $2, %rax
    mov $511, %rdx
    syscall

    lea read_request(%rip), %rsi  
    xor %rax, %rax                
    xor %rdx, %rdx                
    xor %r11, %r11
    add %r10, %rsi

find_content:
    movb (%rsi), %al
    dec %rsi
    inc %r11
    cmp $10, %al            
    je content_finded         
    jmp find_content      

content_finded:
    inc %rsi
    inc %rsi
    
    mov $3, %rdi
    mov %r11, %rdx      
    dec %rdx
    dec %rdx
    mov $1, %rax
    syscall
    
    mov $3, %rdi
    mov $3, %rax
    syscall

    mov $1, %rax                      
    mov $4, %rdi                      
    lea http_response(%rip), %rsi     
    mov $19, %rdx        
    syscall                           
    
    movl $60, %eax              
    xorl %edi, %edi             
    syscall
