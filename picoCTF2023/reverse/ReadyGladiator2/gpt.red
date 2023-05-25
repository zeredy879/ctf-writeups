    ; Anti-IMP program
    ; Starts by jumping to the end of the code segment
    ; then creates a spiral pattern to scan for the enemy IMP program
start   JMP end      ; Jump to end of code segment

loop    ADD #1, scan ; Increment scan counter
        MOV scan, @scan ; Move the counter to the current scan location
        CMP scan, #0 ; Check if scan counter is zero
        JMP end, < ; Jump to end if counter is zero
        MOV #0, -1 ; Set the -1 memory location to zero
        ADD #1, -1 ; Increment the -1 memory location
        DJN -2, loop ; Decrement the -2 memory location and jump to loop if it is not zero

scan    EQU 0        ; Initialize the scan counter to zero

end     DAT #0       ; End of code segment
end
