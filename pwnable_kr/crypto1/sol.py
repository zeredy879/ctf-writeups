from pwn import *

context.log_level = "error"


def getEpacket(id: bytes, pw: bytes):
    r = remote("pwnable.kr", 9006)
    r.sendlineafter(b"ID\n", id)
    r.sendlineafter(b"PW\n", pw)
    Epacket = re.findall(r"\((.*)\)", str(r.recv()))[0]
    r.close()
    return Epacket


def getCookie():
    cookie = b""
    for i in range(1000):
        padding = b"-" * ((15 - i - 2) % 16)
        for c in "1234567890abcdefghijklmnopqrstuvwxyz-_":
            epacket1 = getEpacket(padding + b"--" + cookie + c.encode("utf-8"), b"")
            epacket2 = getEpacket(padding, b"")
            enc_len = len(padding + b"--" + cookie + c.encode("utf-8")) * 2
            # print(c, epacket1[:enc_len] == epacket2[:enc_len])

            if epacket1[:enc_len] == epacket2[:enc_len]:
                cookie += c.encode("utf-8")
                print(cookie)
                break
    return cookie


cookie = getCookie()
# cookie = b"you_will_never_guess_this_sugar_honey_salt_cookie"
id = b"admin"
pw = hashlib.sha256(id + cookie).hexdigest()

r = remote("pwnable.kr", 9006)
r.sendlineafter(b"ID\n", id)
r.sendlineafter(b"PW\n", pw)
r.interactive()
