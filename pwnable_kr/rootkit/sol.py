from base64 import b64encode

with open("./rootkit", "rb") as f:
    rootkit = f.read()

antikit = (
    rootkit.replace(b"\x75\x1d", b"\x90\x90")
    .replace(b"\x75\x24", b"\x90\x90")
    .replace(b"\xa1\x34\xa0\x5f\xc1", b"\xb8\x70\x8d\x15\xc1")
    .replace(b"rootkit", b"antikit")
)
antikit_b64 = b64encode(antikit)
with open("./antikit_b64", "wb") as f:
    f.write(antikit_b64)
