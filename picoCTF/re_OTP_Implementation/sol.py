import subprocess
import re
from pwn import unhex, xor

flag = "ffadccb05b5892418ff068dd9d42231e8caf8ebb289ea1873f0a474cabe7ce598db77bac9dfef1d7c2b5af3c35bf5844c082"
enc = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe"
key = ["0"] * 100

for i in range(100):
    for j in "0123456789abcdef":
        key[i] = j
        p = subprocess.Popen(["ltrace", "-s", "1000", "./otp", "".join(key)],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        brute = re.findall(r"strncmp\(\"(.*?)\".*\)",
                           p.communicate()[0].decode())[0]
        print(brute)
        if brute[i] == enc[i]:
            break
print(xor(unhex("".join(key)), unhex(flag)))
