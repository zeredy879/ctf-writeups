from Crypto.Util.number import long_to_bytes

red = 39722847074734820757600524178581224432297292490103996089444214757432940313
blue = red * 5
print(blue)
print(long_to_bytes(blue))
