import requests

r = requests.post(
    "http://saturn.picoctf.net:49645/login",
    data={"username": "test", "password": "test!"},
)
for req in r.history:
    print(req.content)
print(r.content)
