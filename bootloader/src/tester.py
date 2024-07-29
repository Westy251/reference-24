from Crypto.PublicKey import RSA
from Crypto.Hash import *
from pwn import *
import serial
from Crypto.Signature import pkcs1_15
import re
import math

ser = serial.Serial("/dev/ttyACM0", 115200)

mykey = RSA.generate(2048)

wkey = mykey.export_key(passphrase="Skibidi")


e_bytes = mykey.e.to_bytes((mykey.e.bit_length() + 7) // 8, 'little')
n_bytes = mykey.n.to_bytes((mykey.n.bit_length() + 7) // 8, 'little')

e_converted = "{"
n_converted = "{"

for i in e_bytes:
    e_converted += hex(i)
    e_converted += ", "

for i in n_bytes:
    n_converted += hex(i)
    n_converted += ", "

e_converted = e_converted[0:len(e_converted) - 2]
n_converted = n_converted[0:len(n_converted) - 2]

e_converted += "}"
n_converted += "}"
print("e-value: " + e_converted)
print("")
print("n-value: " + n_converted)

message = b'Reina and Charlie are the best TAs!'
h = SHA256.new(message)
signature = pkcs1_15.new(mykey).sign(h)

print(signature)

'''with open("key.pem", "wb") as brugh:
    brugh.write(wkey)

def strip_pem_headers(key):
    # Remove the PEM headers and newlines
    key = key.decode('utf-8')
    key = re.sub(r"-----BEGIN .*?-----", "", key)
    key = re.sub(r"-----END .*?-----", "", key)
    key = key.replace("\n", "")
    return key

wkey = strip_pem_headers(wkey)

n = pack(mykey.n, word_size=len(mykey.n)



print(n)

with open("key.h", 'w') as f:
    f.write("#ifndef DEFINE_KEY\n")
    f.write(f'static const char KEY[] = "{wkey}";\n')
    f.write("#endif // KEY_H\n")

    #Thanks max

    #convert to der'''