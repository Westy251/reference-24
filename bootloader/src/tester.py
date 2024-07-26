from Crypto.PublicKey import RSA
import serial
import re

ser = serial.Serial("/dev/ttyACM0", 115200)


mykey = RSA.generate(2048)

wkey = mykey.export_key(passphrase="Skibidi")

print(wkey)

with open("key.pem", "wb") as brugh:
    brugh.write(wkey)

def strip_pem_headers(key):
    # Remove the PEM headers and newlines
    key = key.decode('utf-8')
    key = re.sub(r"-----BEGIN .*?-----", "", key)
    key = re.sub(r"-----END .*?-----", "", key)
    key = key.replace("\n", "")
    return key

wkey = strip_pem_headers(wkey)

with open("key.h", 'w') as f:
    f.write("#ifndef DEFINE_KEY\n")
    f.write(f'static const char KEY[] = "{wkey}";\n')
    f.write("#endif // KEY_H\n")

    #Thanks max

    #convert to der