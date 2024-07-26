from Crypto.PublicKey import RSA


mykey = RSA.generate(2048)

print(mykey.export_key(passphrase="Skibidi"))

