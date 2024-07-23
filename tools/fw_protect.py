#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation and team BRUGH!!. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import random
from Crypto.Cipher import AES
from pwn import *
from Crypto.Hash import SHA256

# Pads the input data using random characters
# Takes the data to be padded, and the completed size
# Returns padded data
def randPad(data, size):
    # Calculates the number of bytes of padding
    toPad = size - len(data) % size

    randData = b""
    # Generates padding
    for i in range(toPad):
        randData += p8(random.randint(0, 255), endian = "little")

    return data + randData

# Encrypts the input data using CBC
# Takes the data to be encrypted, the key,
# and additional authenticated data
# Returns the encypted data
def encrypt(data, key, header):
    #create hash, but don't send it over yet
    
    h = SHA256.new()
    h.update(data)

    # Returns encrypted data, tag and IV
    plaintext = data + h.digest()
    cipher = AES.new(key, AES.MODE_CBC)
    
    iv = cipher.iv
    ct_bytes = cipher.encrypt(plaintext)
    
    return(ct_bytes + iv)

# Packages the firmware
# Takes firmware location, output location,
# version, release message, and keys location
def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Instantiate and read the key
    key = b""
    header = b""
    with open ("../bootloader/secret_build_output.txt", "rb") as fp:
        key = fp.read(16)
        fp.read(1); # Gets rid of new line between key
        header = fp.read(16)

    # Encrypt the firmware
    messageAndDataEncrypted = b""
    i = 0
    messageBin = message.encode()
    messageBin += b"\x00"
    firmwareAndMessage = firmware + messageBin #Smushes firmware adnd message together
    # Breaks into chunks
    for i in range (0, len(firmwareAndMessage), 1024):
        # Check if the data fills a full 0x400 chunk
        if ((len(firmwareAndMessage) - i) // 1024 != 0):
            temp = p8(2, endian = "little") + encrypt(firmwareAndMessage[i : i + 1024], key, header) # Message type + firmware
            messageAndDataEncrypted += temp
    # If the last chunk is not a 0xF chunk, pads and encrypts
    if (len(firmwareAndMessage) % 1024 != 0):
        temp = randPad((firmwareAndMessage[i : len(firmwareAndMessage)]), 1024) # Message type + firmware + padding
        messageAndDataEncrypted += p8(2, endian = "little") + encrypt(temp, key, header)


    # Create START frame
    # Temp is the type + version num + firmware len + RM len + padding
    temp = randPad(p16(version, endian = "little") + p16(len(firmware), endian = "little") + p16(len(messageBin), endian = "little"), 1024)
    begin = p8(1, endian = "little") + encrypt(temp, key, header)

    # Create END frame
    # Temp is the type + padding
    temp = randPad(b"", 1024)
    end = p8(3, endian = "little") + encrypt(temp, key, header)

    # For debugging?
    # print(begin)
    
    # Smush the START frame, encrypted firmware and RM, and END frame together
    firmware_blob = begin + messageAndDataEncrypted + end
    # Write encrypted firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)
    
# Runs the program
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)#Calls the firmware protect method
    # EXAMPLE COMMAND TO RUN THIS CODE
    # python3 ./fw_protect.py --infile ../firmware/gcc/main.bin --outfile ../firmware/gcc/protected.bin --version 0 --message lolz
