from pwn import *
import time
import serial
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x00"
FRAME_SIZE = 256

data = b"\0x00\0x00\0x00\0x00\0x00"
key = randbytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
iv = cipher.iv

print(ct_bytes)

print(ser.readline())#Reads greeting
ser.write(iv)#Writes IV
print(ser.readline())#Reads greeting
ser.write(p16(len(ct_bytes)))#Writes length
print(u16(ser.read(2)))
print(ser.readline())#Reads ret
ser.write(ct_bytes)
print(ser.readline())#Reads ret
print(ser.readline())#Reads ret
print(ser.readline())#Reads ret
print(ser.read(len(ct_bytes)))#Reads plaintext
print(ser.readline())#Reads ret

