from pwn import *
import time
import serial
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x00"
FRAME_SIZE = 256

data = b"thisisatestinpu"
key = randbytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
iv = cipher.iv

print(ct_bytes)

