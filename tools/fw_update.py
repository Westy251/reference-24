#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

import argparse
import time
import serial

from util import *

from Crypto.Util.Padding import pad
from pwn import *

OK = b"\x00"
ERROR = b"\x01"
END = b"\x02"

ser = serial.Serial("/dev/ttyACM0", 115200)

FRAME_SIZE = 1073

# Sends START frame
# Takes serial object, meta frame, and debug
def send_metadata(ser, metadata, debug=False):
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("Waiting for response...")
        pass
    print("Starting upload\n")
    
    send_frame(ser, metadata, debug)

# Sends frames
# Takes serial object, frame, and debug
def send_frame(ser, frame, debug=False):

    falsetimes = 0 # Error counter
    failed = True # Stores if sent frame was successful
    
    # Resend frame if frame fails to send
    while failed:
        # Self checks if time-out
        if falsetimes >= 10:
            raise RuntimeError("Invalid frame sent too many times, aborting")
        
        # Send frame to serial
        ser.write(frame) 
        
        # Get return message type and error number
        msgType = ser.read(1)
        errorNum = ser.read(1)


        time.sleep(0.1)
        
        # If debug mode on, prints error type
        if debug:
            print("Resp: {}".format(ord(errorNum)))
            
        # Check message type
        if msgType == b'\x04':
            # Check for success
            if errorNum == OK:
                failed = False
            # Check for error
            elif errorNum == ERROR:
                falsetimes += 1 # Increment error counter
            # Check for end
            elif errorNum == END:
                raise RuntimeError("Invalid frame sent too many times, aborting")
            # Check for invalid error
            else:
                raise RuntimeError("Invalid error, aborting")
        else:
            raise RuntimeError("Invalid message type, aborting")

# Sends all frames
# Takes serial object, encrypted frames location, and debug
# Returns serial object input
def update(ser, infile, debug):
    # Open and read file of encrypted packets
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    # Send START frame
    metadata = firmware_blob[:1073]
    send_metadata(ser, metadata, debug=debug)

    # Send DATA, MESSAGE, and END frames
    firmware = firmware_blob[1073:]
    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        # Chunk and write frames
        data = firmware[frame_start : frame_start + FRAME_SIZE]
        send_frame(ser, data, debug=debug)
        # Confirm frame has been written
        print(f"Wrote frame {idx} ({len(data)} bytes)")

    # Print end message
    print("Done writing firmware.")

    return ser

# Carries out program
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

  
    # Start updating
    update(ser=ser, infile=args.firmware, debug=args.debug)

