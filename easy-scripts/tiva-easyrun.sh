#/bin/bash

cd ..

echo "starting with bl_build.py"

cd ./tools

echo "if an error occurs, try copying wolfssl onto ./lib/wolfssl"

python bl_build.py

echo "Flashing"

sudo lm4flash ../bootloader/bin/bootloader.bin

echo "Flash successful"

cd ..

echo "Making firmware..."

cd ./firmware
make

echo "Running protect.py..."

cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"

echo "Running update.py..."

python fw_update.py --firmware ./firmware_protected.bin

echo "Now to the car serial..."

car-serial
