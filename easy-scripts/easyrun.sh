#/bin/bash

echo "You are running easyrun.sh"

read -p "Press <ENTER> to start:" response0

echo "Starting with bl_build.py"

cd ./tools

echo "If an error occurs in build.py, try copying wolfssl onto ./lib/wolfssl"
read -p "Press <ENTER> to continue:" response1

echo "Building..."

python bl_build.py

echo "Flashing. Make sure you have your board connected."
read -p "Press <ENTER> to continue:" response2

echo "Flashing..."

sudo lm4flash ../bootloader/bin/bootloader.bin

echo "Flash successful!"

cd ..

echo "Making firmware..."

python tools/bl_build.py

echo "Running protect.py..."

cd tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version $version --message $message

echo "Running update.py..."

python fw_update.py --firmware ./firmware_protected.bin

echo "At last, connecting to car serial."
read -p "Press <ENTER> to continue:" response3

echo "Connecting to car serial..."

car-serial