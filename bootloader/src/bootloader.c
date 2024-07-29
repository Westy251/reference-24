// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}

int main(){

    initialize_uarts(UART0);
    uart_write_str(UART0, "Welcome to Roblox Institute of Technology!!! \n");

    // Imported variables
    RsaKey priv;
    RsaKey pub;
    RsaKey enc;
    
    // Note, the wolfssl original RsaKey rng is not recommended
    #include "key.h"

    // Definitions
    int ret;
    byte e[] = {0x1, 0x0, 0x1}; // Initialize with received e component of the public key
    byte n[] = {0xd9, 0x93, 0xea, 0x0, 0xa3, 0x3f, 0xf0, 0xd2, 0xcd, 0x69, 0xed, 0x83, 0x53, 0xa1, 0x25, 0xfe, 0x84, 0x63, 0x69, 0x21, 0x8, 0x4b, 0x8d, 0xea, 0x1, 0xba, 0x37, 0xd2, 0x6b, 0x4e, 0xa3, 0xd5, 0xfc, 0x3b, 0xcd, 0x85, 0x3a, 0xb6, 0xaa, 0x4a, 0x8d, 0x87, 0xf1, 0x6c, 0xce, 0xed, 0x4d, 0xdd, 0xb2, 0x60, 0x10, 0xf0, 0xcc, 0xd7, 0x1f, 0x56, 0x22, 0xc, 0xb3, 0x44, 0xd, 0x7d, 0x56, 0xb6, 0x7a, 0xda, 0xf5, 0x9e, 0x8, 0x62, 0x23, 0x79, 0x5, 0xe9, 0x54, 0x23, 0x1f, 0x74, 0x39, 0xb, 0xc, 0xee, 0xc7, 0xf3, 0xea, 0x4e, 0xa4, 0x2f, 0xae, 0x6f, 0x1f, 0xe1, 0x2, 0xc4, 0x8e, 0x14, 0x14, 0x8f, 0x84, 0x65, 0x46, 0xeb, 0x74, 0x83, 0xda, 0x1a, 0x8b, 0x6, 0x7c, 0xfb, 0x80, 0xc2, 0xbe, 0x2b, 0xe9, 0x19, 0x23, 0xfa, 0x61, 0x9d, 0x4c, 0x71, 0xa, 0x91, 0xf9, 0x79, 0xa2, 0xe7, 0x3a, 0x3, 0xca, 0x8a, 0x1f, 0x86, 0xcf, 0x3f, 0xae, 0xe3, 0xe2, 0xe5, 0x94, 0x4b, 0x15, 0x43, 0x16, 0x38, 0xa3, 0x63, 0x7, 0x38, 0xf7, 0x59, 0x1a, 0x53, 0xcb, 0xf9, 0x3a, 0x41, 0x29, 0x8e, 0x3, 0x4e, 0xd4, 0xcf, 0xe2, 0x46, 0xe7, 0xdc, 0x3e, 0x12, 0xac, 0x44, 0x95, 0x26, 0xea, 0xe5, 0xd6, 0xb4, 0xba, 0x58, 0xb4, 0x7b, 0xdf, 0x8d, 0xb5, 0x41, 0xdc, 0xe1, 0xd, 0xf5, 0x3c, 0xcb, 0x1, 0x7, 0x2e, 0xf4, 0xf, 0x62, 0xa9, 0x3d, 0xe, 0x5d, 0x86, 0x75, 0x5c, 0x11, 0xf5, 0xbe, 0xbe, 0xd5, 0xd1, 0x87, 0x27, 0x55, 0xda, 0x5b, 0xba, 0x8d, 0xcc, 0xbc, 0x4b, 0xa5, 0xb0, 0xc7, 0xb7, 0x45, 0xdc, 0x49, 0x8d, 0xb, 0x55, 0xe5, 0x7c, 0x16, 0x58, 0x88, 0x2e, 0xd2, 0x62, 0xc, 0xbe, 0x68, 0xc1, 0x1f, 0xcc, 0xee, 0xa8, 0x4b, 0x21, 0xdb, 0xe2, 0x1c, 0x50, 0xfb, 0x98, 0xa0}; // Initialize with received n component of the public key
    //byte plaintext[256] = {0xff, 0xff, 0xff, 0xff, 0xff}; 
    byte plaintext[256];
    byte ciphertext[] = {0xb6, 0x9a, 0xf8, 0xe2, 0x51, 0xed, 0xf4, 0x1c, 0x6f, 0xad, 0xc4, 0x3c, 0x11, 0xbc, 0x12, 0x26, 0xdb, 0xd1, 0x97, 0xa7, 0xc3, 0xb8, 0x99, 0x2c, 0xc5, 0x3b, 0x88, 0x98, 0x26, 0xd3, 0xfd, 0x10, 0x3d, 0x71, 0x23, 0xa8, 0xd6, 0x1f, 0x5f, 0xb2, 0x38, 0x77, 0x7a, 0x45, 0xc1, 0xde, 0x41, 0xd, 0xe2, 0xa, 0x8, 0x72, 0x75, 0xe5, 0x6b, 0x7b, 0xa2, 0x4, 0x7b, 0x94, 0xc9, 0x86, 0x93, 0x46, 0xff, 0xa2, 0xd9, 0xcd, 0x0, 0x11, 0x49, 0x80, 0x21, 0xb7, 0xf2, 0xe9, 0x83, 0xd4, 0xb1, 0xc3, 0x8c, 0x96, 0x58, 0x46, 0x35, 0xb0, 0xd2, 0xfb, 0xe, 0xab, 0x6c, 0xaf, 0x11, 0xa8, 0x29, 0x1f, 0x9d, 0xc3, 0x1a, 0xb, 0x24, 0xb3, 0x6c, 0xb7, 0xa2, 0x7, 0x33, 0xa8, 0xc9, 0x95, 0x5e, 0xfa, 0x54, 0xea, 0x92, 0x72, 0x3d, 0xe7, 0xff, 0x18, 0x11, 0xe2, 0xc6, 0x79, 0xd9, 0x31, 0xf8, 0x63, 0x3d, 0xc, 0xeb, 0x62, 0x6d, 0x96, 0x3a, 0x68, 0xbc, 0x4f, 0x11, 0x3a, 0xd2, 0x13, 0xc3, 0x8f, 0xac, 0xdb, 0xbd, 0xc5, 0xb0, 0x35, 0x39, 0xed, 0xb8, 0xba, 0x4b, 0xe8, 0x47, 0x7e, 0x55, 0xc4, 0xeb, 0x57, 0xec, 0x8b, 0xbe, 0x7d, 0xe3, 0x5b, 0xe2, 0xb2, 0x30, 0x51, 0xd8, 0x3c, 0x20, 0x65, 0xd5, 0x96, 0xf4, 0x6b, 0xf, 0xcf, 0xe2, 0xf0, 0xa3, 0x69, 0xdf, 0xb4, 0x5c, 0x86, 0xf2, 0xed, 0xb0, 0xe4, 0xe7, 0xf2, 0xc9, 0x60, 0xd4, 0x94, 0x6b, 0x35, 0xd3, 0x4a, 0x67, 0xb0, 0xbd, 0x89, 0x5d, 0x59, 0x1c, 0x18, 0x7b, 0x1e, 0x22, 0xaa, 0x72, 0x72, 0xcd, 0x63, 0x93, 0x15, 0x71, 0xf1, 0x30, 0x73, 0xfc, 0xc4, 0xc, 0x92, 0x55, 0xae, 0x1d, 0x50, 0x73, 0x6e, 0x8d, 0xe9, 0x62, 0x14, 0xf2, 0x89, 0x7b, 0xb2, 0xef, 0xbd, 0xe, 0xe0, 0xd, 0x60, 0x6a, 0x78, 0x63, 0x7, 0x66, 0xe4};

    /*
    rsa_key_init(&pub);
    rsa_public_key_decode(&pub, pub, sizeof(pub));
    */

    wc_InitRsaKey(&enc, NULL);

    //wc_InitRng(KEY);
    //wc_MakeRSAKey(&priv, 2048, e, KEY);

    //wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &priv);

    //wc_RsaPublicEncrypt(plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext), &pub, KEY);

    //wc_RsaPrivateDecrypt(plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext), &KEY);

    wc_RsaSSL_Verify(plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext), KEY);
    
    uart_write_str(UART0, "RSA\n");

}
/*
int main(void) {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}
*/

 /*
 * Load the firmware into flash.
 */
void load_firmware(void) {
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;

    // Get version.
    rcv = uart_read(UART0, BLOCKING, &read);
    version = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    version |= (uint32_t)rcv << 8;

    // Get size.
    rcv = uart_read(UART0, BLOCKING, &read);
    size = (uint32_t)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART0, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
    while (1) {

        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length += (int)rcv;

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read);
            data_index += 1;
        } // for

        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            // Try to write flash and check for error
            if (program_flash((uint8_t *) page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        } // if

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}

void boot_firmware(void) {
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART0, (char *)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}
