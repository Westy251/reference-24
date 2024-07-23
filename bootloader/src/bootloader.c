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
#include "../keys.h" // !! ACCESS TO KEY

// Library Imports
#include <string.h>
#include <wolfssl.h>

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
// Brugh Forward Declarations
int uart_read_bytes(int bytes, uint8_t* dest);
int frame_decrypt(uint8_t *arr, int expected_type);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash
// Brugh Firmware Constants
#define FW_VERSION_ADDRESS (uint16_t *)METADATA_BASE;
#define FW_SIZE_ADDRESS (uint16_t *)(METADATA_BASE + 2);

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')
// Brugh Protocol Constants
#define END ((unsigned char)0x02)
#define TYPE ((unsigned char)0x04)

// Device metadata
//version and size address defined in "Brugh Firmware Constants"
//uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
//uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE]; // !! move to load initial firmware

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

/*
 * ****************************************************************
 * Reads a given number of bytes from UART1
 * 
 * \param bytes is the number of bytes to be read
 * \param dest is where to write them
 *
 * \return Returns 0 if reading successful, 1 if not
 * ****************************************************************
 */
// !! EDIT ME
int uart_read_bytes(int bytes, uint8_t* dest){
    int rcv = 0;//Received data
    int read = 0; //Flag that reports on success of read operation
    int result = 0;//Stores operation status
    for (int i = 0; i < bytes; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        dest[i] = rcv;
        if (read != 0){
            result = 1;
        }
    }
    return result;
}

/* ****************************************************************
 *
 * Reads and decrypts a packet as well as checking its HASH.
 *
 * \param arr is the array that unencrypted data will be written to.
 * 
 * \return Returns a 0 on success, or a 1 if the GHASH was invalid.
 * 
 * ****************************************************************
 */
// !! EDIT ME
int frame_decrypt(uint8_t *arr, int expected_type){
    // Misc vars for reading
    int read = 0;
    uint32_t rcv = 0;
    int error = 0;

    uint8_t encrypted[1056];
    uint8_t iv[16];

    unsigned char gen_hash[32];

    // Zero out the generated hash array
    for (int c = 0; c < 32; c++){
        gen_hash[c] = 0;
    }

    // Read and check TYPE
    if (uart_read(UART1, BLOCKING, &read) != (int) expected_type){
        error = 1;
        return error;
    }

    // Reads DATA and HASH
    for (int i = 0; i < 1056; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        encrypted[i] = rcv;
    }
    // Reads IV
    for (int i = 0; i < 16; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        iv[i] = rcv;
    }

    // Unencrypt w/ CBC
    const br_block_cbcdec_class* vd = &br_aes_big_cbcdec_vtable;
    br_aes_gen_cbcdec_keys v_dc;
    const br_block_cbcdec_class **dc;
    dc = &v_dc.vtable;
    vd->init(dc, KEY, 16);
    vd->run(dc, iv, encrypted, 1056);

    // Put unencrypted firmware into output array
    for (int i = 0; i < 1024; i += 1) {
        arr[i] = encrypted[i];
    }

    // Init hash variables
    br_sha256_context ctx;
    int owo = sizeof(br_sha256_context);
    for (int uwu = 0; uwu < owo; uwu++){
        ((uint8_t *)&ctx)[uwu] = 0;
    }
    // Generate HASH
    br_sha256_init(&ctx); // Initialize SHA256 context
    br_sha256_update(&ctx, arr, 1024); // Update context with data
    br_sha256_out(&ctx, gen_hash);

    // Compare new HASH to old HASH
    for (int i = 0; i < 32; i += 1) {
        if (gen_hash[i] != encrypted[1024 + i]){
            error = 1;
        }
    }

    return error;
}

/* ****************************************************************
 *
 * Recieves and decrypts all frames using frame_decrypt()
 * 
 * Writes start firmware metadata, firmware data, and release message
 * to flash
 * 
 * ****************************************************************
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
