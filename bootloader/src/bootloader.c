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
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"
Aes dec;
Aes enc;

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
    */

    wc_AesGCMSetKey(&dec, KEY, 2 /*idk if this is key size*/, /*where is devId*/);
    wc_AesSetIV(&dec, iv);
    wc_AesGcmDecrypt(&dec, encrypted, 1056, iv, /*authtag and its sizes missing*/);

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
    }*/

   wc_AesGcmDecrypt(Aes * aes, byte * out, const byte * in, word32 sz, const byte * iv, word32 ivSz, const byte * authTag, word32 authTagSz, const byte * authIn, word32 authInSz)

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

    // the good old Brugh codes of load firmware
    uart_write_str(UART0, "\nUpdate started\n");

    int error = 0;              // stores frame_decrypt return
    int error_counter = 0;

    uint32_t data_index = 0;            // Length of current data chunk written to flash
    uint32_t page_addr = FW_BASE;   // Address to write to in flash
    
    // variables to store data from START frame
    uint16_t version;
    uint16_t f_size;
    uint16_t r_size;

    // Firmware Buffer
    unsigned char complete_data[1024];
    // ************************************************************
    // Read START frame and checks for errors
    do {
        // Read frame
        error = frame_decrypt(complete_data, 1);

        // Get version (0x2)
        version = (uint16_t)complete_data[0];
        version |= (uint16_t)complete_data[1] << 8;
        uart_write_str(UART0, "Received Firmware Version: ");
        uart_write_hex(UART0, version);
        nl(UART0);
        // Get release message size in bytes (0x2)
        f_size = (uint16_t)complete_data[2];
        f_size |= (uint16_t)complete_data[3] << 8;
        uart_write_str(UART0, "Received Firmware Size: ");
        uart_write_hex(UART0, f_size);
        nl(UART0);
        // Get firmware size in bytes (0x2) 
        r_size = (uint16_t)complete_data[4];
        r_size |= (uint16_t)complete_data[5] << 8;
        uart_write_str(UART0, "Received Release Message Size: ");
        uart_write_hex(UART0, r_size);
        nl(UART0);

        // Get version metadata
        uint16_t old_version = *FW_VERSION_ADDRESS;
        // If version 0 (debug), don't change version
        if (version == 0){
            version = old_version;
        }

        // Check for HASH error
        if (error == 1){
            uart_write_str(UART2, "Incorrect Hash or Type\n");
        // If version less than old version, reject and reset
        } else if ((version < old_version)){
            uart_write_str(UART2, "Incorrect Version\n");
            error = 1;
        }

        // Reject metadata if any error
        if (error == 1){
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
        }

        // Implements error timeout
        // If 10+ errors for a single frame, end by returning out of method
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Timeout: too many errors\n");
            uart_write(UART1, TYPE);
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }
    } while (error != 0);

    // Resets counter, since start frame successful
    error_counter = 0;

    // Write metadata to flash (firmware size and version) 
    // Version is at lower address, size is at higher address
    uint32_t metadata = ((f_size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    // Acknowledge the metadata.
    uart_write_str(UART0, "Metadata written to flash\n");
    uart_write(UART0, TYPE);
    uart_write(UART0, OK);

// ************************************************************
    // Process DATA frames
    int total_size = f_size + r_size;
    for (int i = 0; i < total_size; i += 1024){
        // Reading and checking for errors
        do {
            // Read frame
            error = frame_decrypt(complete_data, 2);

            // Error handling
            if (error == 1){
                uart_write_str(UART0, "Incorrect Hash or Type\n");
                uart_write(UART0, TYPE);
                uart_write(UART0, ERROR);
            }

            // Error timeout implementation
            error_counter += error;
            if(error_counter > 10){
                uart_write_str(UART0, "Timeout: too many errors\n");
                uart_write(UART0, TYPE);
                uart_write(UART0, END);
                SysCtlReset();
                return;
            }

        } while (error != 0);

        // Write that packet has been recieved
        uart_write_str(UART0, "Recieved bytes at ");
        uart_write_hex(UART0, i);
        nl(UART0);

        if (total_size - i < FLASH_PAGESIZE) {
            data_index = total_size - i;
        } else {
            data_index = FLASH_PAGESIZE;
        }

        // Writing to flash
        do {
            // Write to flash, then check if data and memory match
            if (program_flash(page_addr, complete_data, data_index) == -1){
                uart_write_str(UART0, "Error while writing\n");
                uart_write(UART0, TYPE);
                uart_write(UART0, ERROR);
                error = 1;
            } else if (memcmp(complete_data, (void *) page_addr, data_index) != 0){
                uart_write_str(UART0, "Error while writing\n");
                uart_write(UART0, TYPE);
                uart_write(UART0, ERROR);
                error = 1;
            }
                    
            // Error timeout
            error_counter += error;
            if (error_counter > 10){
                uart_write_str(UART0, "Timeout: too many errors\n");
                uart_write(UART0, TYPE);
                uart_write(UART0, END);
                SysCtlReset();
                return;
            }
        } while(error != 0);

        // Write success and debugging messages to UART2.
        uart_write_str(UART0, "Page successfully programmed\nAddress: ");
        uart_write_hex(UART0, page_addr);
        uart_write_str(UART0, "\nBytes: ");
        uart_write_hex(UART0, data_index);
        nl(UART0);

        // Update to next page
        page_addr += FLASH_PAGESIZE;
        data_index = 0;


        // Send packet recieved success message
        uart_write(UART0, TYPE);
        uart_write(UART0, OK);
        
        // Reset counter inbetween packets
        error_counter = 0;
    }
    // ************************************************************
    // Process END frame
    do {
        // Read frame
        error = frame_decrypt(complete_data, 3);
            
        // Error handling
        if (error == 1){
            uart_write_str(UART0, "Incorrect Hash or Type\n");
            uart_write(UART0, TYPE);
            uart_write(UART0, ERROR);
        }

        // Error timeout implementation
        error_counter += error;
        if(error_counter > 10){
            uart_write_str(UART0, "Timeout: too many errors\n");
            uart_write(UART0, TYPE);
            uart_write(UART0, END);
            SysCtlReset();
            return;
        }

    } while (error != 0);

    uart_write_str(UAUART0RT2, "End frame processed\n\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧\n");

    // End return
    uart_write(UART0, TYPE);
    uart_write(UART0, OK);
    
    uart_write_str(UART0, "Received Firmware Version: ");
    uart_write_hex(UART0, version);
    uart_write_str(UART0, "Received Release Message Size: ");
    uart_write_hex(UART0, r_size);
    uart_write_str(UART0, "Received Firmware Size: ");
    uart_write_hex(UART0, f_size);
    return;
}

/* ****************************************************************
 *
 * Programs a stream of bytes to the flash.
 * Also performs an erase of the specified flash page before writing
 * the data.
 * 
 * \param page_addr is the starting address of a 1KB page. Must be 
 * a multiple of four
 * \param data is a pointer to the data to write.
 * \param data_len is the number of bytes to write.
 * 
 * \return Returns 0 on success, or -1 if an error is encountered
 *
 * ****************************************************************
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
