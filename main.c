#include <stdio.h>
#include <pb_decode.h>
#include "proto/tron.pb.h"  // Make sure this is the correct path to your generated header
#include <string.h>

// Function to convert hex string to byte array
void hexStringToByteArray(const char *hexString, uint8_t *byteArray, size_t byteArrayLength) {
    for (size_t i = 0; i < byteArrayLength; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

int main() {
    // Hex string from your raw_data_hex
    const char *hexData = "0a020d9f220898db5757485586b540c8dc9cb6ee315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541fd49eda0f23ff7ec1d03b52c3a45991c24cd440e12154198927ffb9f554dc4a453c64b2e553a02d6df514b1822709b8d99b6ee31";
    size_t hexDataLength = strlen(hexData) / 2;
    
    // Buffer to store the byte array
    uint8_t buffer[hexDataLength]; // Buffer to store byte data

    // Convert hex string to byte array
    hexStringToByteArray(hexData, buffer, hexDataLength);

    // Set up the nanopb input stream
    pb_istream_t stream = pb_istream_from_buffer(buffer, hexDataLength);

    // Define a structure to hold the decoded data
    protocol_Transaction_raw transaction = protocol_Transaction_raw_init_zero;

    // Decode the byte array into the structure
    bool status = pb_decode(&stream, protocol_Transaction_raw_fields, &transaction);
    if (!status) {
        printf("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        return 1;
    }

    // Access decoded data from the structure
    printf("Decoding succeeded.\n");

    return 0;
}

