#include <stdio.h>
#include "./nanopb/pb_decode.h"
#include "proto/tron.pb.h"
#include <string.h>
#include "sha2.h"
#include "secp256k1.h"
#include "ecdsa.h"


//https://github.com/tronprotocol/Documentation/blob/master/TRX/Tron-overview.md#6-user-address-generation

void hexStringToByteArray(const char *hexString, uint8_t *byteArray, size_t byteArrayLength) {
    for (size_t i = 0; i < byteArrayLength; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

int main() {
    const ecdsa_curve mycurve = secp256k1;
    const ecdsa_curve *mycurveptr = &mycurve;
    const curve_point *G = &(mycurveptr->G);

    // Hex string from your raw_data_hex
    const char *hexData = "0a020d9f220898db5757485586b540c8dc9cb6ee315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541fd49eda0f23ff7ec1d03b52c3a45991c24cd440e12154198927ffb9f554dc4a453c64b2e553a02d6df514b1822709b8d99b6ee31";
    size_t hexDataLength = strlen(hexData) / 2;
    
    uint8_t buffer[hexDataLength];

    hexStringToByteArray(hexData, buffer, hexDataLength);

    for(int i =0;i<hexDataLength;i++){
        //printf("%02x",buffer[i]);
    }

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
    printf("Decoding succeeded.\n");
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
    //hash the raw data
    sha256_Raw(buffer,hexDataLength,hash);

    //PvtKey:
    const char *phex= "b81bd3e840f624f1ebda1c9572e2e2653ce3b1008aa99489f30e90ada64047c0";
    size_t plen = strlen(phex) / 2;
    uint8_t pvkey[plen];

    hexStringToByteArray(phex,pvkey,plen);

    for(int i =0;i<plen;i++){
    //    printf("%02x",pvkey[i]);
    }
    uint8_t sig[64];
    ecdsa_sign_digest(&mycurve,pvkey,hash,sig,NULL,NULL);

    for(int i =0;i<plen;i++){
        printf("%02x",sig[i]);
    }
    return 0;
}

