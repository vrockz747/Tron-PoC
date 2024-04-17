#include <stdio.h>
#include "./nanopb/pb_decode.h"
#include "./proto/tron.pb.h"
#include <string.h>
#include "sha2.h"
#include "secp256k1.h"
#include "ecdsa.h"
#include "./proto/Contract.pb.h"


//https://github.com/tronprotocol/Documentation/blob/master/TRX/Tron-overview.md#6-user-address-generation

void hexStringToByteArray(const char *hexString, uint8_t *byteArray, size_t byteArrayLength) {
    for (size_t i = 0; i < byteArrayLength; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}
void extract_contract_info(protocol_Transaction_raw* transaction_raw);

int main() {
    const ecdsa_curve mycurve = secp256k1;
    const ecdsa_curve *mycurveptr = &mycurve;
    const curve_point *G = &(mycurveptr->G);

    // Hex string from your raw_data_hex
    const char *hexData = "0a0271392208d291dee52544509340e8d39598f72f5a58080b12540a32747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e467265657a6542616c616e6365436f6e7472616374121e0a15411fafb1e96dfe4f609e2259bfaf8c77b60c535b9310a0968001180370a7939298f72f";
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
    const char *phex= "33fe9187089d4bf319de2e50889eba5f7e7e084b03edbb827600a765ce8ccb3d";
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
    
    extract_contract_info(&transaction);
}


void extract_contract_info(protocol_Transaction_raw* transaction_raw) {
    if (transaction_raw->contract_count > 0) {
        protocol_Transaction_Contract contract = transaction_raw->contract[0];  // Example for the first contract

        // Check the type of contract and process accordingly
        switch (contract.type) {
            case protocol_Transaction_Contract_ContractType_TransferContract:
                google_protobuf_Any *any = &contract.parameter;

                //pb_istream_t stream = pb_istream_from_buffer(any->value, sizeof(protocol_TransferContract));
                protocol_TransferContract transfer_contract = protocol_TransferContract_init_default;
                if (pb_decode((pb_istream_t *)&any->value, protocol_TransferContract_fields, &transfer_contract)) {
                    // Access fields from transfer_contract, e.g., transfer_contract.to_address
                    printf("\nAddress Decoded!");
                    break;
                }
            default:
                    printf("\nAddress Decoding Failed!");
        }
        
    }
}

