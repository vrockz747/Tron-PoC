#include <stdio.h>
#include "./nanopb/pb_decode.h"
#include "./proto/tron.pb.h"
#include <string.h>
#include "sha2.h"
#include "secp256k1.h"
#include "ecdsa.h"
#include "./proto/Contract.pb.h"


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
    const char *hexData = "0a02dc2a220810bfeb129a05639f40809ad082ef315a66080112620a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412310a1541fd49eda0f23ff7ec1d03b52c3a45991c24cd440e12154198927ffb9f554dc4a453c64b2e553a02d6df514b18ad2c7097d6cc82ef31";
    size_t hexDataLength = strlen(hexData) / 2;
    
    uint8_t buffer[hexDataLength];hexStringToByteArray(hexData, buffer, hexDataLength);

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
    //printf("Decoding succeeded.\n");
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
    //hash the raw data
    sha256_Raw(buffer,hexDataLength,hash);

    //PvtKey:https://github.com/tronprotocol/Documentation/blob/master/English_Documentation/Procedures_of_transaction_signature_generation.md
    const char *phex= "8e812436a0e3323166e1f0e8ba79e19e217b2c4a53c970d4cca0cfb1078979df";
    size_t plen = strlen(phex) / 2;
    uint8_t pvkey[plen];

    hexStringToByteArray(phex,pvkey,plen);

    const char *hash_demo_hex = "159817a085f113d099d3d93c051410e9bfe043cc5c20e43aa9a083bf73660145";
    uint8_t hash_demo[32];
    hexStringToByteArray(hash_demo_hex,hash_demo,32);

    for(int i =0;i<SHA256_DIGEST_LENGTH;i++){
        //printf("%02x",hash[i]);
    }
    uint8_t sig[64];
    uint8_t v_value = 0;
    ecdsa_sign_digest(&mycurve,pvkey,hash_demo,sig,&v_value,NULL);

    printf("\nr value: ");
    for(int i =0;i<64;i++){
        printf("%02x",sig[i]);
        if (i == 31 ) printf("\ns value: ");

    }
    printf("\nv value: %i\n",v_value);
    uint8_t public_key[65]; //""
    ecdsa_recover_pub_from_sig(&mycurve,public_key,sig,hash_demo,v_value);
    printf("Uncomp. Public Key: ");
    for(int i =0;i<65;i++){
        printf("%02x",public_key[i]);
    }
    printf("\n");
    extract_contract_info(&transaction);
}


void extract_contract_info(protocol_Transaction_raw* transaction_raw) {
    if (transaction_raw->contract_count > 0) {
        protocol_Transaction_Contract contract = transaction_raw->contract[0];  // Example for the first contract

        protocol_TransferContract transfer_contract;// = protocol_TransferContract_init_default;
        
         //Check the type of contract and process accordingly
        switch (contract.type) {
            case protocol_Transaction_Contract_ContractType_TransferContract:
                google_protobuf_Any any = contract.parameter;
                pb_istream_t stream = pb_istream_from_buffer(any.value.bytes, any.value.size);

                int status = pb_decode(&stream, protocol_TransferContract_fields, &transfer_contract);
                if (status) {
                    // Access fields from transfer_contract, e.g., transfer_contract.to_address
                    printf("Address Decoded!");
                }
                else{
                    printf("\nAddress Decoding Failed!");

                }
                //pb_istream_t stream = pb_istream_from_buffer(any->value, sizeof(protocol_TransferContract));     
            default:
        }
        

        printf("\nAmount: %li :",transfer_contract.amount);
        printf("\nOwner Address: ");
        for(int i =0;i<sizeof(transfer_contract.owner_address);i++){
            printf("%02x",(uint8_t)transfer_contract.owner_address[i]);
        }
        printf("\nTo Address: ");
        for(int i =0;i<sizeof(transfer_contract.to_address);i++){
            printf("%02x",(uint8_t)transfer_contract.to_address[i]);
        }



    }
}


// https://github.com/tronprotocol/Documentation/blob/master/TRX/Tron-overview.md#6-user-address-generation
// https://github.com/LedgerHQ/app-tron/blob/6a86b1147a5ffa4c52ed9eb38e5590d2cf91eefc/proto/core/Tron.proto

