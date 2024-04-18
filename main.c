#include <stdio.h>
#include "./nanopb/pb_decode.h"
#include "./proto/tron.pb.h"
#include <string.h>
#include "sha2.h"
#include "sha3.h"
#include "secp256k1.h"
#include "ecdsa.h"
#include "bip32.h"
#include "./proto/Contract.pb.h"
#include "base58.h"


void hexStringToByteArray(const char *hexString, uint8_t *byteArray, size_t byteArrayLength) {
    for (size_t i = 0; i < byteArrayLength; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

void extract_contract_info(protocol_Transaction_raw* transaction_raw);

bool derive_hdnode_from_path(const uint32_t *path,
                             const size_t path_length,
                             const char *curve,
                             const uint8_t *seed,
                             HDNode *hdnode);

int main() {
    const ecdsa_curve mycurve = secp256k1;
    const ecdsa_curve *mycurveptr = &mycurve;
    const curve_point *G = &(mycurveptr->G);

    // Hex string from your raw_data_hex
    const char *hexData = "0a02dc2a220810bfeb129a05639f40809ad082ef315a66080112620a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412310a1541fd49eda0f23ff7ec1d03b52c3a45991c24cd440e12154198927ffb9f554dc4a453c64b2e553a02d6df514b18ad2c7097d6cc82ef31";
    size_t hexDataLength = strlen(hexData) / 2;
    uint8_t buffer[hexDataLength];hexStringToByteArray(hexData, buffer, hexDataLength);

    //Converting raw_data_hex to Transaction_raw type
    {
        // Set up the nanopb input stream
        pb_istream_t stream = pb_istream_from_buffer(buffer, hexDataLength);
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
        extract_contract_info(&transaction);

    }


    // Example: (TEST)
    // PvtKey, Hash_demo :https://github.com/tronprotocol/Documentation/blob/master/English_Documentation/Procedures_of_transaction_signature_generation.md
    {
        const char *phex= "8e812436a0e3323166e1f0e8ba79e19e217b2c4a53c970d4cca0cfb1078979df";
        size_t plen = strlen(phex) / 2;
        uint8_t pvkey[plen];
        hexStringToByteArray(phex,pvkey,plen);
        // Hash_demo
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
    }

    printf("\n");

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

void generateAddress(const uint8_t *seed, const uint32_t *path, uint32_t path_length, uint8_t *public_key){

    // gen public key from seed:
    HDNode node = {0};

    derive_hdnode_from_path(path, path_length, "secp256k1", seed, &node);

    ecdsa_uncompress_pubkey(get_curve_by_name("secp256k1")->params, node.public_key, public_key);
    //memzero(&node, sizeof(HDNode));
    
    // gen Address:
    uint8_t initial_address[1 + 20 + 4] = {0}; //initial address
    initial_address[0] = 41;
    //hash pubkey using sha3-256
    uint8_t hashed_pubkey[32];
    #define USE_KECCAK 1
    sha3_256(public_key,64,hashed_pubkey);

    // extract last 20 bytes
    // address = 41||sha3[12,32)
    for(int i = 12;i < 32;i++){
        initial_address[i - 12 + 1] = hashed_pubkey[i];
    }
    // sha256(address) x 2
    uint8_t hash_address[SHA256_DIGEST_LENGTH];
    sha256_Raw(initial_address,21,hash_address);
    sha256_Raw(hash_address,32,hash_address);
    
    // checkSum = sha256_1[0, 4):
    for(int i = 32; i<36; i++){
        initial_address[i] = hash_address[i - 32];
    }

    base58_encode_check(initial_address,)
}

bool derive_hdnode_from_path(const uint32_t *path,
                             const size_t path_length,
                             const char *curve,
                             const uint8_t *seed,
                             HDNode *hdnode) {
  hdnode_from_seed(seed, 512 / 8, curve, hdnode);
  for (size_t i = 0; i < path_length; i++) {
    if (0 == hdnode_private_ckd(hdnode, path[i])) {
      // hdnode_private_ckd returns 1 when the derivation succeeds
      return false;
    }
  }
  hdnode_fill_public_key(hdnode);
  return true;
}

// https://github.com/tronprotocol/Documentation/blob/master/TRX/Tron-overview.md#6-user-address-generation
// https://github.com/LedgerHQ/app-tron/blob/6a86b1147a5ffa4c52ed9eb38e5590d2cf91eefc/proto/core/Tron.proto

