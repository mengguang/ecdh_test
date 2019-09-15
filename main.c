#include <stdio.h>
#include "uECC.h"
#include "ctype.h"

void hex_dump(const char *label, const uint8_t *data, uint32_t length) {
    printf(label);
    printf("0x");
    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int char_to_int(char input) {
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return 0;
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex_load(const char* src, uint8_t * target) {
    //skip 0x header
    if((src[0] == '0') && (tolower(src[1]) == 'x')) {
        src += 2;
    }
    while (*src && src[1]) {
        *(target++) = char_to_int(*src) * 16 + char_to_int(src[1]);
        src += 2;
    }
}

const char *hex_private_key = "0x424cc65c2514f2a3ce8a415d4823b0d6b5a659c31bb218dc65c31860286880ee";
//const char *hex_partner_public_key = "0x7130959ea6d1b055b33b768da0c95a06a1113767a03ccd6811ec39284d3c840e082145d731dc81063d8118b955ffd87df1c3a04aec271d595e415e7d0c39dc78";
const char *hex_partner_public_key = "0xaa64862f8675df6f863f14938256ae3065457a78cb5adbe0d22aa0b4846d74b0e8c0052bb66085615ffa9e11c917dea2f0577b47631ff3957eefd02355fc6c95";

int test_ecdh_002() {
    uint8_t private_key[32];
    uint8_t public_key[64];
    hex_load(hex_private_key,private_key);
    int result = 0;
    result = uECC_compute_public_key(private_key,public_key,uECC_secp256r1());
    if(result == 0) {
        printf("uECC_make_key error!\n");
        return -1;
    }

    hex_dump("public_key:\n",public_key,sizeof(public_key));
    uint8_t partner_public_key[64];
    hex_load(hex_partner_public_key,partner_public_key);

    result = uECC_valid_public_key(partner_public_key,uECC_secp256r1());
    hex_dump("partner public key:\n",partner_public_key,sizeof(partner_public_key));
    if(result == 0) {
        printf("uECC_valid_public_key error!\n");
        return -1;
    }
    uint8_t ecdh_secret[32];
    result = uECC_shared_secret(partner_public_key,private_key,ecdh_secret,uECC_secp256r1());
    if(result == 0) {
        printf("uECC_shared_secret error!\n");
        return -1;
    }
    hex_dump("ecdh_secret:\n",ecdh_secret,sizeof(ecdh_secret));

}

int test_ecdh_001() {

    uint8_t private_key_1[32];
    uint8_t public_key_1[64];

    uint8_t private_key_2[32];
    uint8_t public_key_2[64];

    int result = 0;
    result = uECC_make_key(public_key_1,private_key_1,uECC_secp256r1());
    if(result == 0) {
        printf("uECC_make_key error!\n");
        return -1;
    }

    hex_dump("private_key_1:\n",private_key_1,sizeof(private_key_1));
    hex_dump("public_key_1:\n",public_key_1,sizeof(public_key_1));

    result = uECC_make_key(public_key_2,private_key_2,uECC_secp256r1());
    if(result == 0) {
        printf("uECC_make_key error!\n");
        return -1;
    }

    hex_dump("private_key_2:\n",private_key_2,sizeof(private_key_2));
    hex_dump("public_key_2:\n",public_key_2,sizeof(public_key_2));

    uint8_t ecdh_secret_1[32];
    uint8_t ecdh_secret_2[32];
    result = uECC_shared_secret(public_key_1,private_key_2,ecdh_secret_1,uECC_secp256r1());
    if(result == 0) {
        printf("uECC_shared_secret error!\n");
        return -1;
    }

    result = uECC_shared_secret(public_key_2,private_key_1,ecdh_secret_2,uECC_secp256r1());
    if(result == 0) {
        printf("uECC_shared_secret error!\n");
        return -1;
    }

    hex_dump("ecdh_secret_1:\n",ecdh_secret_1,sizeof(ecdh_secret_1));
    hex_dump("ecdh_secret_2:\n",ecdh_secret_2,sizeof(ecdh_secret_2));

    return 0;
}

int main() {
    test_ecdh_002();
    return 0;
}