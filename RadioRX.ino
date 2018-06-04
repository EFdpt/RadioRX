#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>
#include <Base64.h>

#define CTR 1

#include "aes.h"

#define CIPHER_MAX_LENGTH     1024 // multiplo di 16

#define IV_LEN                AES_KEYLEN

char key[AES_KEYLEN] = {   0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 
                                        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 
                                        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }; // 24 bytes
char iv[IV_LEN + 1];
char cipher[CIPHER_MAX_LENGTH + 1] = {0};

#define BASE64_ENC_LEN(n)   ((n + 2 - ((n + 2) % 3)) / 3 * 4)

RF24 radio(8, 7);
const uint64_t pipe = 0xE8E8F0F0E1LL;

void setup(void) {
    Serial.begin(115200);
    while (!Serial);

    radio.begin();
    radio.openReadingPipe(1, pipe);
    radio.startListening();
}

#define ENCODED_MAX_LEN     BASE64_ENC_LEN(IV_LEN) + BASE64_ENC_LEN(CIPHER_MAX_LENGTH)

char encodedString[ENCODED_MAX_LEN];

inline void decrypt_model(char* buffer, char* iv, uint16_t plain_len, uint16_t buffer_len) {
    
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, (const uint8_t*) key, (const uint8_t*) iv);

    AES_CTR_xcrypt_buffer(&ctx, (uint8_t*) buffer, buffer_len);
}

void loop(void) {
    if (radio.available()) {
        radio.read(encodedString, ENCODED_MAX_LEN);
            
        memset(cipher, 0, CIPHER_MAX_LENGTH);
        memset(iv, 0, IV_LEN);

        int encodedIvLength = Base64.encodedLength(IV_LEN);
        int decodedLength = Base64.decodedLength(encodedString, Base64.encodedLength(CIPHER_MAX_LENGTH));
        char decodedString[decodedLength];

        Base64.decode(iv, encodedString, encodedIvLength);
        Base64.decode(decodedString, encodedString + encodedIvLength, decodedLength);
        
        decrypt_model(decodedString, iv, decodedLength, CIPHER_MAX_LENGTH);

        // remove padding
        unsigned char padding = decodedString[decodedLength - 1];
        memset(decodedString + (decodedLength - padding), 0, padding);

        Serial.println(decodedString);
        Serial.flush();
    }
}
