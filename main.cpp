/*
* Copy right: HolyChen.
* Create Time: 2014.
* Lisence: MIT/X.
* Reference: RFC 1321 http://www.rfc-editor.org/rfc/rfc1321.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

/*
* ------------------- NOCATION! -------------------
* ALL char, long used to calculate MD5, must be unsigned!.
* ------------------- NOCATION! -------------------
*/


void UNIT_TEST(int order, char* src, char* expectMD5);

/*
* Calculate 32-bit MD5 code of clear text.
* @param clearText data need encrypting
* @param originLength length of clear text.
* @return a unsigned char array in heap, which represents md5 code of clearText in ASCII encoding.
*/
char* calculateMD5(unsigned char* clearText, unsigned long long originLength);


int main(int argc, char *argv[]) {
    UNIT_TEST(1, "", "d41d8cd98f00b204e9800998ecf8427e");
    UNIT_TEST(2, "a", "0cc175b9c0f1b6a831c399e269772661");
    UNIT_TEST(3, "abc", "900150983cd24fb0d6963f7d28e17f72");
    UNIT_TEST(4, "message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    UNIT_TEST(5, "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
    return 0;
}

void UNIT_TEST(int order, char* src, char* expectMD5) {
    char *md5;
    md5 = calculateMD5((unsigned char*)src, strlen(src));
    printf("Test Case %d\n", order);
    printf("************************ Start ************************\n");
    printf("String: %s\n", src);
    printf("\t       MD5: %s\n", md5);
    printf("\tExpect MD5: %s\n", expectMD5);
    printf("They are same: %s\n", strcmp(md5, expectMD5) == 0? "True" : "FALSE");
    printf("************************* End *************************\n");
    printf("\n\n\n");
    delete[] md5;
}

/*
* Calculate 32-bit MD5 code of clear text, you can write a script by simulate it.
* @param clearText data need encrypting
* @param originLength length of clear text.
* @return a unsigned char array in heap, which represents md5 code of clearText in ASCII encoding.
*/
char* calculateMD5(unsigned char* clearText, unsigned long long originLength) {
    unsigned char *paddedData;
    // padding the clear text
    unsigned long long paddedLength;
    paddedData = paddingClearText(clearText, originLength, &paddedLength);

    // Append origin information data length in bit.
    unsigned long long originBitLength = originLength * 8;
    unsigned long long totalLength;
    // append length of clearText in bit.
    paddedData = appendBitLength(paddedData, paddedLength, originBitLength, &totalLength);

    // The data would be used 4 byte a time, means a 32-bits word.
    unsigned long long newWordLength = totalLength / 4;

    unsigned long *state = new unsigned long[4] {
        WORD_A, WORD_B, WORD_C, WORD_D
    };
    // Process 16 word per block
    for (unsigned long i = 0; i < newWordLength / 16; i++) {
        md5Core(paddedData + i * 16 * 4, state);
    }
    delete[] paddedData;
    // To use easy, return a ascii represent to print directly.
    char* asciiRepre = getMD5inASCII(state);
    delete[] state;
    return asciiRepre;
}