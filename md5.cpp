/*
* Copy right: HolyChen.
* Create Time: 2014.
* Lisence: MIT/X.
* Reference: RFC 1321 http://www.rfc-editor.org/rfc/rfc1321.txt
*/
#include "MD5.h"
#include <string.h>
#include <stdlib.h>

/*
 * ------------------- NOCATION! -------------------
 * ALL char, long used to calculate MD5, must be unsigned!.
 * ------------------- NOCATION! -------------------
 */


/*
 * Define the four auxiliary function the each take as input
 * three 32-bit words and prodcue as output one 32-bit word.
 */
inline unsigned long functionF(unsigned long x, unsigned long y, unsigned long z) {
    return (x & y) | (~x & z);
}

inline unsigned long functionG(unsigned long x, unsigned long y, unsigned long z) {
    return (x & z) | (y & ~z);
}

inline unsigned long functionH(unsigned long x, unsigned long y, unsigned long z) {
    return x ^ y ^ z;
}

inline unsigned long functionI(unsigned long x, unsigned long y, unsigned long z) {
    return y ^ (x | ~z);
}

/*
 * Define round left function in int_32.
 */
inline unsigned long roundLeft(unsigned long x, unsigned long n) {
    return (x << n) | (x >> (32 - n));
}

/*
 * Define four round function.
 */
inline void round1(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, unsigned long xk, unsigned long s, unsigned long ti) {
    *a = b + roundLeft((*a + functionF(b, c, d) + xk + ti), s);
}
    
inline void round2(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, unsigned long xk, unsigned long s, unsigned long ti) {
    *a = b + roundLeft((*a + functionG(b, c, d) + xk + ti), s);
}

inline void round3(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, unsigned long xk, unsigned long s, unsigned long ti) {
    *a = b + roundLeft((*a + functionH(b, c, d) + xk + ti), s);
}

inline void round4(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, unsigned long xk, unsigned long s, unsigned long ti) {
    *a = b + roundLeft((*a + functionI(b, c, d) + xk + ti), s);
}

/*
 * Get MD5 code in ASCII represent.
 */
char* getMD5inASCII(unsigned long state[4]) {
    
    unsigned char temp[16];
    for (int i = 0; i < 4; i++) {
        memcpy(temp + i * 4, (unsigned char*)(state + i), 4);
    }
    char* ascii = new char[33];
    for (int i = 0; i < 16; i++) {
        // 2 unsigned char width
        if ((temp[i] & 0xF0) != 0) {
            _ltoa(temp[i] & 0xff, ascii + i * 2, 16);
        } else {
            ascii[i * 2] = '0';
            _ltoa(temp[i] & 0xff, ascii + i * 2 + 1, 16);
        }
    }
    ascii[32] = 0;
    return ascii;
}

/*
 * The message is "padded" (extended) so that its length (in bits) is
 * congruent to 448, modulo 512. That is, the message is extended so
 * that it is just 64 bits shy of being a multiple of 512 bits long.
 * Padding is always performed, even if the length of the message is
 * already congruent to 448, modulo 512.
 *
 * Padding is performed as follows: a single "1" bit is appended to the
 * message, and then "0" bits are appended so that the length in bits of
 * the padded message becomes congruent to 448, modulo 512. In all, at
 * least one bit and at most 512 bits are appended.
 *
 * @param clearText Data to padding 100000...b.
 * @param originLength Length of clearText, it's unit is byte.
 * @param *newLength the length of clearText after padding.
 *
 * @return clearText after padding, and 64-bits blank at the end need appending.
 */
unsigned char* paddingClearText(unsigned char* clearText, unsigned long long originLength, unsigned long long *newLength) {
    // get the length need to padding, so (clearText.len - 56) % 64 == 0.
    unsigned long long paddingLength = 64LL - (originLength + 8LL) % 64LL;

    // padding
    unsigned char* paddedData = new unsigned char[originLength + paddingLength + 8];
    memcpy(paddedData, clearText, originLength);
    memcpy(paddedData + originLength, PADDINGS, paddingLength);
    *newLength = originLength + paddingLength;
    return paddedData;
}

/*
 * A 64-bit representation of b (the length of the message before the
 * padding bits were added) is appended to the result of the previous
 * step. In the unlikely event that b is greater than 2^64, then only
 * the low-order 64 bits of b are used. (These bits are appended as two
 * 32-bit words and appended low-order word first in accordance with the
 * previous conventions.)
 *
 * @param paddedData the data after paddingClearText.
 * @param offset the length of paddedData without 64-bits blank, it's unit is byte.
 * @param bitLength the length of source data in BITS, it possible differs from
 *            length of paddedData before padded, because the message could
 *            be parited.
 *
 * @return paddedData appended by bitLength, so the newLength you can get by offset + 8.
 */
unsigned char* appendBitLength(unsigned char* paddedData, unsigned long long offset, unsigned long long bitLength,
    unsigned long long *totalLength) {
    memcpy(paddedData + offset, (unsigned char*)&bitLength, 8);
    *totalLength = offset + 8;
    return paddedData;
}

unsigned long x[16];

/*
 * Core algorithm of calculate md5, you can understand it by reading RFC 1321,
 * however, I suggest you shouldn't do that, you can't understand, because the
 * document say nothing.
 *
 * @param paddedData the clearData after padding 1000....b and length in bit,
 *           so, the length of it in byte should divisible by 8.
 * @param state state of register a, b, c and d in order.
 */
void md5Core(unsigned char *paddedData, unsigned long* state) {
    unsigned long AA = state[0], BB = state[1], CC = state[2], DD = state[3];

    // Save word to X
    for (int j = 0; j < 16; j++) {
        x[j] = *(unsigned long*)(paddedData + j * 4);
    }

    /* Round 1 */
    round1(&state[0], state[1], state[2], state[3], x[0], S11, 0xd76aa478); /* 1 */
    round1(&state[3], state[0], state[1], state[2], x[1], S12, 0xe8c7b756); /* 2 */
    round1(&state[2], state[3], state[0], state[1], x[2], S13, 0x242070db); /* 3 */
    round1(&state[1], state[2], state[3], state[0], x[3], S14, 0xc1bdceee); /* 4 */
    round1(&state[0], state[1], state[2], state[3], x[4], S11, 0xf57c0faf); /* 5 */
    round1(&state[3], state[0], state[1], state[2], x[5], S12, 0x4787c62a); /* 6 */
    round1(&state[2], state[3], state[0], state[1], x[6], S13, 0xa8304613); /* 7 */
    round1(&state[1], state[2], state[3], state[0], x[7], S14, 0xfd469501); /* 8 */
    round1(&state[0], state[1], state[2], state[3], x[8], S11, 0x698098d8); /* 9 */
    round1(&state[3], state[0], state[1], state[2], x[9], S12, 0x8b44f7af); /* 10 */
    round1(&state[2], state[3], state[0], state[1], x[10], S13, 0xffff5bb1); /* 11 */
    round1(&state[1], state[2], state[3], state[0], x[11], S14, 0x895cd7be); /* 12 */
    round1(&state[0], state[1], state[2], state[3], x[12], S11, 0x6b901122); /* 13 */
    round1(&state[3], state[0], state[1], state[2], x[13], S12, 0xfd987193); /* 14 */
    round1(&state[2], state[3], state[0], state[1], x[14], S13, 0xa679438e); /* 15 */
    round1(&state[1], state[2], state[3], state[0], x[15], S14, 0x49b40821); /* 16 */
    /* Round 2 */
    round2(&state[0], state[1], state[2], state[3], x[1], S21, 0xf61e2562); /* 17 */
    round2(&state[3], state[0], state[1], state[2], x[6], S22, 0xc040b340); /* 18 */
    round2(&state[2], state[3], state[0], state[1], x[11], S23, 0x265e5a51); /* 19 */
    round2(&state[1], state[2], state[3], state[0], x[0], S24, 0xe9b6c7aa); /* 20 */
    round2(&state[0], state[1], state[2], state[3], x[5], S21, 0xd62f105d); /* 21 */
    round2(&state[3], state[0], state[1], state[2], x[10], S22, 0x2441453); /* 22 */
    round2(&state[2], state[3], state[0], state[1], x[15], S23, 0xd8a1e681); /* 23 */
    round2(&state[1], state[2], state[3], state[0], x[4], S24, 0xe7d3fbc8); /* 24 */
    round2(&state[0], state[1], state[2], state[3], x[9], S21, 0x21e1cde6); /* 25 */
    round2(&state[3], state[0], state[1], state[2], x[14], S22, 0xc33707d6); /* 26 */
    round2(&state[2], state[3], state[0], state[1], x[3], S23, 0xf4d50d87); /* 27 */
    round2(&state[1], state[2], state[3], state[0], x[8], S24, 0x455a14ed); /* 28 */
    round2(&state[0], state[1], state[2], state[3], x[13], S21, 0xa9e3e905); /* 29 */
    round2(&state[3], state[0], state[1], state[2], x[2], S22, 0xfcefa3f8); /* 30 */
    round2(&state[2], state[3], state[0], state[1], x[7], S23, 0x676f02d9); /* 31 */
    round2(&state[1], state[2], state[3], state[0], x[12], S24, 0x8d2a4c8a); /* 32 */
    /* Round 3 */
    round3(&state[0], state[1], state[2], state[3], x[5], S31, 0xfffa3942); /* 33 */
    round3(&state[3], state[0], state[1], state[2], x[8], S32, 0x8771f681); /* 34 */
    round3(&state[2], state[3], state[0], state[1], x[11], S33, 0x6d9d6122); /* 35 */
    round3(&state[1], state[2], state[3], state[0], x[14], S34, 0xfde5380c); /* 36 */
    round3(&state[0], state[1], state[2], state[3], x[1], S31, 0xa4beea44); /* 37 */
    round3(&state[3], state[0], state[1], state[2], x[4], S32, 0x4bdecfa9); /* 38 */
    round3(&state[2], state[3], state[0], state[1], x[7], S33, 0xf6bb4b60); /* 39 */
    round3(&state[1], state[2], state[3], state[0], x[10], S34, 0xbebfbc70); /* 40 */
    round3(&state[0], state[1], state[2], state[3], x[13], S31, 0x289b7ec6); /* 41 */
    round3(&state[3], state[0], state[1], state[2], x[0], S32, 0xeaa127fa); /* 42 */
    round3(&state[2], state[3], state[0], state[1], x[3], S33, 0xd4ef3085); /* 43 */
    round3(&state[1], state[2], state[3], state[0], x[6], S34, 0x4881d05); /* 44 */
    round3(&state[0], state[1], state[2], state[3], x[9], S31, 0xd9d4d039); /* 45 */
    round3(&state[3], state[0], state[1], state[2], x[12], S32, 0xe6db99e5); /* 46 */
    round3(&state[2], state[3], state[0], state[1], x[15], S33, 0x1fa27cf8); /* 47 */
    round3(&state[1], state[2], state[3], state[0], x[2], S34, 0xc4ac5665); /* 48 */
    /* Round 4 */
    round4(&state[0], state[1], state[2], state[3], x[0], S41, 0xf4292244); /* 49 */
    round4(&state[3], state[0], state[1], state[2], x[7], S42, 0x432aff97); /* 50 */
    round4(&state[2], state[3], state[0], state[1], x[14], S43, 0xab9423a7); /* 51 */
    round4(&state[1], state[2], state[3], state[0], x[5], S44, 0xfc93a039); /* 52 */
    round4(&state[0], state[1], state[2], state[3], x[12], S41, 0x655b59c3); /* 53 */
    round4(&state[3], state[0], state[1], state[2], x[3], S42, 0x8f0ccc92); /* 54 */
    round4(&state[2], state[3], state[0], state[1], x[10], S43, 0xffeff47d); /* 55 */
    round4(&state[1], state[2], state[3], state[0], x[1], S44, 0x85845dd1); /* 56 */
    round4(&state[0], state[1], state[2], state[3], x[8], S41, 0x6fa87e4f); /* 57 */
    round4(&state[3], state[0], state[1], state[2], x[15], S42, 0xfe2ce6e0); /* 58 */
    round4(&state[2], state[3], state[0], state[1], x[6], S43, 0xa3014314); /* 59 */
    round4(&state[1], state[2], state[3], state[0], x[13], S44, 0x4e0811a1); /* 60 */
    round4(&state[0], state[1], state[2], state[3], x[4], S41, 0xf7537e82); /* 61 */
    round4(&state[3], state[0], state[1], state[2], x[11], S42, 0xbd3af235); /* 62 */
    round4(&state[2], state[3], state[0], state[1], x[2], S43, 0x2ad7d2bb); /* 63 */
    round4(&state[1], state[2], state[3], state[0], x[9], S44, 0xeb86d391); /* 64 */

    state[0] += AA;
    state[1] += BB;
    state[2] += CC;
    state[3] += DD;
}
