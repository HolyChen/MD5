/*
 * Copy right: HolyChen.
 * Create Time: 2014.
 * Lisence: MIT/X.
  * Reference: RFC 1321 http://www.rfc-editor.org/rfc/rfc1321.txt
 */
#ifndef _MD5_H_
#define _MD5_H_

/*
* ------------------- NOCATION! -------------------
* ALL char, long used to calculate MD5, must be unsigned!.
* ------------------- NOCATION! -------------------
*/


/*
 * Define the four words used to compute the message digets.
 */
#define WORD_A 0x67452301
#define WORD_B 0xEFCDAB89
#define WORD_C 0x98BADCFE
#define WORD_D 0x10325476

// Round constant
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

const unsigned char PADDINGS[64] = {
    (unsigned char)0x80
};

/*
* Define the four auxiliary function the each take as input
* three 32-bit words and prodcue as output one 32-bit word.
*/
inline unsigned long functionF(unsigned long x, unsigned long y, unsigned long z);
inline unsigned long functionG(unsigned long x, unsigned long y, unsigned long z);
inline unsigned long functionH(unsigned long x, unsigned long y, unsigned long z);
inline unsigned long functionI(unsigned long x, unsigned long y, unsigned long z);
inline unsigned long roundLeft(unsigned long x, unsigned long n);
inline void round1(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, short xk, unsigned long s, unsigned long ti);
inline void round2(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, short xk, unsigned long s, unsigned long ti);
inline void round3(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, short xk, unsigned long s, unsigned long ti);
inline void round4(unsigned long *a, unsigned long b, unsigned long c, unsigned long d, short xk, unsigned long s, unsigned long ti);

/*
* Get MD5 code in ASCII represent.
*/
char* getMD5inASCII(unsigned long state[4]);

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
*/
unsigned char* paddingClearText(unsigned char* clearText, unsigned long long originLength, unsigned long long *newLength);

/*
* A 64-bit representation of b (the length of the message before the
* padding bits were added) is appended to the result of the previous
* step. In the unlikely event that b is greater than 2^64, then only
* the low-order 64 bits of b are used. (These bits are appended as two
* 32-bit words and appended low-order word first in accordance with the
* previous conventions.)
*/
unsigned char* appendBitLength(unsigned char* paddedData, unsigned long long offset, unsigned long long bitLength,
    unsigned long long *totalLength);

/*
* Core algorithm of calculate md5.
*/
void md5Core(unsigned char *paddedData, unsigned long* state);

#endif