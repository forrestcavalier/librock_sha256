/* librock_sha256.c, an implementation of SHA-256 in C.

Part of libROCK: QUICK REUSE WITHOUT CHANGES!
- MIT License
- High-Quality. Highly portable. Compiles on gcc/MSVC/Clang/Windows/Linux/BSD/more.
- Global names start "librock_", for compatibility.

This file consists of
    [[The MIT License]] (and copyright statement.)

    [[okdshin's C++ picosha2, adapted to C. static (PRIVATE)]]

    [[librock_sha256, (PUBLIC)]]
        typedef struct librock_SHA256_CTX *librock_SHA256_CTX_t; // Opaque structure.
        
        int librock_SHA256_Init(
            struct librock_SHA256_CTX *c); // Call with NULL to get a size to allocate

        int librock_SHA256_Update(
            struct librock_SHA256_CTX *c, const void *data, int len);
        
        int librock_SHA256_StoreFinal (
            unsigned char *md, struct librock_SHA256_CTX *c); //md=32 bytes
        
    [[Typical example main()]] #ifdef LIBROCK_SHA256_MAIN
*/

/**************************************************************/
//[[The MIT License]]
/*
The MIT License (MIT)

Portions Copyright (C) 2014 okdshin
Portions Copyright (C) 2016 MIB SOFTWARE INC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
/**************************************************************/

/**************************************************************/
//[[okdshin's picosha2, adapted to C. Static (PRIVATE)]]
/* Adapted from picosha2.h, a C++, header-only implementation at:
    https://github.com/okdshin/PicoSHA2/blob/master/picosha2.h

    Adapted to C by Forrest Cavalier III, MIB SOFTWARE INC.
*/

typedef unsigned long word_t;
typedef unsigned char byte_t;
#define PRIVATE static

PRIVATE byte_t mask_8bit(byte_t x)
{
    return x&0xff;
}

PRIVATE word_t mask_32bit(word_t x)
{
    return x&0xffffffff;
}

PRIVATE const word_t add_constant[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

PRIVATE word_t ch(word_t x, word_t y, word_t z)
{
    return (x&y)^((~x)&z);
}

PRIVATE word_t maj(word_t x, word_t y, word_t z)
{
    return (x&y)^(x&z)^(y&z);
}

PRIVATE word_t rotr(word_t x, unsigned n)
{
//  assert(n < 32);
    return mask_32bit((x>>n)|(x<<(32-n)));
}

PRIVATE word_t bsig0(word_t x)
{
    return rotr(x, 2)^rotr(x, 13)^rotr(x, 22);
}

PRIVATE word_t bsig1(word_t x)
{
    return rotr(x, 6)^rotr(x, 11)^rotr(x, 25);
}

PRIVATE word_t shr(word_t x,unsigned n)
{
//  assert(n < 32);
    return x >> n;
}

PRIVATE word_t ssig0(word_t x)
{
    return rotr(x, 7)^rotr(x, 18)^shr(x, 3);
}

PRIVATE word_t ssig1(word_t x)
{
    return rotr(x, 17)^rotr(x, 19)^shr(x, 10);
}

PRIVATE void hash256_block(word_t *message_digest, unsigned char const *first/*, unsigned char const * last*/)
{
    word_t w[64];
    unsigned i;
    word_t a,b,c,d,e,f,g,h;
    //(all w[] are written anyway) memset(w,'\0',sizeof w);
    
    for(i = 0; i < 16; ++i){
        w[i] = ((word_t)(mask_8bit(*(first+i*4)))<<24)
            |((word_t)(mask_8bit(*(first+i*4+1)))<<16) 
            |((word_t)(mask_8bit(*(first+i*4+2)))<<8)
            |((word_t)(mask_8bit(*(first+i*4+3)))); 
    }
    for(i = 16; i < 64; ++i){
        w[i] = mask_32bit(ssig1(w[i-2])+w[i-7]+ssig0(w[i-15])+w[i-16]);
    }
    
    a = *message_digest;
    b = *(message_digest+1);
    c = *(message_digest+2);
    d = *(message_digest+3);
    e = *(message_digest+4);
    f = *(message_digest+5);
    g = *(message_digest+6);
    h = *(message_digest+7);
    
    for( i = 0; i < 64; ++i){
        word_t temp1 = h+bsig1(e)+ch(e,f,g)+add_constant[i]+w[i];
        word_t temp2 = bsig0(a)+maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = mask_32bit(d+temp1);
        d = c;
        c = b;
        b = a;
        a = mask_32bit(temp1+temp2);
    }
    *message_digest += a;
    *(message_digest+1) += b;
    *(message_digest+2) += c;
    *(message_digest+3) += d;
    *(message_digest+4) += e;
    *(message_digest+5) += f;
    *(message_digest+6) += g;
    *(message_digest+7) += h;
    for(i = 0; i < 8; ++i){
        *(message_digest+i) = mask_32bit(*(message_digest+i));
    }
}
/**************************************************************/

/**************************************************************/
//[[librock_sha256]] By Forrest Cavalier III, MIB SOFTWARE, INC.
/* See MIT LICENSE above for copyright and license statement.*/
#include <string.h> //memset

typedef struct librock_SHA256_CTX {
    word_t data_length_digits_[4]; //as 64bit integer (16bit x 4 integer)
    word_t h_[8];
    unsigned char buffer[64];
    int nBuffer;
} SHA256_CTX_t;

int librock_SHA256_Init(struct librock_SHA256_CTX *c)
{
    if (!c) {//mibsoftware.com Allow caller to use opaque structures.
        return sizeof(*c);
    }
    c->data_length_digits_[0] = 0;
    c->data_length_digits_[1] = 0;
    c->data_length_digits_[2] = 0;
    c->data_length_digits_[3] = 0;
//    memset (c,0,sizeof(*c));
    c->h_[0]=0x6a09e667UL;  c->h_[1]=0xbb67ae85UL;
    c->h_[2]=0x3c6ef372UL;  c->h_[3]=0xa54ff53aUL;
    c->h_[4]=0x510e527fUL;  c->h_[5]=0x9b05688cUL;
    c->h_[6]=0x1f83d9abUL;  c->h_[7]=0x5be0cd19UL;
    c->nBuffer = 0;
    return 1;
} /* librock_SHA256_Init */

/**************************************************************/
int librock_SHA256_Update(struct librock_SHA256_CTX *c, const void *data_, int len)
{
    int i = 0;
    if (len < 0) {
        return 0;
    }
    { /* add data length */
        unsigned j;
        word_t carry = 0;
        c->data_length_digits_[0] += len;
        for(j = 0; j < 4; ++j) {
            c->data_length_digits_[j] += carry;
            if(c->data_length_digits_[j] >= 65536u) {
                carry = (c->data_length_digits_[j]>>16);
                c->data_length_digits_[j] &= 65535u;
            } else {
                break;
            }
        }
    }

    /* If working on a partial block, and can fill it out, process it. */ 
    if (c->nBuffer > 0 && (len - i + c->nBuffer >= 64)) {
        memcpy(c->buffer+c->nBuffer,(char *)data_+i,64 - c->nBuffer);
        i += 64 - c->nBuffer;
        hash256_block(c->h_, c->buffer);
        c->nBuffer = 0;
    }
    /* If len - i >= 64, then we know c->nBuffer was set to 0, and we can work in full blocks */
    while(len - i >= 64) { /* Do as many blocks as possible without copies */
        hash256_block(c->h_, (unsigned char *)data_+i);
        i += 64;
    }
    if (len - i > 0) { /* Save partial */
        memcpy(c->buffer+c->nBuffer,(char *)data_+i,len - i);
        c->nBuffer += len - i;
    }
    return 1;
} /* librock_SHA256_Update */

/**************************************************************/
int librock_SHA256_StoreFinal (unsigned char *md, struct librock_SHA256_CTX *c)
{

    int i;
    c->buffer[c->nBuffer] = 0x80;

    if(c->nBuffer > 55) {
        memset(c->buffer+c->nBuffer+1,'\0', 64-c->nBuffer-1);
        hash256_block(c->h_, c->buffer);
        memset(c->buffer,'\0', 56);
    } else {
        memset(c->buffer+c->nBuffer+1,'\0', 56-c->nBuffer-1);
    }

    {/* write data bit length */
        // convert byte length to bit length (multiply 8 or shift 3 times left)
        unsigned char *begin  = &(c->buffer[56]);
        word_t carry = 0;
        int i;
        for(i = 0; i < 4; ++i) {
            word_t before_val = c->data_length_digits_[i];
            c->data_length_digits_[i] <<= 3;
            c->data_length_digits_[i] |= carry;
            c->data_length_digits_[i] &= 65535u;
            carry = (before_val >> (16-3)) & 65535u;
        }

        // write data_bit_length
        for(i = 3; i >= 0; --i) {
            (*begin++) = (unsigned char)(c->data_length_digits_[i] >> 8);
            (*begin++) = (unsigned char)(c->data_length_digits_[i]);
        }
    }       
    hash256_block(c->h_, c->buffer);
    
    memset(c->buffer,'\0',sizeof c->buffer); //Clear temporary buffer.
    for(i = 0; i < 8; i++) {
        *md++ = (c->h_[i]>>24) & 0xff;
        *md++ = (c->h_[i]>>16) & 0xff;
        *md++ = (c->h_[i]>>8) & 0xff;
        *md++ = (c->h_[i]) & 0xff;
    }
    return 1;
} /* librock_SHA256_StoreFinal */
/**************************************************************/
    
/**************************************************************/
//[[Typical Example main]]  By Forrest Cavalier III, MIB SOFTWARE, INC.
/* See MIT LICENSE above for copyright and license statement. */
#if LIBROCK_SHA256_MAIN //Typical use mibsoftware.com
#include <stdio.h>
#include <stdlib.h> //malloc
#include <time.h> //clock()
#include <string.h>

void dumpmem(unsigned char *md,int len)
{int i;
    for(i = 0;i < len;i++) {
        printf("%02x",md[i]);
    }
    printf("\n");
}

int main()
{
    unsigned char md[32]; /* Result */
    char *str; /* Input */
    int len; /* Input length */
    void *pHashInfo; /* allocated, reusable. */
    int itest; /* 4 tests */

    pHashInfo = malloc(librock_SHA256_Init(0)/*Get size */);

    for (itest=0;itest < 4;itest++) {
        librock_SHA256_Init( pHashInfo );

        str = 0;
        if (itest == 0) {
            str = "abc";
            /* expect ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
        } else if (itest==1) {
            str = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
            /* expect cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1 */
        } else if (itest == 2) {
            str = "";
        } else if (itest == 3) {
            /* Timed test */
            int c;
            len = 250000;
            str = malloc(len+1);
            if (!str) {
                perror("Creating buffer");
                exit(-1);
            }
            memset(str,'a',len);
            str[len] = 0;
            c = clock();

            {
            int i = 0;
        //    for(i = 0;i < 65536;i++) { // got 00e94ed5771326935293ebbb9831d811bd1d8dd5b4690def8e2bc87c56f789c6
            for(i = 0;i < 4;i++) {     /* expect cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0 */
        //        for(i = 0;i < 40;i++) {
                    librock_SHA256_Update( pHashInfo, ( unsigned char * ) str, len );
                    printf("%d\n",i);
                }
            }
            printf("%g\n", (float) (clock() - c) / CLOCKS_PER_SEC);
            free(str);
            str = 0;
        }
        if (str) {
            len = strlen(str);

            if (len > 8) { /* Good test to split it up */
                librock_SHA256_Update( pHashInfo, ( unsigned char * ) str, 4 );
                librock_SHA256_Update( pHashInfo, ( unsigned char * ) str+4, 4 );
                librock_SHA256_Update( pHashInfo, ( unsigned char * ) str+8, len-8 );
            } else {
                librock_SHA256_Update( pHashInfo, ( unsigned char * ) str, len );
            }
        }

        librock_SHA256_StoreFinal( md,pHashInfo );

        dumpmem(md,sizeof(md)); //Show result to stdout
    }
    free(pHashInfo);
    return 0;
} /* main */
#endif //LIBROCK_SHA256_MAIN
