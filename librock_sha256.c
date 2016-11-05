/* librock_sha256.c, adapted from picosha2.h, which is a C++ header-only version
	https://github.com/okdshin/PicoSHA2/blob/master/picosha2.h
	
The MIT License (MIT)

Copyright (C) 2014 okdshin

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
//#include <iostream>
//#include <vector>
//#include <iterator>
//#include <cassert>
//#include <sstream>
//#include <algorithm>

//namespace picosha2
//namespace {
typedef unsigned long word_t;
typedef unsigned char byte_t;
#include <string.h> //memset
#define PRIVATE static
//namespace detail 
//namespace {
PRIVATE byte_t mask_8bit(byte_t x){
	return x&0xff;
}

PRIVATE word_t mask_32bit(word_t x){
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
#if 0
const word_t initial_message_digest[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
#endif

PRIVATE word_t ch(word_t x, word_t y, word_t z){
	return (x&y)^((~x)&z);
}

PRIVATE word_t maj(word_t x, word_t y, word_t z){
	return (x&y)^(x&z)^(y&z);
}

PRIVATE word_t rotr(word_t x, /*std::size_t*/unsigned n){
//	assert(n < 32);
	return mask_32bit((x>>n)|(x<<(32-n)));
}

PRIVATE word_t bsig0(word_t x){
	return rotr(x, 2)^rotr(x, 13)^rotr(x, 22);
}

PRIVATE word_t bsig1(word_t x){
	return rotr(x, 6)^rotr(x, 11)^rotr(x, 25);
}

PRIVATE word_t shr(word_t x, /*std::size_t*/unsigned n){
//	assert(n < 32);
	return x >> n;
}

PRIVATE word_t ssig0(word_t x){
	return rotr(x, 7)^rotr(x, 18)^shr(x, 3);
}

PRIVATE word_t ssig1(word_t x){
	return rotr(x, 17)^rotr(x, 19)^shr(x, 10);
}

//template<typename RaIter1, typename RaIter2>
//void hash256_block(RaIter1 message_digest, RaIter2 first, RaIter2 last){
void hash256_block(word_t *message_digest, unsigned char const *first/*, unsigned char const * last*/){
	word_t w[64];
	unsigned i;
	word_t a,b,c,d,e,f,g,h;
	memset(w,'\0',sizeof w);//	std::fill(w, w+64, 0);
	
	for(/*std::size_t*/i = 0; i < 16; ++i){
		w[i] = ((word_t)(mask_8bit(*(first+i*4)))<<24)
			|((word_t)(mask_8bit(*(first+i*4+1)))<<16) 
			|((word_t)(mask_8bit(*(first+i*4+2)))<<8)
			|((word_t)(mask_8bit(*(first+i*4+3)))); 
	}
	for(/*std::size_t*/i = 16; i < 64; ++i){
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
	
	for(/*std::size_t*/ i = 0; i < 64; ++i){
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
	for(/*std::size_t*/ i = 0; i < 8; ++i){
		*(message_digest+i) = mask_32bit(*(message_digest+i));
	}
}
typedef struct {
//	std::vector<byte_t> buffer_;
	word_t data_length_digits_[4]; //as 64bit integer (16bit x 4 integer)
	word_t h_[8];
	unsigned char buffer[64];
	int nBuffer;
} SHA256_CTX;

int librock_SHA256_Init(SHA256_CTX *c)
{
	if (!c) {//mibsoftware.com Allow caller to use opaque structures.
		return sizeof(*c);
	}
	memset (c,0,sizeof(*c));
	c->h_[0]=0x6a09e667UL;	c->h_[1]=0xbb67ae85UL;
	c->h_[2]=0x3c6ef372UL;	c->h_[3]=0xa54ff53aUL;
	c->h_[4]=0x510e527fUL;	c->h_[5]=0x9b05688cUL;
	c->h_[6]=0x1f83d9abUL;	c->h_[7]=0x5be0cd19UL;
	c->nBuffer = 0;
	//c->md_len=SHA256_DIGEST_LENGTH;
	return 1;
}

int librock_SHA256_Update(SHA256_CTX *c, const void *data_, size_t len)
{
		int i = 0;

	{
		unsigned j;
		word_t carry = 0;
		c->data_length_digits_[0] += len;
		for(/*std::size_t*/j = 0; j < 4; ++j) {
			c->data_length_digits_[j] += carry;
			if(c->data_length_digits_[j] >= 65536u) {
				carry = (c->data_length_digits_[j]>>16); //20161104 was carry=1
				c->data_length_digits_[j] &= 65535u; //20161104 was -= 65536u.
			}
			else {
				break;
			}
		}
	}

		
		while(len - i + c->nBuffer >= 64) {
			memcpy(c->buffer+c->nBuffer,(char *)data_+i,64 - c->nBuffer);
			i += 64 - c->nBuffer;
			hash256_block(c->h_, c->buffer);
			c->nBuffer = 0;
			printf("%d\n",i);
		}
		memcpy(c->buffer+c->nBuffer,(char *)data_+i,len - i);
		c->nBuffer = len - i;
		memset(c->buffer+c->nBuffer,'\0',64 - c->nBuffer);
		return 1;
}
int librock_SHA256_StoreFinal (unsigned char *md, SHA256_CTX *c)
{

		int i;
		c->buffer[c->nBuffer] = 0x80;

		if(c->nBuffer > 55){
			memset(c->buffer+c->nBuffer+1,'\0', 64-c->nBuffer-1);
			hash256_block(c->h_, c->buffer);
			memset(c->buffer+c->nBuffer+1,'\0', 56);
		}
		else {
			memset(c->buffer+c->nBuffer+1,'\0', 56-c->nBuffer-1);
		}
/* write data bit length *///		write_data_bit_length(&(temp[56]));

		{
				// convert byte length to bit length (multiply 8 or shift 3 times left)
				unsigned char *begin  = &(c->buffer[56]);
				word_t carry = 0;
				int i;
				for(/*std::size_t*/ i = 0; i < 4; ++i) {
					word_t before_val = c->data_length_digits_[i];
					c->data_length_digits_[i] <<= 3;
					c->data_length_digits_[i] |= carry;
					c->data_length_digits_[i] &= 65535u;
					carry = (before_val >> (16-3)) & 65535u;
				}

				// write data_bit_length
				for(/*int*/ i = 3; i >= 0; --i) {
					(*begin++) = (unsigned char)(c->data_length_digits_[i] >> 8);
					(*begin++) = (unsigned char)(c->data_length_digits_[i]);
				}
		}		
		hash256_block(c->h_, c->buffer);
		for(/*int*/ i = 0; i < 8; i++) {
			*md++ = (c->h_[i]>>24) & 0xff;
			*md++ = (c->h_[i]>>16) & 0xff;
			*md++ = (c->h_[i]>>8) & 0xff;
			*md++ = (c->h_[i]) & 0xff;
		}
		return 1;
}
	
#if 1 //Typical use mibsoftware.com
#include <stdio.h>
#include <stdlib.h> //malloc
void dumpmem(unsigned char *md,int len)
{int i;
	for(i = 0;i < len;i++) {
		printf("%02x",md[i]);
	}
	printf("\n");
}

int main()
{
	unsigned char md[32];
    char *str = "This is a test string.";
	int len;
	void *pHashInfo;
	str = "abc";
	str = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	/* expect cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1 */
    len = strlen(str);
#if 1
	len = 1000000;
	str = malloc(len+1);
	memset(str,'a',len);
	/* expect cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0 */
	str[len] = 0;
#endif
	pHashInfo = malloc(librock_SHA256_Init(0)/*Get size */);

    librock_SHA256_Init( pHashInfo );

    librock_SHA256_Update( pHashInfo, ( unsigned char * ) str, len );
	dumpmem((unsigned char *)pHashInfo,32);

    librock_SHA256_StoreFinal( md,pHashInfo );
	dumpmem(md,sizeof(md));
	free(pHashInfo);
	return 0;
} /* main */
#endif
