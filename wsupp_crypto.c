#include <string.h>
#include <errno.h>

#include "crypto/sha1.h"
#include "crypto/aes128.h"

#define byte unsigned char
#define memzero(a, b) memset(a, 0, b)

static void* memadd(void* p, void* src, unsigned len)
{
	memcpy(p, src, len);
	return p + len;
}

static int memxcmp(const void* av, const void* bv, size_t len)
{
	const uint8_t* a = (const uint8_t*) av;
	const uint8_t* b = (const uint8_t*) bv;
	int ret = 0;
	
	while(len-- > 0)
		ret |= (*a++ - *b++);

	return ret;
}

/* Supplementary crypto routines for EAPOL negotiations.
   Ref. IEEE 802.11-2012 11.6.1.2 PRF
   
   The standard calls for PRF384 but that's just the same code
   that truncates the result to 48 bytes. In their terms:

       PRF-384(K, A, B) = L(PRF-480(K, A, B), 0, 384)
   
   To make things a bit easier, K is made 60 bytes (480 bits)
   long and no explicit truncation is preformed. In the caller,
   K is a temporary buffer anyway, the useful stuff gets copied
   out immediately.
 
   This function also handles concatenation:

       A = str
       B = mac1 | mac2 | nonce1 | nonce2

   HMAC input is then

       A | 0 | B | i

   so there's no point in a dedicated buffer for B. */

void PRF480(byte out[60], byte key[32], const char* str,
            byte mac1[6], byte mac2[6],
            byte nonce1[32], byte nonce2[32])
{
	int slen = strlen(str);
	int ilen = slen + 1 + 2*6 + 2*32 + 1; /* exact input len */
	int xlen = ilen + 10; /* guarded buffer len */

	char ibuf[xlen];
	char* p = ibuf;

	p = memadd(p, str, slen + 1);
	p = memadd(p, mac1, 6);
	p = memadd(p, mac2, 6);
	p = memadd(p, nonce1, 32);
	p = memadd(p, nonce2, 32);

	for(int i = 0; i < 3; i++) {
		*p = i;
		hmac_sha1(out + i*20, key, 32, ibuf, ilen);
	}
}

/* SHA-1 based message integrity code (MIC) for auth and key management
   scheme (AKM) 00-0F-AC:2, which we requested in association IEs and
   probably checked in packet 1 payload. 

   Ref. IEEE 802.11-2012 11.6.3 EAPOL-Key frame construction and processing. */

void make_mic(byte mic[16], byte kck[16], void* buf, int len)
{
	uint8_t hash[20];
	int kcklen = 16;
	int miclen = 16;

	hmac_sha1(hash, kck, kcklen, buf, len);

	memcpy(mic, hash, miclen);
}

int check_mic(byte mic[16], byte kck[16], void* buf, int len)
{
	uint8_t hash[20];
	uint8_t copy[16];
	int kcklen = 16;
	int miclen = 16;

	memcpy(copy, mic, miclen);
	memzero(mic, miclen);

	hmac_sha1(hash, kck, kcklen, buf, len);

	int ret = memxcmp(hash, copy, miclen);
	
	return ret;
}

/* Packet 3 payload (GTK) is wrapped with standard RFC3394 0xA6
   checkblock. We unwrap it in place, and start parsing 8 bytes
   into the data. */

static const byte iv[8] = {
	0xA6, 0xA6, 0xA6, 0xA6,
	0xA6, 0xA6, 0xA6, 0xA6
};

int unwrap_key(uint8_t kek[16], void* buf, int len)
{
	if(len % 8 || len < 16)
		return -1;

	aes128_unwrap(kek, buf, len);

	return memxcmp(buf, iv, 8);
}
