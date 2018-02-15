LDFLAGS = -lpcap
CFLAGS = -O0 -g3 -Wall -Wno-discarded-qualifiers -Wno-unused-variable

CR_OBJS = wsupp_crypto.o crypto/pbkdf2_sha1.o crypto/sha1.o \
crypto/aes128.o crypto/aes128_unwrap.o crypto/sha1_hmac.o
all: wpakey

wpakey: $(CR_OBJS)

clean:
	rm -f wpakey
