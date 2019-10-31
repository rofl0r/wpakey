#include <stdio.h>

static inline int myisascii(int x) {
	return x >= ' ' && x < 127;
}

void dump(const unsigned char* data, size_t len) {
	static const char atab[] = "0123456789abcdef";
	char hex[24*2+1], ascii[24+1];
	unsigned h = 0, a = 0;
	int fill = ' ';

	while(len) {
		len--;
		hex[h++] = atab[*data >> 4];
		hex[h++] = atab[*data & 0xf];
		ascii[a++] = myisascii(*data) ? *data : '.';
		if(a == 24) {
	dump:
			hex[h] = 0;
			ascii[a] = 0;
			printf("%s\t%s\n", hex, ascii);

			if(fill == '_') return; /* jump from filler */

			a = 0;
			h = 0;
		}
		data++;
	}
	if(a) {
	filler:
		while(a<24) {
			hex[h++] = fill;
			hex[h++] = fill;
			ascii[a++] = fill;
		}
		goto dump;
	}
	a = 0;
	fill = '_';
	goto filler;
}

