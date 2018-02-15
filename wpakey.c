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

struct global {
	pcap_t *cap;
	unsigned char our_mac[6];
	unsigned char bssid[6];
	char essid[32+1];
	char conn_state;
	unsigned char rates[64];
	unsigned char erates[64];
	unsigned char htcaps[64];
	unsigned char len_rates;
	unsigned char len_erates;
	unsigned char len_htcaps;
	uint16_t caps;
	uint16_t enctype;
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

static void init_header(unsigned char* packet, uint16_t fc, const unsigned char dst[6])
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
		if(status == PCAP_ERROR_NO_SUCH_DEVICE)
			dprintf(2, "[X] PCAP: no such device\n");
		/* TODO : print nice error message for other codes */
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
	memcpy(&framectl, data+offset, 2);
	framectl = end_le16toh(framectl);

	switch(framectl) {
			/* IEEE 802.11 packet type */
			case 0x0080: /* beacon */

				/* TODO : retrieve essid from tagged data */

				if(gstate.conn_state >= ST_GOT_BEACON)
					return 0;

				dot11 = (void*)(data+offset);
				/* beacon from target AP ? */
				if(memcmp(gstate.bssid, dot11->source, 6))
					return 0;
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
			case 0x00b0: /* authentication */
				if(gstate.conn_state >= ST_GOT_AUTH)
					return 0;
				/* fall through */
			case 0x0010: /* association resp */
				if(gstate.conn_state >= ST_GOT_ASSOC)
					return 0;

				dot11 = (void*)(data+offset);
				/* our ap ?*/
				if(memcmp(gstate.bssid, dot11->bssid, 6))
					return 0;
				/* for us ? */
				if(memcmp(gstate.our_mac, dot11->receiver, 6))
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

	return 0;
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
		   , argv0 );
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

	sigalrm_init();

	gstate.conn_state = ST_CLEAN;

	int exit_state = 1;

	for(;;) {
		int ret = process_packet(gstate.cap);
		if(ret == -1) break;
		if(ret == 1) {
			switch(gstate.conn_state) {
				case ST_CLEAN:
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
					dprintf(2, "YEAH!\n");
					return 0;
					;
					break;

			}

		}

	}

	return exit_state;
}
