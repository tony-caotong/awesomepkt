/**
*	Awesome packet.
*		by Cao Tong<tony_caotong@gmail.com> 
*		at 2017-01-13
*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <getopt.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/if.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#define ASM_ERR_NONE 0x00000000
#define ASM_ERR_PARM 0x00000001

#define MAX_PKT_LEN ((2 << 16) - 1)

uint32_t failure = ASM_ERR_NONE;

unsigned char pkt_buf[MAX_PKT_LEN];

struct configs {
	/* Src Mac, Dst Mac*/
	struct ether_addr dst_mac;
	struct ether_addr src_mac;
	/* sip addr, dip addr*/
	struct in_addr saddr;
	struct in_addr daddr;
	/* l4 protocol type */
	uint8_t protocol;
	/* sport. dport*/
	uint16_t sport;
	uint16_t dport;
	/* payloads */
	uint16_t length;
	unsigned char buf[MAX_PKT_LEN];
} __attribute__((__packed__));

int x2c(const char x)
{
	int c;
	if (x >= '0' && x <= '9') {
		c = x - '0';
	} else if (x >= 'a' && x <= 'f') {
		c = 0x0a + (x - 'a');
	} else if (x >= 'A' && x <= 'F') {
		c = 0x0A + (x - 'A');
	} else {
		c = -1;
	}
	return c;
}

int format_mac(char* str, struct ether_addr* addr)
{
	int i;
	int r = 0;

	/* 0. check the legality of mac_str's format. */
	/* TODO: */
	/* 2. format eth legality string to struct ether_addr. */
	for (i = 0; i < ETH_ALEN; i++) {
		int v, tmp;
		tmp = x2c(str[i*3]);
		if (tmp < 0) {
			r = -1;
			goto err;
		}
		v = tmp << 4;
		tmp = x2c(str[i*3+1]);
		if (tmp < 0) {
			r = -1;
			goto err;
		}
		v += tmp;
		addr->ether_addr_octet[i] = v;
	}
err:
	return r;
}

int prepare_tcp(const struct configs* cfg, struct iphdr* iph,
				unsigned char* buf, size_t size)
{

}

int prepare_udp(const struct configs* cfg, struct iphdr* iph,
				unsigned char* buf, size_t size)
{

}


int prepare_ipv4_payload(const struct configs* cfg, struct iphdr* iph,
				unsigned char* buf, size_t size) 
{
/*	if (cfg->protocol == IPPROTO_TCP)
		return prepare_tcp();
	else if (cfg->protocol == IPPROTO_UDP)
		return prepare_tcp();
	else
*/
		return -1;
}

int prepare_ipv4(const struct configs* cfg, unsigned char* buf, size_t size) 
{
	int hdrlen, r;
	struct iphdr* iph;
	struct udphdr* udph;

	/* 1. format l4 header. */
	iph = (struct iphdr*)(buf);
	hdrlen += sizeof(struct iphdr);

	/* 2. format payload. */
	r = prepare_ipv4_payload(cfg, iph, buf+hdrlen, size-hdrlen);
	if (r < 0)
		return r;
	/* 3. fix length. */
	/* TODO */
	return hdrlen + r;
}


int prepare_ether_payload(const struct configs* cfg, struct ether_header* eh,
		unsigned char* buf, size_t size) 
{
	return prepare_ipv4(cfg, buf, size);
}

int prepare_ethernet(const struct configs* cfg, unsigned char* buf,
			size_t size)
{
	int hdrlen, r;
	struct ether_header* eh;

	/* 1. format mac header. */
	eh = (struct ether_header*)buf;
	hdrlen += sizeof(struct ether_header);

	/* 2. format ethernet payload. */
	r = prepare_ether_payload(cfg, eh, buf+hdrlen, size-hdrlen);

	/* TODO: calculate CRC. */

	/* min length of ethernet package is 64. */
	if (r < 0) {
		return r;
	} else if (r < 64 - hdrlen) {
		int fillpad_len = 64 - hdrlen - r;
		memset(buf+hdrlen+r, 0, fillpad_len);
		return 64;
	} else if (r <= MAX_PKT_LEN - hdrlen) {
		return hdrlen + r;
	} else {
		return -1;
	}
}

int prepare_pkt(const struct configs* cfg, unsigned char* buf, size_t size)
{
	return prepare_ethernet(cfg, buf, size);
}

void my_usage(char* progname)
{
	fprintf(stderr, "%s Usage:\n", progname);
	fprintf(stderr, "\txxx\n");
	fprintf(stderr, "\tyyy\n");
	fprintf(stderr, "CopyLeft @ 2017 by tong\n");
	fprintf(stderr, "\n");
}

int talk_with_me(int argc, char** argv, struct configs* cfg)
{
	int r = 0;
	int opt;
	static int verbose_flag;
	uint32_t flag = 0x000000FF;


	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"dst_mac", required_argument, &verbose_flag, 0x01},
			{"src_mac", required_argument, &verbose_flag, 0x02},
			{"src_ip", required_argument, &verbose_flag, 0x04},
			{"dst_ip", required_argument, &verbose_flag, 0x08},
			{"protocol", required_argument, &verbose_flag, 0x10},
			{"dst_port", required_argument, &verbose_flag, 0x20},
			{"src_port", required_argument, &verbose_flag, 0x40},
			{"buffer", required_argument, &verbose_flag, 0x80},
			{0,0,0,0}
		};

		int longindex = 0;

		opt = getopt_long(argc, argv, "hi:",
				long_options, &longindex);
		
		if (opt == -1)
			break;
		switch (opt) {
		case 0:
			if (long_options[longindex].flag != 0)
				flag ^= verbose_flag;
			fprintf(stderr, "longopt: %s\n",
				long_options[longindex].name);
			switch(verbose_flag) {
			case 0x01:
				if (format_mac(optarg, &(cfg->dst_mac)) < 0) {
					fprintf(stderr, "error parameter "\
						"format of: %s\n",
						long_options[longindex].name);
					failure |= ASM_ERR_PARM;
					goto err;
				}
				break;
			case 0x02:
				if (format_mac(optarg, &(cfg->src_mac)) < 0) {
					fprintf(stderr, "error parameter "\
						"format of: %s\n",
						long_options[longindex].name);
					failure |= ASM_ERR_PARM;
					goto err;
				}
				break;
			case 0x04: {
				struct in_addr tmp;
				if (inet_aton(optarg, &tmp) == 0) {
					fprintf(stderr, "error parameter "\
						"format of: %s\n",
						long_options[longindex].name);
					failure |= ASM_ERR_PARM;
					goto err;
				}
				cfg->saddr = tmp;
				break;
			}
			case 0x08: {
				struct in_addr tmp;
				if (inet_aton(optarg, &tmp) == 0) {
					fprintf(stderr, "error parameter "\
						"format of: %s\n",
						long_options[longindex].name);
					failure |= ASM_ERR_PARM;
					goto err;
				}
				cfg->daddr = tmp;
				break;
			}
			case 0x10:
				if (strcasecmp("tcp", optarg) == 0) {
					cfg->protocol = IPPROTO_TCP;
				} else if (strcasecmp("udp", optarg) == 0) {
					cfg->protocol = IPPROTO_UDP;
				} else {
					fprintf(stderr, "error parameter "\
						"format of: %s\n",
						long_options[longindex].name);
					failure |= ASM_ERR_PARM;
					goto err;
				}
				break;
			case 0x20:
				/* TODO: error detecting. */
				cfg->sport = atoi(optarg);
				break;
			case 0x40:
				/* TODO: error detecting. */
				cfg->dport = atoi(optarg);
				break;
			case 0x80:
				cfg->length = strlen(optarg);
				memcpy(cfg->buf, optarg, cfg->length);
				break;
			default:
				break;
			}
			break;
		case 'i':
			fprintf(stderr, "argument for b: %s\n", optarg);
			break;
/*
		case '?':
			fprintf(stderr, "here is ? \n");
			break;
*/
		case 'h':
		default:
			my_usage(argv[0]);
			failure |= ASM_ERR_PARM;
			r = -1;
			goto err;
		}
	}
	if (flag != 0)
		fprintf(stderr, "All 'must' arguments must be set [%u].\n",
			flag);
err:
	return r;
}

int fucking_push()
{
	printf("go in fucking push!\n");
	int sock;
	struct sockaddr_ll addr;

	if ((sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0) {
		perror("socket: ");
		return -1;
	}
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);

	struct ifreq req;
	strncpy(req.ifr_name, "tap-dpdk-2", sizeof(req.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &req) < 0) {
		perror("ioctl: ");
		return -1;
	}
	addr.sll_ifindex =  req.ifr_ifindex;
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind: ");
		return -1;
	}

	while(1) {
		int r = recv(sock, pkt_buf, MAX_PKT_LEN, 0);
		if (r < 0)
			continue;
		unsigned char* p = pkt_buf;
		int j;
		printf("Found pack: [size: %d]\n", j);
		for (j = 0; j < r; j++) {
			if (j % 32 == 0)
				printf("0x");
			printf("%02x", *(p++));
			if ((j + 1)%32 == 0) {
				printf("\n");
				continue;
			}
			if ((j + 1)%16 == 0)
				printf(" ");
		}
		printf("\n");
	}
	return 0;
}

int main(int argc, char** argv)
{
	struct configs cfg;
	unsigned char* buf;
	unsigned int len;
	
	/* 1. deal with paremeters. format them into 'struct pktinfo'.*/
	if (talk_with_me(argc, argv, &cfg) < 0) {
		goto quit;
	}

	/* 2. Prepare packet buffer. transform 'pktinfo' into binary buffer. */
//	if (prepare_pkt(&cfg, buf, &len) < 0)
//		goto quit;

	/* 3. Get a raw socket, then push pkt buffer off.*/
	if (fucking_push() < 0)
		goto quit;

quit:
	return failure;
}
