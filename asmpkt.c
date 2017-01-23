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
#include <unistd.h>
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

#include <errno.h>
#include <assert.h>

#define ASM_ERR_NONE 0x00000000
#define ASM_ERR_PARM 0x00000001

#define MAX_PKT_LEN ((2 << 16) - 1)
#define MAX_IF_LEN 16

uint32_t failure = ASM_ERR_NONE;

char pkt_buf[MAX_PKT_LEN];

struct configs {
	/* Src Mac, Dst Mac*/
	struct ether_addr dst_mac;
	struct ether_addr src_mac;
	/* sip addr, dip addr*/
	struct in_addr saddr;
	struct in_addr daddr;
	/* l4 protocol type */
	union {
		uint32_t ptype;
		struct {
			uint32_t l2_type:8;
			uint32_t l3_type:16;
			uint32_t l4_type:8;
		};
	};
	/* sport. dport*/
	uint16_t sport;
	uint16_t dport;
	/* payloads */
	uint16_t length;
	char ifname[MAX_IF_LEN];
	char buf[MAX_PKT_LEN];
	uint8_t fix;
} __attribute__((__packed__));

void serial_fill(char* buf, size_t len)
{
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = 'a' + (i % ('z' -'a'));
	}
}

/* TODO: difference values for different endian.
 * current we only support little-endian.
 */
#define ASM_PROTO_RAW 0x01
#define ASM_PROTO_ETH 0x02
#define ASM_PROTO_IP4 ETHERTYPE_IP << 8
#define ASM_PROTO_IP6 ETHERTYPE_IPV6 << 8
#define ASM_PROTO_TCP IPPROTO_TCP << 24
#define ASM_PROTO_UDP IPPROTO_UDP << 24

uint32_t getmask(uint32_t type)
{
	uint32_t mask;
	switch (type) {
	case ASM_PROTO_RAW:
	case ASM_PROTO_ETH:
		mask = 0xFFFFFF00;
		break;
	case ASM_PROTO_IP4:
	case ASM_PROTO_IP6:
		mask = 0xFF0000FF;
		break;
	case ASM_PROTO_TCP:
	case ASM_PROTO_UDP:
		mask = 0x00FFFFFF;
		break;
	}
	return mask;
}

int set_ptype(struct configs* cfg, uint32_t type)
{
	uint32_t mask;
	uint32_t value;

	mask = getmask(type);
	value = cfg->ptype & ~mask;

	if (value != 0) {
		return -1;
	}
	cfg->ptype |= type;
	return 0;
}

void binary_print(char* capital, char* buf, size_t length)
{
	int i = 0;
	
	printf("Capital: [%s]\n", capital);
	while(i < length) {
		if (i%16 == 0)
			printf("0x%016lx -- ", (unsigned long)&buf[i]);
		printf("%02X", (unsigned char)buf[i]);
		i++;
		if (i%16 == 0 && i != length)
			printf("\n");
		else if (i%8 == 0)
			printf("\t");
	}
	printf("\n");
}

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
	/* TODO: strlen() */
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
				char* buf, size_t size)
{
	return -1;
}

int prepare_udp(const struct configs* cfg, struct iphdr* iph,
				char* buf, size_t size)
{
	return -1;
}


int prepare_ipv4_payload(const struct configs* cfg, struct iphdr* iph,
				char* buf, size_t size) 
{
	int r = -1;

	if (cfg->l4_type == IPPROTO_TCP)
		r = prepare_tcp(cfg, iph, buf, size);
	else if (cfg->l4_type == IPPROTO_UDP)
		r = prepare_tcp(cfg, iph, buf, size);
	return r;
}

int prepare_ipv4(const struct configs* cfg, char* buf, size_t size) 
{
	int hdrlen, r;
	struct iphdr* iph;
	struct udphdr* udph __attribute((unused));

	/* 1. format l4 header. */
	iph = (struct iphdr*)(buf);
	hdrlen = sizeof(struct iphdr);

	/* 2. format payload. */
	r = prepare_ipv4_payload(cfg, iph, buf+hdrlen, size-hdrlen);
	if (r < 0)
		return r;
	/* 3. fix length. */
	/* TODO */
	return hdrlen + r;
}


int prepare_ether_payload(const struct configs* cfg, struct ether_header* eh,
		char* buf, size_t size) 
{
	int r = -1;

	if (cfg->l3_type == ETHERTYPE_IP) {
		eh->ether_type = ETHERTYPE_IP;
		r = prepare_ipv4(cfg, buf, size);
	} else if (cfg->l3_type == ETHERTYPE_IPV6) {
		/* TODO */
	} else {
		if (cfg->length > size) {
			fprintf(stderr, "buf is too long for ethernet pkt.\n");
			return -1;
		}
		eh->ether_type = 0x0000;
		memcpy(buf, cfg->buf, cfg->length);
		r = cfg->length;
	}
	return r;
}

int prepare_ethernet(const struct configs* cfg, char* buf,
			size_t size)
{
	int hdrlen, r;
	struct ether_header* eh;

	/* 1. format mac header. */
	eh = (struct ether_header*)buf;
	memcpy(eh->ether_dhost, &(cfg->dst_mac), ETH_ALEN);
	memcpy(eh->ether_shost, &(cfg->src_mac), ETH_ALEN);
	hdrlen = sizeof(struct ether_header);


	/* TODO: MTU */
	/* TODO: vlan */

	/* 2. format ethernet payload. */
	r = prepare_ether_payload(cfg, eh, buf+hdrlen, size-hdrlen);

	/* tip 1: As known, the min length of ethernet package is 64. Actually
		port driver(maybe) will deal with it and padding to 64.
	   tip 2: driver or hardware(mustbe) will calculate FCS.
	*/
	return r>0 ? r+hdrlen : r;
}

int prepare_pkt(const struct configs* cfg, char* buf, size_t size)
{
	int r = -1;

	if (cfg->l2_type == ASM_PROTO_ETH) {
		r = prepare_ethernet(cfg, buf, size);
	}
	return r;
}

void my_usage(char* progname)
{
	fprintf(stderr, "\nUsage: ");
	fprintf(stderr, "\t%s -i tap-dpdk-2\n", progname);
	fprintf(stderr, "\t-i <interface>\n");
	fprintf(stderr, "\t\twhich network interface to sent.\n");
	fprintf(stderr, "\t--dst_mac  <macaddr>\n");
	fprintf(stderr, "\t--src_mac  <macaddr>\n");
	fprintf(stderr, "\t--src_ip   <ipaddr>\n");
	fprintf(stderr, "\t--dst_ip   <ipaddr>\n");
	fprintf(stderr, "\t--ptype <raw/eth/ipv4/ipv6/tcp/udp>\n");
	fprintf(stderr, "\t\tipv4 is default.\n");
	fprintf(stderr, "\t--dst_port <port>\n");
	fprintf(stderr, "\t--src_port <port>\n");
	fprintf(stderr, "\t--buffer   <buffer>\n");
	fprintf(stderr, "\t--fix      <length>\n");
	fprintf(stderr, "\t--help\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "CopyLeft @ 2017 by tong\n");
}

int talk_with_me(int argc, char** argv, struct configs* cfg)
{
	int r = 0;
	int opt;
	static int verbose_flag;
//	uint32_t flag = 0x000001FF;
	uint32_t flag = 0x00000100;


	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"dst_mac", required_argument, &verbose_flag, 0x01},
			{"src_mac", required_argument, &verbose_flag, 0x02},
			{"src_ip", required_argument, &verbose_flag, 0x04},
			{"dst_ip", required_argument, &verbose_flag, 0x08},
			{"ptype", required_argument, &verbose_flag, 0x10},
			{"dst_port", required_argument, &verbose_flag, 0x20},
			{"src_port", required_argument, &verbose_flag, 0x40},
			{"buffer", required_argument, &verbose_flag, 0x80},
			{"fix", required_argument, &verbose_flag, 0x0100},
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
				flag = flag & ~verbose_flag;
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
			case 0x10: {
				uint32_t type;
				if (strcasecmp("raw", optarg) == 0) {
					type = ASM_PROTO_RAW;
				} else if (strcasecmp("eth", optarg) == 0) {
					type = ASM_PROTO_ETH;
				} else if (strcasecmp("ipv4", optarg) == 0) {
					type = ASM_PROTO_IP4;
				} else if (strcasecmp("ipv6", optarg) == 0) {
					type = ASM_PROTO_IP6;
					fprintf(stderr, "ipv6 is not "\
						"supporting right now.\n");
					failure |= ASM_ERR_PARM;
					r = -1;
					goto err;
				} else if (strcasecmp("tcp", optarg) == 0) {
					type = ASM_PROTO_TCP;
				} else if (strcasecmp("udp", optarg) == 0) {
					type = ASM_PROTO_UDP;
				} else {
					fprintf(stderr, "error parameter "\
						"format of: %s\n",
						long_options[longindex].name);
					failure |= ASM_ERR_PARM;
					r = -1;
					goto err;
				}
				if (set_ptype(cfg, type) < 0) {
					fprintf(stderr, "ptype conflicts.\n");
					failure |= ASM_ERR_PARM;
					r = -1;
					goto err;
				}
				break;
			}
			case 0x20:
				/* TODO: error detecting. */
				cfg->sport = atoi(optarg);
				break;
			case 0x40:
				/* TODO: error detecting. */
				cfg->dport = atoi(optarg);
				break;
			case 0x80: {
				int len, i;
				len = strlen(optarg);
				if (len % 2 != 0) {
					fprintf(stderr, "length of buf must "\
						"be double.\n");
					failure |= ASM_ERR_PARM;
					r = -1;
					goto err;
				}
				for (i = 0; i<len/2 && i<MAX_PKT_LEN; i++) {
					int v, tmp;
					tmp = x2c(optarg[i*2]);
					if (tmp < 0) {
						failure |= ASM_ERR_PARM;
						r = -1;
						goto err;
					}
					v = tmp << 4;
					tmp = x2c(optarg[i*2+1]);
					if (tmp < 0) {
						failure |= ASM_ERR_PARM;
						r = -1;
						goto err;
					}
					v += tmp;
					/* DEBUG */
					/*fprintf(stderr, "assign buf[%i]"\
							"=[%02x]\n", i, v); */
					cfg->buf[i] = v;
				}
				cfg->length = i;
				break;
			}
			case 0x0100: /* fix */ {
				char* tmp = NULL;
				long int len;

				cfg->fix = 1;
				len = strtol(optarg, &tmp, 0);
				if (strcmp(tmp, "\0") != 0) {
					fprintf(stderr, "err param of fix.\n");
					failure |= ASM_ERR_PARM;
					r = -1;
					goto err;
				}
				cfg->length = len;
				break;
			}
			default:
				break;
			}
			break;
		case 'i':
			fprintf(stderr, "argument for i: %s\n", optarg);
			if(strlen(optarg) >= MAX_IF_LEN - 1) {
				fprintf(stderr, "if name is too long.");
				failure |= ASM_ERR_PARM;
				r = -1;
				goto err;
			}
			flag = flag & ~0x0100;
			strncpy(cfg->ifname, optarg, MAX_IF_LEN-1);
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
	if (flag != 0) {
		fprintf(stderr, "All 'must' arguments must be set [%u].\n",
			flag);
		my_usage(argv[0]);
		r = -1;
	}
err:
	return r;
}

int fucking_push(struct configs* cfg, char* buf, size_t length)
{
	printf("go in fucking push!\n");
	int sock;
	int r = 0, sent;
	struct sockaddr_ll addr;

	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket: ");
		return -1;
	}
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);

	struct ifreq req;
	strncpy(req.ifr_name, cfg->ifname, sizeof(req.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &req) < 0) {
		perror("ioctl: ");
		r = -1;
		goto err;
	}
	addr.sll_ifindex =  req.ifr_ifindex;
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind: ");
		r = -1;
		goto err;
	}

	/* DEBUG: Packet for sending. */	
	printf("sock: %d length: %zd\n", sock, length);
	binary_print("packet", buf, length);

	sent = 0;
	while (sent < length) {
		r = send(sock, buf + sent, length - sent, 0);
		if (r < 0) {
			fprintf(stderr, "send [%d]: %s\n", errno,
				strerror(errno));
			r = -1;
			goto err;
		}
		sent += r;
	}
	printf("pkt send: [%d]\n", sent);
	assert(sent == length);
err:	
	close(sock);
	return r;
}

int main(int argc, char** argv)
{
	struct configs cfg;
	char* buf = pkt_buf;
	int len = 0;
	
	/* 1. deal with paremeters. format them into 'struct pktinfo'.*/
	if (talk_with_me(argc, argv, &cfg) < 0) {
		fprintf(stderr, "talk_with_me() error.\n");
		goto quit;
	}

	/* 2. Prepare packet buffer. transform 'pktinfo' into binary buffer. */
	if (cfg.fix) {
		serial_fill(cfg.buf, cfg.length);
	}
	if (cfg.l2_type == ASM_PROTO_RAW) {
		memcpy(buf, cfg.buf, cfg.length);
		len = cfg.length;
	} else {
		/* DEBUG: */
		binary_print("PKT CFG: dst_mac", (void*)&cfg.dst_mac,
				sizeof(cfg.dst_mac));
		binary_print("PKT CFG: src_mac", (void*)&cfg.src_mac,
				sizeof(cfg.src_mac));
		binary_print("PKT CFG: daddr", (void*)&cfg.daddr,
				sizeof(cfg.daddr));
		binary_print("PKT CFG: saddr", (void*)&cfg.saddr,
				sizeof(cfg.saddr));
		binary_print("PKT CFG: dport", (void*)&cfg.dport,
				sizeof(cfg.dport));
		binary_print("PKT CFG: sport", (void*)&cfg.sport,
				sizeof(cfg.sport));
		binary_print("PKT CFG: ptype", (void*)&cfg.ptype,
				sizeof(cfg.ptype));
		fprintf(stderr, "PKT CFG: l2_type : %02x\n", cfg.l2_type);
		fprintf(stderr, "PKT CFG: l3_type : %04x\n", cfg.l3_type);
		fprintf(stderr, "PKT CFG: l4_type : %02x\n", cfg.l4_type);
		binary_print("PKT CFG: ifname", (void*)&cfg.ifname,
				sizeof(cfg.ifname));
		binary_print("PKT CFG: buffer", (void*)&cfg.buf, cfg.length);

		/* 2B. Prepare pkt level by level. */
		if ((len = prepare_pkt(&cfg, buf, len)) < 0) {
			fprintf(stderr, "prepare_pkt() error.\n");
			goto quit;
		}
	}

	/* 3. Get a raw socket, then push pkt buffer off.*/
	if (fucking_push(&cfg, buf, len) < 0) {
		fprintf(stderr, "fucking_push() error.\n");
		goto quit;
	}
quit:
	fprintf(stderr, "exit(%d).\n", failure);
	return failure;
}
