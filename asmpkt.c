/**
*	Awesome packet.
*		by Cao Tong<tony_caotong@gmail.com> 
*		at 2017-01-13
*/


#include <stdio.h>
#include <stdint.h>
#include <getopt.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
// struct iphdr
#include <netinet/tcp.h>
// struct tcphdr

#define ASM_ERR_NONE 0x00000000
#define ASM_ERR_PARM 0x00000001


uint32_t failure = ASM_ERR_NONE;

typedef struct pktinfo Pktinfo;

struct configs {
	/* Src Mac, Dst Mac*/
	struct ether_addr des_mac;
	struct ether_addr src_mac;
	/* sip addr, dip addr*/
	uint32_t saddr;
	uint32_t daddr;
	/* l4 protocol type */
	uint8_t protocol;
	/* sport. dport*/
	uint16_t sport;
	uint16_t dport;
	/* payloads */
	unsigned char* buf;
} __attribute__((__packed__));

struct pktinfo {

};

int prepare_pkt()
{
	uint32_t failure = ASM_ERR_NONE;
	return failure;
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

	while (1) {
		static struct option long_options[] = {
			{"test", no_argument, 0, 0},
			{"test-print", required_argument, 0, 0},
			{"verbose_0", required_argument, &verbose_flag, 0},
			{"verbose_1", required_argument, &verbose_flag, 1},
			{"verbose_2", required_argument, &verbose_flag, 2},
			{"verbose_3", required_argument, &verbose_flag, 3},
			{"verbose_4", no_argument, &verbose_flag, 4},
			{0,0,0,0}
		};

		int longindex = 0;

		opt = getopt_long(argc, argv, "hab:",
				long_options, &longindex);
		
		if (opt == -1)
			break;
		switch (opt) {
		case 0:
			printf("argu: %s: ", long_options[longindex].name);
			if (optarg)
				printf("%s", optarg);
			if (long_options[longindex].flag != 0) {
				printf("flag: %lu: ",
					(uint64_t)(long_options[longindex].flag));
				printf("verbose_flag: %d ", verbose_flag);
				printf("*flag: %d: ",
					*(long_options[longindex].flag));
				printf("val: %d: ", long_options[longindex].val);
			}
			printf("\n");
			break;
		case 'a':
			fprintf(stderr, "found param a.\n");
			break;
		case 'b':
			fprintf(stderr, "argument of b: %s\n", optarg);
			break;
		case ':':
			fprintf(stderr, "here is : \n");
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
err:
	return r;
}

int fucking_push()
{
	struct ether_header eth;
	return 0;
}

int main(int argc, char** argv)
{
	struct configs cfg;
	
	/* 1. deal with paremeters. format them into 'struct pktinfo'.*/
	if (talk_with_me(argc, argv, &cfg) < 0) {
		goto quit;
	}

	/* 2. Prepare packet buffer. transform 'pktinfo' into binary buffer. */

	/* 3. Get a raw socket, then push pkt buffer off.*/

quit:
	return failure;
}
