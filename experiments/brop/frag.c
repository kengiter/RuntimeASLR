#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

static int _s;
static unsigned char _mac[6];
static int _ifidx;

#if 0
static void hexdump(void *x, int len)
{
	unsigned char *p = x;

	while (len--)
		printf("%.2x ", *p++);

	printf("\n");
}
#endif

static void send_data(unsigned char *p, int len)
{
	int rc;
	struct sockaddr_ll ll;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family   = PF_PACKET;
	ll.sll_protocol = htons(ETH_P_IP);
	ll.sll_halen    = 6;

	ll.sll_ifindex  = _ifidx;
	memcpy(ll.sll_addr, _mac, ll.sll_halen);

	if ((rc = sendto(_s, p, len, 0,
			 (struct sockaddr*) &ll, sizeof(ll))) == -1)
		errx(1, "sendto()");

	printf("Wrote %d\n", rc);
}

unsigned short in_cksum (unsigned short *ptr, int nbytes) {
  register long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while (nbytes > 1)
    { 
      sum += *ptr++;
      nbytes -= 2;
    }

  if (nbytes == 1)
    { 
      oddbyte = 0;
      *((u_char *) & oddbyte) = *(u_char *) ptr;
      sum += oddbyte;
    }
                                                                                                              
  sum = (sum >> 16) + (sum & 0xffff);                                                                         
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

static void out_packet(unsigned char *p, int len)
{
	struct ip *ip = (struct ip*) p;
	unsigned char packet[2048];
	struct ip *ip2 = (struct ip*) packet;
	unsigned char *p2;
	int iphl = ip->ip_hl * 4;
	int off = 0;
	int fragsize = iphl + 150 * 8;

/*
	printf("Got %d\n", len);
	hexdump(p, len);
*/

	if (ntohs(ip->ip_len) != len) {
		printf("whoops\n");
		return;
	}

	memcpy(ip2, ip, iphl);
	p2 = &packet[iphl];

	len -= iphl;
	p   += iphl;

	while (len > 0) {
		int sz = len + iphl;
		int ds;

		if (sz > fragsize)
			sz = fragsize;

		ds = sz - iphl;
		memcpy(p2, p, ds);

		ip2->ip_len = htons(sz);
		ip2->ip_off = off / 8;

		if ((len - ds) > 0)
			ip2->ip_off |= IP_MF;

		ip2->ip_off = htons(ip2->ip_off);

		if (off % 8)
			errx(1, "morte");

		ip2->ip_sum = 0;
		ip2->ip_sum = in_cksum((unsigned short*) ip2, iphl);

		send_data(packet, sz);

		len -= ds;
		p   += ds;
		off += ds;
	}
}

static void pwn(void)
{
	int fd, s;
	struct ifreq ifr;
	unsigned char buf[4096 * 10];
	int rc;

	if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
		err(1, "open()");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	strcpy(ifr.ifr_name, "frag0");

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
		err(1, "ioctl(TUNSETIFF)");

	if ((s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
		err(1, "socket()");

	_s = s;

	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		int off = 4;

		if (rc < off)
			errx(1, "damn");

		out_packet(&buf[off], rc - off);
	}
}

static void output_fix(int ifidx, char *p)
{
	int i;

	_ifidx = ifidx;

	for (i = 0; i < sizeof(_mac); i++) {
		char tmp[3];
		unsigned long x;

		tmp[0] = *p++;
		tmp[1] = *p++;
		tmp[2] = 0;

		p++;

		if (sscanf(tmp, "%lx", &x) != 1)
			errx(1, "mac parse error\n");

		_mac[i] = (unsigned char) x;
	}

	pwn();
	exit(0);
}

static int packet_input(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data)
{
	unsigned char *packet;
	int len;
        struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
        unsigned int id = ntohl(ph->packet_id);
	struct tcphdr *th;
	short diff;
	unsigned short win = 666;
	unsigned short sum;

        len = nfq_get_payload(nfa, &packet);
	if (len < 0)
		err(1, "nfq_get_payload()");

#if 0
	printf("Got %d bytes\n", len);
	hexdump(packet, len);
#endif

	th = (struct tcphdr*) (packet + 20);

#if 0
	printf("Changing window from %d -> %d [%d]\n",
	       ntohs(th->th_win), win, len);

	diff = win - ntohs(th->th_win);
	th->th_win = htons(win);
#endif
	unsigned short *mss = (unsigned short*) ((unsigned char*) th + 22);
	win = 10000;
	printf("MSS %d -> %d\n", ntohs(*mss), win);
	diff = win - ntohs(*mss);
	*mss = htons(win);

	sum = ntohs(th->th_sum);
	sum = ~sum;
	sum += diff;
	sum = ~sum;
	th->th_sum = htons(sum);

	nfq_set_verdict(qh, id, NF_ACCEPT, len, packet);

	return 0;
}

static void input_fix()
{
	struct nfq_handle *h;
	struct nfq_q_handle *q;
	int fd;
	unsigned char buf[2048];
	int len;

	if (!(h = nfq_open()))
		err(1, "nfq_open()");

        if (nfq_bind_pf(h, AF_INET) < 0)
		err(1, "nfq_bind_pf()");

	if (!(q = nfq_create_queue(h, 666, packet_input, NULL)))
		err(1, "nfq_create_queue()");

        if (nfq_set_mode(q, NFQNL_COPY_PACKET, 0xffff) < 0)
		err(1, "nfq_set_mode()");

	fd = nfq_fd(h);

	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		nfq_handle_packet(h, (char*) buf, len);
	}

	exit(0);
}

int main(int argc, char *argv[])
{
	int pid;

	if (argc < 3)
		errx(1, "Usage %s: <ifindex> <mac>", argv[0]);

	if ((pid = fork()) == -1)
		err(1, "fork()");

	if (pid == 0) {
		input_fix();
		exit(1);
	}

	output_fix(atoi(argv[1]), argv[2]);
	exit(1);
}
