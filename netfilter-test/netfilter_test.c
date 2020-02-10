#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
// for strstr()
#include <string.h>

//#define DEBUG 1
char *host;

static inline int
isCapital(char x)
{
	return x >= 'A' && x <= 'Z';
}



/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, int* result)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);

		size_t ip_header_len = (data[0] & 0xf) << 2;
		size_t ip_total_len = (size_t)ntohs((*(uint16_t*)&data[2]));
		
		char* tcp_header_ptr = data + ip_header_len;
		size_t tcp_header_len = tcp_header_ptr[12] >> 2;
		char* tcp_data_ptr = tcp_header_ptr + tcp_header_len;
	
	#ifdef DEBUG
		printf("ip_header_len: %lu\n", ip_header_len);
		printf("ip_total_len: %lu\n", ip_total_len);
		printf("tcp_header_len: %lu\n", tcp_header_len);
	
		printf("tcp_len: %lu\n", ip_total_len - ip_header_len);	
		for(int i = 0; i < ip_total_len - ip_header_len; i++) {
			if( i % 16 == 0) puts("");
			printf("%02X ", tcp_header_ptr[i]);
		}
	#endif
		// HTTP
		
		// Packets with short tcp payloads --> PASS
		size_t tcp_data_len = ip_total_len - ip_header_len - tcp_header_len;
		if(!tcp_data_len) {
			*result = NF_ACCEPT;
			return id;
		}

		// Every HTTP request starts 
		// with HTTP method name or 'HTTP'(All in captial letters)
		for(int i = 0; i < 3; i++) {
			if(!isCapital(tcp_data_ptr[i])) {
				*result = NF_ACCEPT;
				return id;
			}
		}

		char* http_host = NULL;
		
		// Find carriage return in HTTP request
		for(int i = 0; i < 30; i++) {
			uint16_t carriage_return = 0x0a0d;
		
			if(*(uint16_t*)(tcp_data_ptr + i) == carriage_return) {
				http_host = tcp_data_ptr + i + 8;
				break;
			}

		}
		
		if(!http_host) {
			*result = NF_ACCEPT;
			return id;
		}

		if (!memcmp(host, http_host, strlen(host))) {
			*result = NF_DROP;
		} else {
			*result = NF_ACCEPT;
		}
	
		return id;
	}
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	// print_pkt() printf packet info
	// and stores whether the packet is filtered or not
	// by storing value in result variable.
	int result;
	u_int32_t id = print_pkt(nfa, &result);
	
	printf("entering callback\n");
	// result is either NF_ACCEPT or NF_DROP.
	return nfq_set_verdict(qh, id, result, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc < 2) {
		puts("Usage: ./netfilter_test <host>");
	}
	host = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);
	#ifdef DEBUG
	int i = 0;
	#endif

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		#ifdef DEBUG
			printf("%d: ", i++);
		#endif
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

