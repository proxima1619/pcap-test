#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(const uint8_t* mac) {
	for (int i = 0; i < 6; i++) {
		printf("%02x", mac[i]);
		if (i != 5) printf(":");
	}
}

void print_payload(const u_char* data, int len) {
	int print_len = len;
	if (print_len > 20) print_len = 20;

	for (int i = 0; i < print_len; i++) {
		printf("%02x", data[i]);
		if (i != print_len - 1) printf(" ");
	}
}

void process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
	if (header->caplen < sizeof(struct libnet_ethernet_hdr)) return;

	const struct libnet_ethernet_hdr* eth =
		(const struct libnet_ethernet_hdr*)packet;

	if (ntohs(eth->ether_type) != 0x0800) return;

	int eth_len = sizeof(struct libnet_ethernet_hdr);

	if (header->caplen < eth_len + sizeof(struct libnet_ipv4_hdr)) return;

	const struct libnet_ipv4_hdr* ip =
		(const struct libnet_ipv4_hdr*)(packet + eth_len);

	int ip_header_len = ip->ip_hl * 4;

	if (ip->ip_p != IPPROTO_TCP) return;

	if (header->caplen < eth_len + ip_header_len + sizeof(struct libnet_tcp_hdr)) return;

	const struct libnet_tcp_hdr* tcp =
		(const struct libnet_tcp_hdr*)(packet + eth_len + ip_header_len);

	int tcp_header_len = tcp->th_off * 4;

	int payload_len = ntohs(ip->ip_len) - ip_header_len - tcp_header_len;

	const u_char* payload = packet + eth_len + ip_header_len + tcp_header_len;

	printf("ETH src=");
	print_mac(eth->ether_shost);
	printf(" dst=");
	print_mac(eth->ether_dhost);
	printf("\n");

	printf("IP src=%s ", inet_ntoa(ip->ip_src));
	printf("dst=%s\n", inet_ntoa(ip->ip_dst));

	printf("TCP src port=%u dst port=%u\n",
		ntohs(tcp->th_sport),
		ntohs(tcp->th_dport));

	printf("Payload=");
	print_payload(payload, payload_len);
	printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		process_packet(header, packet);
	}

	pcap_close(pcap);
	return 0;
}
