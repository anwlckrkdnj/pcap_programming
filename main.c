#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libnet.h>
#include <netinet/in.h>

void func_tcp(const u_char* packet, uint16_t* tcp_dst_port, uint16_t* tcp_src_port){
	struct libnet_tcp_hdr tcp;
	memcpy(&tcp, packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr), sizeof(struct libnet_tcp_hdr));
	memcpy(tcp_dst_port, &tcp.th_dport, sizeof(uint16_t));
	memcpy(tcp_src_port, &tcp.th_sport, sizeof(uint16_t));
}

int func_ip(const u_char* packet, struct in_addr* ipv4_dst_addr, struct in_addr* ipv4_src_addr){
	struct libnet_ipv4_hdr ip;
	memcpy(&ip, packet + sizeof(struct libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
	if(ip.ip_p != 0x06)
		return -1;
	memcpy(ipv4_dst_addr, &ip.ip_dst, sizeof(struct in_addr));
	memcpy(ipv4_src_addr, &ip.ip_src, sizeof(struct in_addr));
	return 0;
}

int func_eth(const u_char* packet, uint8_t* eth_dst_addr, uint8_t* eth_src_addr){
	struct libnet_ethernet_hdr eth;
	memcpy(&eth, packet, sizeof(struct libnet_ethernet_hdr));
	if(eth.ether_type != ntohs(0x0800))
		return -1;
	memcpy(eth_dst_addr, &eth.ether_dhost, sizeof(eth.ether_dhost));
	memcpy(eth_src_addr, &eth.ether_shost, sizeof(eth.ether_shost));
	return 0;
}

void print_data(struct pcap_pkthdr* header, const u_char* packet){
	int total_hdr_len = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);	
	int len = (16 < header->caplen - total_hdr_len)?16:(header->caplen - total_hdr_len);
	printf("%d byte\n", len);
	if(!len)
		return;
	char tmp = 0;
	printf("ascii > ");
	for(int i = 0 ; i < len ; i++){
		memcpy(&tmp, packet + total_hdr_len + i, 1);
		printf("%c", tmp);
	}
	printf("\n");
}

void print_tcp(uint16_t tcp_port){
	printf("%d\n", ntohs(tcp_port));
}

void print_ip(struct in_addr* ip_addr){
	for(int i = 0; i < 4; i++){
		printf("%d", (ntohl(ip_addr->s_addr) >> (24 - 8 * i)) & 0xFF);
		if(i < 3)
			printf(".");
	}
	printf("\n");
}

void print_eth(uint8_t* mac_addr){
	for(int i = 0; i < 6; i++){
		printf("%02x", mac_addr[i]);
		if(i < 5)
			printf(".");
	}
	printf("\n");
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    int packet_number = 0;
    while (true) {
	packet_number++;
	printf("packet number : %d\n", packet_number);
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
	
	uint8_t eth_dst_addr[6];
	uint8_t eth_src_addr[6];
	struct in_addr ipv4_dst_addr;
	struct in_addr ipv4_src_addr;
	uint16_t tcp_dst_port;
	uint16_t tcp_src_port;

	if(func_eth(packet, eth_dst_addr, eth_src_addr)){
		printf("not ipv4 format\n\n");
		continue;
	}
	if(func_ip(packet, &ipv4_dst_addr, &ipv4_src_addr)){
		printf("not tcp format\n\n");
		continue;
	}
	func_tcp(packet, &tcp_dst_port, &tcp_src_port);

	printf("dst mac address : ");
	print_eth(eth_dst_addr);
	printf("src mac address : ");
	print_eth(eth_src_addr);
	printf("dst ip address : ");
	print_ip(&ipv4_dst_addr);
	printf("src ip address : ");
	print_ip(&ipv4_src_addr);
	printf("dst port number : ");
	print_tcp(tcp_dst_port);
	printf("src port number : ");
	print_tcp(tcp_src_port);
	printf("packet payload ");
	print_data(header, packet);
	printf("\n");
    }

    pcap_close(handle);

    return 0;
}
