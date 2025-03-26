#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <string.h>

#define SNAP_LEN 1518  // 캡처할 최대 패킷 크기
#define ETHERNET_HEADER_LEN 14  // Ethernet 헤더 크기

// 패킷 분석 함수
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct ether_header *eth_header = (struct ether_header *) bytes;
    printf("\n===== Captured TCP Packet =====\n");

    // Ethernet Header 출력
    printf("Ethernet Header:\n");
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));

    // IP 패킷인지 확인
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(bytes + ETHERNET_HEADER_LEN);
        int ip_header_len = ip_header->ip_hl * 4;

        printf("\nIP Header:\n");
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        // TCP 패킷인지 확인
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(bytes + ETHERNET_HEADER_LEN + ip_header_len);
            int tcp_header_len = tcp_header->th_off * 4;

            printf("\nTCP Header:\n");
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

            // TCP 데이터 (Payload) 출력
            int data_offset = ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;
            int data_length = h->caplen - data_offset;

            if (data_length > 0) {
                printf("\nTCP Message Data (%d bytes):\n", data_length);
                fwrite(bytes + data_offset, 1, data_length, stdout);
                printf("\n");
            }
        }
    }
    printf("===============================\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 사용할 네트워크 인터페이스
    char *dev = "ens33";

    printf("📡 Capturing on device: %s\n", dev);

    // 네트워크 인터페이스에서 패킷 캡처 시작
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // TCP 패킷만 캡처하도록 필터 설정
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // 패킷 캡처 실행 (무한 루프)
    pcap_loop(handle, -1, packet_handler, NULL);

    // 핸들 닫기
    pcap_close(handle);
    return 0;
}
