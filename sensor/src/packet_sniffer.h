#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <string>

class PacketSniffer {
public:
    explicit PacketSniffer(int device_num);
    ~PacketSniffer();
    void start_sniffing();

private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];   // <- must be present
    static void packet_handler_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);
    void process_packet(const u_char* packet_data);
    void process_packet_with_len(const u_char* packet_data, bpf_u_int32 packet_len);
};

#endif // PACKET_SNIFFER_H
