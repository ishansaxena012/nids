#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <fstream>  // Required for std::ofstream
#include <string>

class PacketSniffer {
public:
    explicit PacketSniffer(int device_num);
    ~PacketSniffer();

    // Non-copyable
    PacketSniffer(const PacketSniffer&) = delete;
    PacketSniffer& operator=(const PacketSniffer&) = delete;

    // Non-movable (for now)
    PacketSniffer(PacketSniffer&&) = delete;
    PacketSniffer& operator=(PacketSniffer&&) = delete;

    // Start packet capture loop (blocking)
    void start_sniffing();

private:
    pcap_t* handle_;           // libpcap capture handle

    // Persistent log stream for performance fix
    std::ofstream log_stream_;

    static void packet_handler_callback(
        u_char* user_data,
        const pcap_pkthdr* pkthdr,
        const u_char* packet_data);

    void process_packet(const u_char* packet_data);

    // <-- SIGNATURE FIX: member function taking packet pointer + length
    void process_packet_with_len(const u_char* packet_data, bpf_u_int32 packet_len);
};

#endif  // PACKET_SNIFFER_H
