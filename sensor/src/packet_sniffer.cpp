// packet_sniffer.cpp
#include "packet_sniffer.h"

#include "packet_sniffer.h"
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <cstring>
#include <winsock2.h>
using namespace std;

// Define TCP flag macros if platform headers didn't
#ifndef TH_SYN
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#endif

// Helper: format current time
static string get_current_time_str()
{
    time_t raw = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&raw));
    return string(buf);
}

// Convert network-order uint32_t to dotted IP string
static string ip_to_string(uint32_t net_ip)
{
    struct in_addr addr;
    addr.s_addr = net_ip; // network order as expected by inet_ntoa
    return string(inet_ntoa(addr));
}

// Logging helper (append)
static void log_alert_to_file(const string &json)
{
    ofstream ofs("intrusion_alerts.log", ios::app);
    if (ofs)
    {
        ofs << json;
        ofs.close();
    }
}

// Simple TCP SYN tracking record
struct TCPScanRecord
{
    int syns = 0;
    chrono::steady_clock::time_point first_seen;
};

static unordered_map<string, TCPScanRecord> scan_tracker;

// Whitelist of common server ports (do NOT include 22/3389 if you want those alerted)
static const unordered_set<uint16_t> SAFE_SERVER_PORTS = {
    80,   // HTTP
    443,  // HTTPS
    53,   // DNS
    123,  // NTP
    853,  // DNS over TLS
    5353, // mDNS
    4500  // IPsec NAT-T
};

// PacketSniffer methods

PacketSniffer::PacketSniffer(int device_num) : handle(nullptr)
{
    if (device_num <= 0)
        device_num = 1;

    pcap_if_t *alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cerr << "Error finding devices: " << errbuf << endl;
        exit(1);
    }
    if (!alldevs)
    {
        cerr << "No devices found." << endl;
        exit(1);
    }

    // Choose 1-based device number: 1 => first device
    pcap_if_t *dev = alldevs;
    int idx = 1;
    while (dev && idx < device_num)
    {
        dev = dev->next;
        ++idx;
    }

    if (!dev)
    {
        cerr << "Error: Device number " << device_num << " not found." << endl;
        cerr << "Available devices:" << endl;
        int i = 1;
        for (pcap_if_t *d = alldevs; d; d = d->next, ++i)
        {
            cerr << "  " << i << ": " << (d->description ? d->description : d->name) << endl;
        }
        pcap_freealldevs(alldevs);
        exit(1);
    }

    cerr << "---" << endl;
    cerr << "Attempting to sniff on device " << device_num << ": " << (dev->description ? dev->description : dev->name) << endl;
    cerr << "---" << endl;

    handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);
    if (!handle)
    {
        cerr << "Couldn't open device " << dev->name << ": " << errbuf << endl;
        exit(1);
    }
}

PacketSniffer::~PacketSniffer()
{
    if (handle)
    {
        pcap_close(handle);
    }
}

void PacketSniffer::start_sniffing()
{
    pcap_loop(handle, -1, packet_handler_callback, reinterpret_cast<u_char *>(this));
}

// static callback required by libpcap
void PacketSniffer::packet_handler_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_data)
{
    PacketSniffer *sniffer = reinterpret_cast<PacketSniffer *>(user_data);
    if (sniffer && packet_data && pkthdr)
    {
        sniffer->process_packet_with_len(packet_data, pkthdr->len);
    }
}

// legacy compatibility (no-op)
void PacketSniffer::process_packet(const u_char * /*packet_data*/)
{
    return;
}

// length-aware processing (safe parsing)
void PacketSniffer::process_packet_with_len(const u_char *packet_data, bpf_u_int32 packet_len)
{
    if (!packet_data || packet_len < 14)
        return; // must have ethernet header

    const size_t ETH_HDR_LEN = 14;
    const u_char *eth = packet_data;

    // EtherType at offset 12-13
    uint16_t eth_type_net = 0;
    memcpy(&eth_type_net, eth + 12, sizeof(eth_type_net));
    uint16_t eth_type = ntohs(eth_type_net);
    const uint16_t ETH_P_IP = 0x0800;
    if (eth_type != ETH_P_IP)
        return; // not IPv4

    // IP header starts at offset 14
    if (packet_len < ETH_HDR_LEN + 20)
        return; // minimal IPv4 header
    const u_char *ip_ptr = packet_data + ETH_HDR_LEN;

    uint8_t ver_ihl = ip_ptr[0];
    uint8_t ip_ver = (ver_ihl >> 4) & 0x0F;
    uint8_t ihl = ver_ihl & 0x0F;
    if (ip_ver != 4 || ihl < 5)
        return;

    size_t ip_header_len = static_cast<size_t>(ihl) * 4;
    if (packet_len < ETH_HDR_LEN + ip_header_len)
        return; // truncated IP header

    // Protocol at offset 9
    uint8_t proto = ip_ptr[9];

    // Source/dest IP at offsets 12 and 16
    uint32_t src_addr_net = 0, dst_addr_net = 0;
    memcpy(&src_addr_net, ip_ptr + 12, 4);
    memcpy(&dst_addr_net, ip_ptr + 16, 4);
    string src_ip = ip_to_string(src_addr_net);
    string dst_ip = ip_to_string(dst_addr_net);

    auto emit_alert_json = [&](const string &proto_name, const string &severity, const string &description)
    {
        ostringstream ss;
        ss << "{"
           << "\"time\":\"" << get_current_time_str() << "\","
           << "\"src_ip\":\"" << src_ip << "\","
           << "\"dst_ip\":\"" << dst_ip << "\","
           << "\"proto\":\"" << proto_name << "\","
           << "\"severity\":\"" << severity << "\","
           << "\"desc\":\"" << description << "\""
           << "}\n";
        cout << ss.str();
        cout.flush();
        log_alert_to_file(ss.str());
    };

    //  ICMP handling (protocol 1)
    if (proto == 1)
    {
        // Smarter ICMP: ignore local outgoing pings and detect flood
        static unordered_map<string, int> icmp_count;
        static chrono::steady_clock::time_point last_cleanup = chrono::steady_clock::now();

        // cleanup every 5 seconds
        auto now = chrono::steady_clock::now();
        if (chrono::duration_cast<chrono::seconds>(now - last_cleanup).count() > 5)
        {
            icmp_count.clear();
            last_cleanup = now;
        }

        // Determine if source IP is in private ranges (simple check)
        bool src_is_private = false;
        // check 10., 172.16-31., 192.168.
        // We have net-order src_addr_net; convert to host-order for byte checks
        uint32_t src_host = ntohl(src_addr_net);
        uint8_t b0 = (src_host >> 24) & 0xFF;
        uint8_t b1 = (src_host >> 16) & 0xFF;
        if (b0 == 10)
            src_is_private = true;
        else if (b0 == 192 && b1 == 168)
            src_is_private = true;
        else if (b0 == 172 && (b1 >= 16 && b1 <= 31))
            src_is_private = true;

        // If source is local/private, ignore (likely our own outgoing ping)
        if (src_is_private)
        {
            return;
        }

        // track ICMP flows by src->dst
        string key = src_ip + "->" + dst_ip;
        icmp_count[key]++;

        // threshold: more than 10 ICMP packets in cleanup window = flood
        if (icmp_count[key] > 10)
        {
            emit_alert_json("ICMP", "medium", "High ICMP traffic detected (possible ping flood) from " + src_ip);
            icmp_count[key] = 0;
        }
        return;
    }

    //  UDP handling (protocol 17)
    if (proto == 17)
    {
        return;
    }

    //  TCP handling (protocol 6)
    if (proto == 6)
    {
        size_t tcp_off = ETH_HDR_LEN + ip_header_len;
        // require at least minimal TCP header (20 bytes)
        if (packet_len < tcp_off + 20)
            return;

        // read src/dst ports (network order)
        uint16_t src_port_net = 0, dst_port_net = 0;
        memcpy(&src_port_net, packet_data + tcp_off + 0, sizeof(uint16_t));
        memcpy(&dst_port_net, packet_data + tcp_off + 2, sizeof(uint16_t));
        uint16_t src_port = ntohs(src_port_net);
        uint16_t dst_port = ntohs(dst_port_net);

        // early whitelist: ignore common service ports to avoid false positives
        static const unordered_set<uint16_t> SAFE_PORTS = {80, 443, 53, 123, 853, 5353, 4500};
        if (SAFE_PORTS.count(dst_port))
        {
            // If you prefer to record normal web traffic as low severity uncomment:
            // emit_alert_json("TCP", "low", "Normal traffic on safe port " + to_string(dst_port));
            return;
        }

        // read TCP data-offset and flags (offset 12 and 13 within TCP header)
        uint8_t data_off_byte = packet_data[tcp_off + 12];
        uint8_t tcp_flags = packet_data[tcp_off + 13];
        uint8_t tcp_hdr_len = ((data_off_byte >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20 || packet_len < tcp_off + tcp_hdr_len)
            return;

        // flags
        bool is_syn = (tcp_flags & TH_SYN) != 0;
        bool is_ack = (tcp_flags & TH_ACK) != 0;
        bool is_rst = (tcp_flags & TH_RST) != 0;
        bool is_fin = (tcp_flags & TH_FIN) != 0;
        bool is_psh = (tcp_flags & TH_PUSH) != 0;

        // explicit important ports
        if (dst_port == 22)
        {
            emit_alert_json("TCP", "high", "Potential SSH connection detected to port 22");
            return;
        }
        if (dst_port == 3389)
        {
            emit_alert_json("TCP", "high", "Potential RDP connection detected to port 3389");
            return;
        }

        // Only consider "pure SYN" probes for scan detection
        if (is_syn && !is_ack && !is_rst && !is_fin && !is_psh)
        {
            // sliding-window per src->dst key using chrono
            string key = src_ip + "->" + dst_ip;
            auto &rec = scan_tracker[key]; // TCPScanRecord defined previously with 'syns' and 'first_seen'
            auto now = chrono::steady_clock::now();

            if (rec.syns == 0)
            {
                rec.syns = 1;
                rec.first_seen = now;
            }
            else
            {
                auto elapsed_ms = chrono::duration_cast<chrono::milliseconds>(now - rec.first_seen).count();
                if (elapsed_ms <= 5000)
                { // 5 second window
                    rec.syns++;
                }
                else
                {
                    // window expired -> reset
                    rec.syns = 1;
                    rec.first_seen = now;
                }
            }

            const int SYN_THRESHOLD = 10;
            if (rec.syns > SYN_THRESHOLD)
            {
                emit_alert_json("TCP", "critical",
                                "TCP SYN flood/scan detected from " + src_ip + " to " + dst_ip +
                                    " (" + to_string(rec.syns) + " probes)");
                rec.syns = 0;
            }
            return;
        }

        if (is_rst)
        {
            emit_alert_json("TCP", "medium", "RST observed on port " + to_string(dst_port) + " from " + src_ip);
            return;
        }
    }

    return;
}
