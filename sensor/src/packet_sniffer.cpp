#include "packet_sniffer.h"
#define _WIN32_WINNT 0x0600

#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>   // getnameinfo, NI_* macros, InetPton/InetNtop on Windows
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <iomanip>
// MUTEX INCLUDE REMOVED

#ifndef TH_SYN
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#endif

#pragma comment(lib, "Ws2_32.lib") // Ensure Ws2_32 is linked

extern "C" {
    __declspec(dllimport) int __stdcall inet_pton(int af, const char* src, void* dst);
    __declspec(dllimport) const char* __stdcall inet_ntop(int af, const void* src, char* dst, socklen_t size);
}
namespace
{
    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    // Simple TCP SYN tracking record
    struct TCPScanRecord
    {
        int       syns      = 0;
        TimePoint first_seen = {};
    };

    // Global trackers (NO MUTEX GUARD)
    static std::unordered_map<std::string, std::pair<std::string, TimePoint>> g_dns_cache;
    static constexpr auto DNS_CACHE_TTL = std::chrono::minutes(10);
    static std::unordered_map<std::string, TCPScanRecord> scan_tracker;
    // Mutexes removed

    // Whitelist of common server ports
    const std::unordered_set<std::uint16_t> SAFE_SERVER_PORTS{
        80, 443, 53, 123, 853, 5353, 4500
    };

    // // Compat wrappers for thread-safe functions (still needed)
    // static int inet_pton_compat(int af, const char* src, void* dst)
    // {
    //     // MinGW/GCC should map this to the correct underlying function
    //     return inet_pton(af, src, dst);
    // }

    // static const char* inet_ntop_compat(int af, const void* src, char* dst, socklen_t size)
    // {
    //     // MinGW/GCC should map this to the correct underlying function
    //     return inet_ntop(af, src, dst, size);
    // }

    // Helper: format current time as string
    std::string get_current_time_str()
    {
        std::time_t raw = std::time(nullptr);
        char        buf[32]{};
        if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&raw)) == 0)
        {
            return "1970-01-01 00:00:00";
        }
        return std::string{buf};
    }

    // Convert network-order uint32_t to dotted IP string (Using safer inet_ntop_compat)
    std::string ip_to_string(std::uint32_t net_ip)
    {
        in_addr addr{};
        addr.s_addr = net_ip;
        char buf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &addr, buf, static_cast<socklen_t>(sizeof(buf))))
        {
            return std::string{buf};
        }
        // Fallback if inet_ntop fails
        std::uint32_t host = ntohl(net_ip);
        std::ostringstream ss;
        ss << ((host >> 24) & 0xFF) << '.' << ((host >> 16) & 0xFF) << '.' << ((host >> 8) & 0xFF) << '.' << (host & 0xFF);
        return ss.str();
    }

    // Helper: Check if an IPv4 address is in private ranges
    bool is_private_ipv4(std::uint32_t net_ip)
    {
        std::uint32_t host_ip = ntohl(net_ip);
        std::uint8_t  b0      = static_cast<std::uint8_t>((host_ip >> 24) & 0xFF);
        std::uint8_t  b1      = static_cast<std::uint8_t>((host_ip >> 16) & 0xFF);

        if (b0 == 10) return true;
        if (b0 == 192 && b1 == 168) return true;
        if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
        return false;
    }

    // JSON-escape helper
    static std::string json_escape(const std::string& s) {
        std::string out; out.reserve(s.size());
        for (unsigned char c : s) {
            switch (c) {
                case '\"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buf[7];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        return out;
    }

    // Helper: Reverse DNS lookup with thread-safe TTL cache (Mutexes removed from logic block)
    static std::string resolve_host_for_ip(const std::string& ip)
    {
        if (ip.empty()) return std::string();

        const auto now = Clock::now();

        // NO MUTEX HERE: relies on single-threaded nature of pcap_loop
        auto it = g_dns_cache.find(ip);
        if (it != g_dns_cache.end())
        {
            if (now - it->second.second < DNS_CACHE_TTL)
            {
                return it->second.first; // cached name or numeric fallback
            }
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1)
        {
            return std::string();
        }

        char hostbuf[NI_MAXHOST] = {0};
        int res = getnameinfo(
            reinterpret_cast<sockaddr*>(&sa),
            static_cast<socklen_t>(sizeof(sa)),
            hostbuf,
            sizeof(hostbuf),
            nullptr,
            0,
            0); // 0 instead of NI_NAMEREQD

        std::string host_res;
        if (res == 0)
        {
            host_res = hostbuf;
        }
        else
        {
            // fallback: numeric textual address
            char numbuf[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &sa.sin_addr, numbuf, static_cast<socklen_t>(sizeof(numbuf))))
            {
                host_res = numbuf;
            }
            else
            {
                host_res = ip;
            }
        }

        // NO MUTEX HERE: relies on single-threaded nature of pcap_loop
        g_dns_cache[ip] = std::make_pair(host_res, now);

        return host_res;
    }

} // namespace



// PacketSniffer Implementation
PacketSniffer::PacketSniffer(int device_num)
    : handle_(nullptr)
{
    // --- CRITICAL FIX: Initialize Winsock (WSAStartup) ---
    // Required for getnameinfo, InetPton, and other socket API calls on Windows.
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed. DNS resolution may fail.\n";
        }
    }

    if (device_num <= 0)
        device_num = 1;

    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return;
    }

    if (!alldevs)
    {
        std::cerr << "No devices found.\n";
        return;
    }

    pcap_if_t* dev = alldevs;
    int        idx = 1;
    while (dev && idx < device_num)
    {
        dev = dev->next;
        ++idx;
    }

    if (!dev)
    {
        std::cerr << "Error: Device number " << device_num << " not found.\n";
        std::cerr << "Available devices:\n";
        int i = 1;
        for (pcap_if_t* d = alldevs; d; d = d->next, ++i)
        {
            std::cerr << "   " << i << ": "
                      << (d->description ? d->description : d->name) << "\n";
        }
        pcap_freealldevs(alldevs);
        return;
    }

    std::cerr << "---\n";
    std::cerr << "Attempting to sniff on device " << device_num << ": "
              << (dev->description ? dev->description : dev->name) << "\n";
    std::cerr << "---\n";

    handle_ = pcap_open_live(dev->name,
                             65536,  // snaplen
                             1,      // promiscuous
                             1000,   // timeout ms
                             errbuf);

    pcap_freealldevs(alldevs);

    if (!handle_)
    {
        std::cerr << "Couldn't open device " << dev->name << ": " << errbuf << "\n";
        return;
    }

    // Apply a BPF filter to reduce captured traffic (IP + TCP/ICMP only)
    {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp, "ip and (tcp or icmp)", 1, PCAP_NETMASK_UNKNOWN) == 0)
        {
            if (pcap_setfilter(handle_, &fp) != 0)
            {
                std::cerr << "Warning: pcap_setfilter failed\n";
            }
            pcap_freecode(&fp);
        }
    }

    // Open the persistent log stream once and enable immediate flush (unitbuf)
    log_stream_.open("intrusion_alerts.log", std::ios::app);
    if (!log_stream_.is_open())
    {
        std::cerr << "Warning: Could not open intrusion_alerts.log for writing.\n";
    }
    else
    {
        log_stream_.setf(std::ios::unitbuf); // flush after each write
    }
}

PacketSniffer::~PacketSniffer()
{
    if (handle_)
    {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    if (log_stream_.is_open())
    {
        log_stream_.close();
    }
    // --- CRITICAL FIX: Clean up Winsock ---
    WSACleanup();
    // ----------------------------------------
}

void PacketSniffer::start_sniffing()
{
    if (!handle_)
    {
        std::cerr << "pcap handle is null. Cannot start sniffing.\n";
        return;
    }

    pcap_loop(handle_,
              -1, // infinite loop
              &PacketSniffer::packet_handler_callback,
              reinterpret_cast<u_char*>(this));
}

// static callback required by libpcap
void PacketSniffer::packet_handler_callback(
    u_char* user_data,
    const pcap_pkthdr* pkthdr,
    const u_char* packet_data)
{
    auto* sniffer = reinterpret_cast<PacketSniffer*>(user_data);
    if (!sniffer || !pkthdr || !packet_data)
    {
        return;
    }

    // FIX: Call site now uses the correct 2-argument signature for the instance method
    sniffer->process_packet_with_len(packet_data, pkthdr->len);
}

// Legacy compatibility (no-op)
void PacketSniffer::process_packet(const u_char* /*packet_data*/)
{
    // Intentionally left empty for backwards compatibility
}

// Length-aware processing (safe parsing)
// FIX: Function definition is simplified back to 2 arguments to match the call above
void PacketSniffer::process_packet_with_len(const u_char* packet_data,
                                            bpf_u_int32   packet_len)
{
    if (!packet_data || packet_len < 14U)
    {
        return;
    }

    constexpr std::uint16_t ETH_P_IP = 0x0800;

    const u_char* eth = packet_data;

    std::uint16_t eth_type_net = 0;
    std::memcpy(&eth_type_net, eth + 12, sizeof(eth_type_net));
    std::uint16_t eth_type = ntohs(eth_type_net);
    std::size_t eth_hdr_len = 14U;

    // Handle single 802.1Q VLAN tag (0x8100)
    if (eth_type == 0x8100 && packet_len >= 18U)
    {
        std::memcpy(&eth_type_net, eth + 16, sizeof(eth_type_net));
        eth_type = ntohs(eth_type_net);
        eth_hdr_len = 18U;
    }

    if (eth_type != ETH_P_IP)
    {
        return;
    }

    if (packet_len < eth_hdr_len + 20U)
    {
        return;
    }

    const u_char* ip_ptr = packet_data + eth_hdr_len;

    const std::uint8_t ver_ihl = ip_ptr[0];
    const std::uint8_t ip_ver  = (ver_ihl >> 4) & 0x0F;
    const std::uint8_t ihl     = ver_ihl & 0x0F;

    if (ip_ver != 4 || ihl < 5)
    {
        return;
    }

    const std::size_t ip_header_len = static_cast<std::size_t>(ihl) * 4U;
    if (packet_len < eth_hdr_len + ip_header_len)
    {
        return;
    }

    // Fragmentation: skip non-first fragments
    std::uint16_t frag_off_net = 0;
    std::memcpy(&frag_off_net, ip_ptr + 6, sizeof(frag_off_net));
    std::uint16_t frag_off = ntohs(frag_off_net);
    if ((frag_off & 0x1FFF) != 0)
    {
        return;
    }

    const std::uint8_t proto = ip_ptr[9];

    std::uint32_t src_addr_net = 0;
    std::uint32_t dst_addr_net = 0;

    std::memcpy(&src_addr_net, ip_ptr + 12, sizeof(src_addr_net));
    std::memcpy(&dst_addr_net, ip_ptr + 16, sizeof(dst_addr_net));

    const std::string src_ip = ip_to_string(src_addr_net);
    const std::string dst_ip = ip_to_string(dst_addr_net);

    // Helper: pick IP to resolve (for host)
    auto pick_remote_ip = [&]() -> std::string
    {
        bool src_private = is_private_ipv4(src_addr_net);
        bool dst_private = is_private_ipv4(dst_addr_net);

        if (!src_private && dst_private)
            return src_ip;
        if (!dst_private && src_private)
            return dst_ip;

        return std::string();
    };

    // Helper: Emit alert as JSON, explicitly capturing 'this'
    auto emit_alert_json =
    [this, src_ip, dst_ip](const std::string& proto_name,
        const std::string& severity,
        const std::string& description,
        const std::string& host)
    {
        std::ostringstream ss;
        ss << '{'
           << "\"time\":\""    << get_current_time_str() << "\","
           << "\"src_ip\":\""  << json_escape(src_ip) << "\","
           << "\"dst_ip\":\""  << json_escape(dst_ip) << "\","
           << "\"proto\":\""   << json_escape(proto_name) << "\","
           << "\"severity\":\""<< json_escape(severity) << "\","
           << "\"desc\":\""    << json_escape(description) << "\"";

        if (!host.empty())
        {
            ss << ",\"host\":\"" << json_escape(host) << "\"";
        }
        ss << "}\n";

        const std::string json = ss.str();

        std::cout << json;
        std::cout.flush();

        // Access member via 'this' pointer
        if (this->log_stream_.is_open())
        {
            this->log_stream_ << json;
        }
    };

    // -------------------------------------------------------------------------
    // ICMP handling (protocol 1)
    // -------------------------------------------------------------------------
    if (proto == 1)
    {
        static std::unordered_map<std::string, int> icmp_count;
        static TimePoint last_cleanup = Clock::now();

        const auto now = Clock::now();

        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup).count() > 5)
        {
            icmp_count.clear();
            last_cleanup = now;
        }

        const std::string key = src_ip + "->" + dst_ip;
        ++icmp_count[key];

        if (icmp_count[key] > 3)
        {
            std::string host = resolve_host_for_ip(pick_remote_ip());
            emit_alert_json(
                "ICMP",
                "medium",
                "High ICMP traffic detected (possible ping flood) from " + src_ip,
                host);
            icmp_count[key] = 0;
        }
        return;
    }

    // -------------------------------------------------------------------------
    // UDP handling (protocol 17)
    // -------------------------------------------------------------------------
    if (proto == 17)
    {
        return;
    }

    // -------------------------------------------------------------------------
    // TCP handling (protocol 6)
    // -------------------------------------------------------------------------
    if (proto == 6)
    {
        const std::size_t tcp_off = eth_hdr_len + ip_header_len;

        if (packet_len < tcp_off + 20U)
        {
            return;
        }

        std::uint16_t src_port_net = 0;
        std::uint16_t dst_port_net = 0;

        std::memcpy(&src_port_net, packet_data + tcp_off + 0, sizeof(src_port_net));
        std::memcpy(&dst_port_net, packet_data + tcp_off + 2, sizeof(dst_port_net));

        const std::uint16_t src_port = ntohs(src_port_net);
        const std::uint16_t dst_port = ntohs(dst_port_net);

        const std::uint8_t data_off_byte = packet_data[tcp_off + 12];
        const std::uint8_t tcp_flags     = packet_data[tcp_off + 13];
        const std::uint8_t tcp_hdr_len   =
            static_cast<std::uint8_t>((data_off_byte >> 4) & 0x0F) * 4U;

        if (tcp_hdr_len < 20U || packet_len < tcp_off + tcp_hdr_len)
        {
            return;
        }

        const bool is_syn = (tcp_flags & TH_SYN)  != 0;
        const bool is_ack = (tcp_flags & TH_ACK)  != 0;
        const bool is_rst = (tcp_flags & TH_RST)  != 0;
        const bool is_fin = (tcp_flags & TH_FIN)  != 0;
        const bool is_psh = (tcp_flags & TH_PUSH) != 0;

        std::string host = resolve_host_for_ip(pick_remote_ip());

        // --- SYN scan check runs FIRST (LOGIC FIX) ---
        if (is_syn && !is_ack && !is_rst && !is_fin && !is_psh)
        {
            const std::string key = src_ip + "->" + dst_ip;
            auto&             rec = scan_tracker[key];

            const auto now = Clock::now();

            if (rec.syns == 0)
            {
                rec.syns       = 1;
                rec.first_seen = now;
            }
            else
            {
                const auto elapsed_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - rec.first_seen)
                        .count();

                if (elapsed_ms <= 5000)
                {
                    ++rec.syns;
                }
                else
                {
                    rec.syns       = 1;
                    rec.first_seen = now;
                }
            }

            constexpr int SYN_THRESHOLD = 10;
            if (rec.syns > SYN_THRESHOLD)
            {
                emit_alert_json(
                    "TCP",
                    "critical",
                    "TCP SYN flood/scan detected from " + src_ip +
                    " to " + dst_ip + " (" + std::to_string(rec.syns) + " probes)",
                    host);
                rec.syns = 0;
            }
            return;
        }

        // --- Whitelist check runs AFTER SYN check. ---
        if (SAFE_SERVER_PORTS.count(dst_port) != 0U)
        {
            return;
        }

        // Explicit important ports
        if (dst_port == 22)
        {
            emit_alert_json(
                "TCP",
                "high",
                "Potential SSH connection detected to port 22",
                host);
            return;
        }

        if (dst_port == 3389)
        {
            emit_alert_json(
                "TCP",
                "high",
                "Potential RDP connection detected to port 3389",
                host);
            return;
        }

        if (is_rst)
        {
            emit_alert_json(
                "TCP",
                "medium",
                "RST observed on port " + std::to_string(dst_port) +
                " from " + src_ip,
                host);
            return;
        }
    }
}