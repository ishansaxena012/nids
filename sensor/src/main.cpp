// src/main.cpp
#include "packet_sniffer.h"
#include <iostream>
#include <cstdlib>
#include <csignal>
#include <string>

using namespace std;

static volatile sig_atomic_t stop_requested = 0;

void handle_sigint(int) {
    stop_requested = 1;
    cerr << "\nSIGINT received — shutting down...\n";
    // Note: to break out of pcap_loop gracefully you would call pcap_breakloop(handle)
    // from another thread or expose a stop() method on PacketSniffer that calls it.
}

void print_usage(const char* progname) {
    cerr << "Usage: " << progname << " [device_number]\n"
         << "  device_number : 1-based index of the capture device (default: 1)\n"
         << "  -h, --help    : show this message\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handle_sigint);

    int dev_num = 1;

    if (argc > 1) {
        string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }

        try {
            size_t pos = 0;
            long tmp = stol(arg, &pos, 10);
            if (pos != arg.size() || tmp <= 0) {
                cerr << "Invalid device number: " << arg << "\n";
                print_usage(argv[0]);
                return 1;
            }
            dev_num = static_cast<int>(tmp);
        } catch (const exception& e) {
            cerr << "Error parsing device number: " << e.what() << "\n";
            print_usage(argv[0]);
            return 1;
        }
    } else {
        cerr << "No device number specified, defaulting to 1.\n";
    }

    try {
        PacketSniffer sniffer(dev_num);
        // start_sniffing blocks and runs pcap_loop internally
        sniffer.start_sniffing();
    } catch (const exception& e) {
        cerr << "An error occurred: " << e.what() << endl;
        return 1;
    }

    if (stop_requested) {
        cerr << "Shutdown requested by user.\n";
    }

    return 0;
}
