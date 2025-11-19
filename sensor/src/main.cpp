// src/main.cpp
#include "packet_sniffer.h"

#include <csignal>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

namespace
{
    volatile sig_atomic_t g_stop_requested = 0;

    void handle_sigint(int)
    {
        g_stop_requested = 1;
        std::cerr << "\nSIGINT received — shutting down...\n";
        // If PacketSniffer exposes a stop() that calls pcap_breakloop(),
        // you could call it here (via some global pointer or other mechanism).
    }

    void print_usage(const char* progname)
    {
        std::cerr << "Usage: " << progname << " [device_number]\n"
                  << "  device_number : 1-based index of the capture device (default: 1)\n"
                  << "  -h, --help    : show this message\n";
    }

} // namespace

int main(int argc, char* argv[])
{
    std::signal(SIGINT, handle_sigint);

    int dev_num = 1;

    if (argc > 1)
    {
        const std::string arg = argv[1];

        if (arg == "-h" || arg == "--help")
        {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }

        try
        {
            std::size_t pos = 0;
            long tmp = std::stol(arg, &pos, 10);

            if (pos != arg.size() || tmp <= 0)
            {
                std::cerr << "Invalid device number: " << arg << '\n';
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }

            dev_num = static_cast<int>(tmp);
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error parsing device number: " << e.what() << '\n';
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cerr << "No device number specified, defaulting to 1.\n";
    }

    try
    {
        PacketSniffer sniffer(dev_num);
        // Assuming PacketSniffer has a public check like is_ready() or is_open()
        // If not, the sniffer.start_sniffing() call will handle the failure (which is fine, but less explicit)
        sniffer.start_sniffing();
    }
    catch (const std::exception& e)
    {
        std::cerr << "An error occurred: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    if (g_stop_requested)
    {
        std::cerr << "Shutdown requested by user.\n";
    }

    return EXIT_SUCCESS;
}
