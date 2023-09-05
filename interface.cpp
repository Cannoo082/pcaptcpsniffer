#include <pcap/pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <unordered_map>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <xlsxwriter.h>
#include <vector>

#define SIZE_ETHERNET 14
#define NUM_PROPERTIES 12
#define COL_WIDTH 20
#define COLOR_INCREASE 0x535dc9
#define INITIAL_COLOR 0xC95353


struct TCPTuple
{
    TCPTuple(in_addr client_ip, uint16_t client_port, in_addr server_ip, uint16_t server_port)
    {
        this->client_ip = inet_ntoa(client_ip);
        this->client_port = ntohs(client_port);
        this->server_ip = inet_ntoa(server_ip);
        this->server_port = ntohs(server_port);
    }

    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;
    bool operator==(TCPTuple const& other) const;
};

namespace std
{
    template<>
    struct hash<TCPTuple>
    {
        size_t operator()(const TCPTuple& k) const
        {
            // Custom Hash Function to return same hash even if the client and server are swapped
            return (hash<string>()(k.client_ip) ^ hash<string>()(k.server_ip)) ^ (hash<uint16_t>()(k.client_port) ^ hash<uint16_t>()(k.server_port));
        }
    };
}

bool TCPTuple::operator==(const TCPTuple &other) const
{
    if(client_ip == other.client_ip && client_port == other.client_port && server_ip == other.server_ip && server_port == other.server_port ||
        client_ip == other.server_ip && client_port == other.server_port && server_ip == other.client_ip && other.client_port) return true;
    else return false;
}

struct TCPFlow
{
   TCPFlow(uint64_t _bytes_c2s, uint64_t _ts_flow_begin)
    {
        num_packets_c2s = 1;
        num_packets_s2c = 0;
        bytes_s2c = 0;
        bytes_c2s = _bytes_c2s + SIZE_ETHERNET;
        bytes_total = _bytes_c2s + SIZE_ETHERNET;
        packets_total = 1;
        ts_flow_begin = _ts_flow_begin;
        ts_flow_last = _ts_flow_begin;
    }
    TCPFlow(const TCPFlow&) = default;
    TCPFlow() = default;

    uint64_t num_packets_c2s;
    uint64_t num_packets_s2c;
    uint64_t bytes_s2c;
    uint64_t bytes_c2s;
    uint64_t bytes_total;
    uint64_t packets_total;
    uint64_t ts_flow_begin;
    uint64_t ts_flow_last;
};

class FlowProcessor
{
public:
    void print();
    std::unordered_map<TCPTuple, TCPFlow>& get_flows() { return m_flows; };
private:
    std::unordered_map<TCPTuple, TCPFlow> m_flows;
    static uint32_t handleColor(uint32_t color);
};

uint32_t FlowProcessor::handleColor(uint32_t colorVal)
{
    colorVal += COLOR_INCREASE;

    auto r = (colorVal >> 16) & 0xFF;
    auto g = (colorVal >> 8) & 0xFF;
    auto b = (colorVal >> 0) & 0xFF;
    auto luma = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    //if color is too dark select another color
    if (luma < 60) colorVal = handleColor(colorVal);
    return colorVal;
}

void FlowProcessor::print()
{
    std::string names[] = {"Source IP",
                           "Source Port",
                           "Destination IP",
                           "Destination Port",
                           "# of Packets C->S",
                           "# of Packets S->C",
                           "# of Bytes C->S",
                           "# of Bytes S->C",
                           "# of Total Bytes",
                           "# of Total Packets",
                           "Timestamp begin",
                           "Timestamp end"};

    lxw_workbook *workbook  = workbook_new("demo.xlsx");
    lxw_worksheet *worksheet = workbook_add_worksheet(workbook, "Conversations");

    uint64_t currRow {};

    //print headers
    if (NUM_PROPERTIES > end(names)-begin(names)) throw std::runtime_error("Number of properties is greater than number of names"); // Error checking if NUM_PROPERTIES is changed
    for (int i {}; i < NUM_PROPERTIES; i++)
    {
        worksheet_write_string(worksheet, currRow, i, names[i].c_str(), nullptr);
    }

    currRow++; // skip header row

    // set width of columns
    worksheet_set_column(worksheet, 0, NUM_PROPERTIES, COL_WIDTH, nullptr);

    std::cout << "Printing flows..." << std::endl;

    uint32_t colorVal = INITIAL_COLOR;

    for (auto& [TCPTuple, TCPFlow] : m_flows)
    {
        const std::string values[] = {TCPTuple.client_ip,
                                std::to_string(TCPTuple.client_port),
                                TCPTuple.server_ip,
                                std::to_string(TCPTuple.server_port),
                                std::to_string(TCPFlow.num_packets_c2s),
                                std::to_string(TCPFlow.num_packets_s2c),
                                std::to_string(TCPFlow.bytes_c2s),
                                std::to_string(TCPFlow.bytes_s2c),
                                std::to_string(TCPFlow.bytes_total),
                                std::to_string(TCPFlow.packets_total),
                                std::to_string(TCPFlow.ts_flow_begin),
                                std::to_string(TCPFlow.ts_flow_last)};

        auto format = workbook_add_format(workbook);
        format_set_pattern(format, LXW_PATTERN_SOLID);
        format_set_bg_color(format, colorVal);

        colorVal = handleColor(colorVal);
        for (int i {}; i < NUM_PROPERTIES; i++)
        {
            worksheet_write_string(worksheet, currRow, i, values[i].c_str(), format);
        }
        currRow++;
    }
    workbook_close(workbook);
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr header{};
    FlowProcessor fp;

    // Open offline file for reading
    pcap_t* pcap_file = pcap_open_offline("../try.pcap", errbuf);
    if (pcap_file == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return EXIT_FAILURE;
    }

    auto& map = fp.get_flows();

    while (true)
    {
        packet = pcap_next(pcap_file, &header);
        if (packet == nullptr)
        {
            fp.print();
            break;
        }

        auto* ether_hdr = (struct ether_header *) (packet); // ETHER HEADER
        if (ntohs(ether_hdr->ether_type) != ETHERTYPE_IP) continue; // IF NOT IPV4, CONTINUE
        auto* ip_hdr = (struct ip *) (packet + SIZE_ETHERNET); // IP HEADER
        if(ip_hdr->ip_p != IPPROTO_TCP) continue; // IF NOT TCP, CONTINUE
        auto size_ip = ip_hdr->ip_hl * 4;
        auto* tcp_hdr = (struct tcphdr *) (packet + SIZE_ETHERNET + size_ip); // TCP HEADER

        TCPTuple tuple = TCPTuple{ip_hdr->ip_src, tcp_hdr->th_sport, ip_hdr->ip_dst, tcp_hdr->th_dport};

        std::unordered_map<TCPTuple,TCPFlow>::const_iterator map_iterator = map.find(tuple);
        if (map_iterator == map.end())
        {
            // request not in map
            map[tuple] = TCPFlow{static_cast<uint64_t>(ntohs(ip_hdr->ip_len)),
                                 static_cast<uint64_t>(header.ts.tv_sec)};
        }
        else
        {
            //request already in map
            if(tuple.client_ip == map_iterator->first.client_ip)
            {
                map[tuple].num_packets_c2s++;
                map[tuple].bytes_c2s += ntohs(ip_hdr->ip_len) + SIZE_ETHERNET;
                map[tuple].bytes_total += ntohs(ip_hdr->ip_len) + SIZE_ETHERNET;
                map[tuple].packets_total++;
                map[tuple].ts_flow_last = header.ts.tv_sec;
            }
            else
            {
                map[tuple].num_packets_s2c++;
                map[tuple].bytes_s2c += ntohs(ip_hdr->ip_len) + SIZE_ETHERNET;
                map[tuple].bytes_total += ntohs(ip_hdr->ip_len) + SIZE_ETHERNET;
                map[tuple].packets_total++;
                map[tuple].ts_flow_last = header.ts.tv_sec;
            }
        }
    }
    std::cout << "Done" << std::endl;
    pcap_close(pcap_file);
    return EXIT_SUCCESS;
}