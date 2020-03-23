#pragma once
#include <string>
#include <pcap.h>
#include "Packet_general.h"
#include "json.hpp"

using namespace std;
using json = nlohmann::json;


class EthernetII : public Packet_general
{
public:


	EthernetII(string dMAC, string sMAC, string ethType, const u_char* data, int ethId, int media_len, int header_len, json j_File);
	void EthernetII::parse_IPv4();
	void EthernetII::parse_ICMP();
	void EthernetII::parse_TCP();
	void EthernetII::parse_UDP();
	void EthernetII::parse_ARP(const u_char* data);
	~EthernetII();
};

