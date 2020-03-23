#pragma once
#include <string>
#include <pcap.h>
#include "json.hpp"

using namespace std;
using json = nlohmann::json;


class Packet_general
{
public:
	string source_mac;
	string dest_mac;
	string type;
	string packet_type;
	json jFile;
	int e_data[500];
	int length_pcap;
	int length_media;
	int id;
	int offset;
	int protocol;
	int final_port;
	string src_ip;
	string dest_ip;
	string dest_port;
	string src_port;
	string port_name;
	string ether_type;
	string protocol_name;
	string icmp_message;

	//pre ARP
	string src_hw_addr;
	string dest_hw_addr;
public:
	Packet_general();
	~Packet_general();
};

