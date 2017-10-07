#include "EthernetII.h"
#include <iostream>
#include <pcap.h>
#include <string>
#include "json.hpp"

using namespace std;
using json = nlohmann::json;

EthernetII::EthernetII(string dMAC, string sMAC, string ethType, const u_char* data, int ethId, int media_len, int header_len, json j_file)
{
	source_mac = sMAC;
	dest_mac = dMAC;
	id = ethId;
	jFile = j_file;
	type = ethType;
	length_media = media_len;
	length_pcap = header_len;
	for (int a = 0; a < length_pcap; a++) {
		e_data[a] = (int)data[a];
	}
	string to_to = jFile["eth.types"]["Ethernetname"];
	packet_type = to_to;

	if (type == jFile["ipv4"]["value"]) {
		string to_be = jFile["ipv4"]["name"];
		ether_type = to_be;
		parse_IPv4();
	}
	else if (type == jFile["arp"]["value"]) {
		string to_be = jFile["arp"]["name"];
		ether_type = to_be;
		parse_ARP(data);
	}
}

void EthernetII::parse_IPv4() {
	//doplnujuce options
	offset = (((int)(e_data[14]) & 15) - 5) * 4;
	/*if (!(e_data[14] == 0x45)) {
		cout << "Su tu doplnujuce options!\n";
	}*/

	protocol = (int)e_data[23];
	src_ip = to_string((int)e_data[26]) + '.' + to_string((int)e_data[27]) + '.' + to_string((int)e_data[28]) + '.' + to_string((int)e_data[29]);
	dest_ip = to_string((int)e_data[30]) + '.' + to_string((int)e_data[31]) + '.' + to_string((int)e_data[32]) + '.' + to_string((int)e_data[33]);

	if (protocol == jFile["ipv4"]["protocols"]["icmp"]["value"]) {
		string to_be = jFile["ipv4"]["protocols"]["icmp"]["name"];
		protocol_name = to_be;
		parse_ICMP();
	}
	else if (protocol == jFile["ipv4"]["protocols"]["tcp"]["value"]) {
		string to_be = jFile["ipv4"]["protocols"]["tcp"]["name"];
		protocol_name = to_be;
		parse_TCP();
	}
	else if (protocol == jFile["ipv4"]["protocols"]["udp"]["value"]) {
		string to_be = jFile["ipv4"]["protocols"]["udp"]["name"];
		protocol_name = to_be;
		parse_UDP();
	}
	else {
		protocol_name = "Unknown port";
	}
}

void EthernetII::parse_ICMP() {
	icmp_message = to_string((int)e_data[34+offset]);
	int mess_code = stoi(icmp_message);
	for (auto it = jFile["ipv4"]["messages"].begin(); it != jFile["ipv4"]["messages"].end(); ++it)
	{
		if (it.value() == mess_code) {
			icmp_message = it.key();
		}
	}
}

void EthernetII::parse_TCP() {
	//34 + 35 source port
	src_port = to_string((int)e_data[34 + offset]) + to_string((int)e_data[35 + offset]);
	dest_port = to_string((int)e_data[36 + offset]) + to_string((int)e_data[37 + offset]);
	if (src_port < dest_port) {
		port_name = src_port;
	}
	else {
		port_name = dest_port;
	}
	final_port = stoi(port_name);

	for (auto it = jFile["ipv4"]["messages"].begin(); it != jFile["ipv4"]["messages"].end(); ++it)
	{
		if (it.value() == final_port) {
			port_name = it.key();
		}
	}
}

void EthernetII::parse_UDP() {
	src_port = to_string((int)e_data[34 + offset]) + to_string((int)e_data[35 + offset]);
	dest_port = to_string((int)e_data[36 + offset]) + to_string((int)e_data[37 + offset]);
	if (src_port < dest_port) {
		port_name = src_port;
	}
	else {
		port_name = dest_port;
	}
	final_port = stoi(port_name);

	for (auto it = jFile["ipv4"]["messages"].begin(); it != jFile["ipv4"]["messages"].end(); ++it)
	{
		if (it.value() == final_port) {
			port_name = it.key();
		}
	}
}

void EthernetII::parse_ARP(const u_char* data) {
	char buffer[50];
	//starts at e_data[14];
	//TO DO > operation, - 20,21 = port_name
	//SHA - In an ARP request this field is used to indicate the address of the host sending the request
	//SHA - In an ARP reply this field is used to indicate the address of the host that the request was looking for.

	int operation = (int)e_data[20] + (int)e_data[21];
	if (operation == jFile["arp"]["operation-request"]["value"]) {
		string to_be = jFile["arp"]["operation-request"]["name"];
		port_name = to_be;
	}
	else {
		string to_be = jFile["arp"]["operation-reply"]["name"];
		port_name = to_be;
	}
	sprintf(buffer, "%02X %02X %02X %02X %02X %02X", data[22], data[23], data[24], data[25], data[26], data[27]);
	src_hw_addr = buffer;
	src_ip = to_string((int)e_data[28]) + '.' + to_string((int)e_data[29]) + '.' + to_string((int)e_data[30]) + '.' + to_string((int)e_data[31]);
	sprintf(buffer, "%02X %02X %02X %02X %02X %02X", data[32], data[33], data[34], data[35], data[36], data[37]);
	dest_hw_addr = buffer;
	dest_ip = to_string((int)e_data[38]) + '.' + to_string((int)e_data[39]) + '.' + to_string((int)e_data[40]) + '.' + to_string((int)e_data[41]);
}

EthernetII::~EthernetII()
{
}
