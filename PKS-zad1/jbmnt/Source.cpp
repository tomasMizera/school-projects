#include <iostream>
#include <fstream>
#include <pcap.h>
#include <string>
#include <stdio.h>
#include <unordered_map>
#include <list>
#include "Packet_general.h"
#include "EthernetII.h"
#include "IEEE_llc.h"
#include "IEEE_raw.h"
#include "IEEE_snap.h"
#include "json.hpp"

// for convenience
using json = nlohmann::json;

#define PCAP_FILE "E:\\GIT\\VSprojects\\JSONcpp\\JSONcpp\\Data\\trace_ip_nad_20_B.pcap"
//trace-21.pcap ma v sebe ARPcko

using namespace std;

void vypis(list<Packet_general> objects, string prot) {

	cout << "\n\tVypis " << prot << " komunikacie\n" << endl;
	int occurence = 0, conto = 0;
	for (auto& it : objects) {
		if (it.port_name == prot) {
			conto++;
		}
	}
	if (conto <= 20) {
		for (auto& it : objects) {
			if (it.port_name == prot) {
				cout << endl << "\nramec c." << it.id << endl;
				cout << "dlzka ramca pcap API - " << it.length_pcap << "B" << endl;
				cout << "dlzka ramca po mediu - " << it.length_media << "B" << endl;
				cout << it.packet_type << endl;
				cout << "Zdrojova MAC adresa: " << it.source_mac << endl;
				cout << "Cielova MAC adresa: " << it.dest_mac << endl;;
				cout << it.ether_type << endl;
				cout << "Zdrojova IP adresa: " << it.src_ip << endl;
				cout << "Cielova IP adresa: " << it.dest_ip << endl;
				cout << it.protocol_name << endl;
				cout << "Zdrojovy port: " << stoi(it.src_port) << endl;
				cout << "Cielovy port: " << stoi(it.dest_port) << endl;
				cout << it.port_name;
				for (int i = 0; i < it.length_pcap; i++) {
					if (!(i % 16))
						cout << endl;
					if (!((i - 8) % 16))
						cout << "  ";
					printf("%02X ", it.e_data[i]);
				}
				cout << endl;
			}
		}
	}
	else {
		for (auto& it : objects) {
			if (it.port_name == prot) {
				occurence++;
				if (occurence <= 10 || occurence >= (conto - 10)) {
					cout << endl << "\nramec c." << it.id << endl;
					cout << "dlzka ramca pcap API - " << it.length_pcap << "B" << endl;
					cout << "dlzka ramca po mediu - " << it.length_media << "B" << endl;
					cout << it.packet_type << endl;
					cout << "Zdrojova MAC adresa: " << it.source_mac << endl;
					cout << "Cielova MAC adresa: " << it.dest_mac << endl;;
					cout << it.ether_type << endl;
					cout << "Zdrojova IP adresa: " << it.src_ip << endl;
					cout << "Cielova IP adresa: " << it.dest_ip << endl;
					cout << it.protocol_name << endl;
					cout << "Zdrojovy port: " << stoi(it.src_port) << endl;
					cout << "Cielovy port: " << stoi(it.dest_port) << endl;
					cout << it.port_name;
					for (int i = 0; i < it.length_pcap; i++) {
						if (!(i % 16))
							cout << endl;
						if (!((i - 8) % 16))
							cout << "  ";
						printf("%02X ", it.e_data[i]);
					}
					cout << endl;
				}
			}
		}
	}
}

void vypisICMP(list<Packet_general> objects) {
	cout << "\n\tVypis ICMP komunikacie\n" << endl;
	int occurence = 0, conto = 0;
	for (auto& it : objects) {
		if (it.protocol_name == "ICMP") {
			conto++;
		}
	}
	if (conto <= 20) {
		for (auto& it : objects) {
			if (it.protocol_name == "ICMP") {
				cout << endl << "ramec c." << it.id << endl;
				cout << "dlzka ramca pcap API - " << it.length_pcap << "B" << endl;
				cout << "dlzka ramca po mediu - " << it.length_media << "B" << endl;
				cout << it.packet_type << endl;
				cout << "Zdrojova MAC adresa: " << it.source_mac << endl;
				cout << "Cielova MAC adresa: " << it.dest_mac << endl;;
				cout << it.ether_type << endl;
				cout << "Zdrojova IP adresa: " << it.src_ip << endl;
				cout << "Cielova IP adresa: " << it.dest_ip << endl;
				cout << it.protocol_name << endl;
				cout << "Type: " << it.icmp_message << endl;
				for (int i = 0; i < it.length_pcap; i++) {
					if (!(i % 16))
						cout << endl;
					if (!((i - 8) % 16))
						cout << "  ";
					printf("%02X ", it.e_data[i]);
				}
				cout << endl;
			}
		}
	}
	else {
		for (auto& it : objects) {
			if (it.protocol_name == "ICMP") {
				occurence++;
				if (occurence <= 10 || occurence >= (conto - 10)) {
					cout << endl << "ramec c." << it.id << endl;
					cout << "dlzka ramca pcap API - " << it.length_pcap << "B" << endl;
					cout << "dlzka ramca po mediu - " << it.length_media << "B" << endl;
					cout << it.packet_type << endl;
					cout << "Zdrojova MAC adresa: " << it.source_mac << endl;
					cout << "Cielova MAC adresa: " << it.dest_mac << endl;;
					cout << it.ether_type << endl;
					cout << "Zdrojova IP adresa: " << it.src_ip << endl;
					cout << "Cielova IP adresa: " << it.dest_ip << endl;
					cout << it.protocol_name << endl;
					cout << "Type: " << it.icmp_message << endl;
					for (int i = 0; i < it.length_pcap; i++) {
						if (!(i % 16))
							cout << endl;
						if (!((i - 8) % 16))
							cout << "  ";
						printf("%02X ", it.e_data[i]);
					}
					cout << endl;
				}
			}
		}
	}
}

int main() {
	//nacitanie externeho suboru - JSON
	std::fstream f_json("eth_frame.json");
	json jFile;
	try {
		jFile = json::parse(f_json);
	}
	catch (json::parse_error &e)
	{
		std::cerr << e.what() << std::endl;
	}

	pcap_t *file;
	int number_of_packets = 0, len_media = 0, max_ip_bytes = 0;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	bool prepinac = TRUE;
	const u_char *data;
	string max_ip;
	char type_buf[50], dest_mac[50], src_mac[50];
	list<Packet_general> objects;
	unordered_map<string, int> hashMap;

	//nacitaj pcap subor
	file = pcap_open_offline(PCAP_FILE, errbuff);
	if (file == NULL) {
		std::cout << "Subor sa nenacital, chyba: " << errbuff << std::endl;
		return 0;
	}

	//loop po kazdom jednom ramci
	while (pcap_next_ex(file, &header, &data) >= 0) {
		if (header->len < 60) {
			len_media = 64;
		}
		else {
			len_media = header->len + 4;
		}
		sprintf(dest_mac, "%02X %02X %02X %02X %02X %02X", data[0], data[1], data[2], data[3], data[4], data[5]);
		sprintf(src_mac, "%02X %02X %02X %02X %02X %02X", data[6], data[7], data[8], data[9], data[10], data[11]);
		sprintf(type_buf, "%02X%02X", data[12], data[13]);
		number_of_packets++;
		if (type_buf >= jFile["eth.types"]["value-to-compare"]) {
			EthernetII paket(dest_mac, src_mac, type_buf, data, number_of_packets, len_media, header->len, jFile);
			objects.push_back(paket);

			//pridavanie IP do hashmapy
			if (hashMap.count(paket.src_ip) > 0) {
				//ak je dana IP uz zaregistrovana v Hashmape, hodnotu iba zvys
				hashMap[paket.src_ip] += paket.length_pcap;
			}
			else {
				//ak nie je IP este v hashmape, pridaj ju
				hashMap[paket.src_ip] = paket.length_pcap;
			}
		}
		else if (data[14] == 0xFF || data[14] == 0xff) {
			IEEE_raw paket(dest_mac, src_mac, jFile["eth.types"]["IEEE-raw"], data, number_of_packets, len_media, header->len, jFile);
			objects.push_back(paket);
		}
		else if (data[14] == 0xAA || data[14] == 0xaa) {
			IEEE_snap paket(dest_mac, src_mac, jFile["eth.types"]["IEEE-snap"], data, number_of_packets, len_media, header->len, jFile);
			objects.push_back(paket);
		}
		else {
			IEEE_llc paket(dest_mac, src_mac, jFile["eth.types"]["IEEE-llc"], data, number_of_packets, len_media, header->len, jFile);
			objects.push_back(paket);
		}
	}
	pcap_close(file);

	//Vypis!!
	for (auto& it : objects) {
		cout << endl << "ramec c." << it.id << endl;
		cout << "dlzka ramca pcap API - " << it.length_pcap << "B" << endl;
		cout << "dlzka ramca po mediu - " << it.length_media << "B" << endl;
		cout << it.packet_type << endl;
		cout << "Zdrojova MAC adresa: " << it.source_mac << endl;
		cout << "Cielova MAC adresa: " << it.dest_mac;
		for (int i = 0; i < it.length_pcap; i++) {
			if (!(i % 16))
				cout << endl;
			if (!((i - 8) % 16))
				cout << "  ";
			printf("%02X ", it.e_data[i]);
		}
		cout << "\n\n";
	}

	//IPcky
	cout << "IP adresy vysielajucich uzlov: " << endl;
	for (auto const& x : hashMap) 
	{
		if (x.second > max_ip_bytes) {
			max_ip_bytes = x.second;
			max_ip = x.first;
			std::cout << x.first << std::endl;
		}
	}
	std::cout << "\n\nAdresa uzla s najvacsim poctom odvysielanych bajtov: \n" << max_ip << "\t" << max_ip_bytes << " bajtov" << std::endl;
	vypis(objects, "http");
	vypis(objects, "https");
	vypis(objects, "telnet");
	vypis(objects, "ssh");
	vypis(objects, "ftp-control");
	vypis(objects, "ftp-data");
	vypis(objects, "tftp");
	vypisICMP(objects);

	//ARP - dvojice
	int counter = 0;
	cout << "\tARP komunikacie\n";
	for (auto const& x : objects)
	{
		if (x.ether_type == "ARP" && x.port_name == "reply") {
			for (auto const& y : objects) {
				if (y.ether_type == "ARP" && y.port_name == "request" && y.src_ip == x.dest_ip && y.dest_ip == x.src_ip) {
					counter++;
					cout << "\nKomunikacia c." << counter << "\n\nARP-" << y.port_name << ", IP: " << y.dest_ip << ", MAC: " << y.dest_hw_addr;
					cout <<"\nZdrojova IP: " << y.src_ip << ", Cielova IP: " << y.dest_ip << endl;
					cout << "ramec c." << y.id << endl;
					cout << "dlzka ramca pcap API - " << y.length_pcap << "B" << endl;
					cout << "dlzka ramca po mediu - " << y.length_media << "B" << endl;
					cout << y.packet_type << endl;
					cout << "Zdrojova MAC adresa: " << y.source_mac << endl;
					cout << "Cielova MAC adresa: " << y.dest_mac;
					for (int i = 0; i < y.length_pcap; i++) {
						if (!(i % 16))
							cout << endl;
						if (!((i - 8) % 16))
							cout << "  ";
						printf("%02X ", y.e_data[i]);
					}
					cout << endl << endl;
					cout << "\nARP-" << x.port_name << ", IP: " << x.src_ip << ", MAC: " << x.src_hw_addr;
					cout << "\nZdrojova IP: " << x.src_ip << ", Cielova IP: " << x.dest_ip << endl;
					cout << "ramec c." << x.id << endl;
					cout << "dlzka ramca pcap API - " << x.length_pcap << "B" << endl;
					cout << "dlzka ramca po mediu - " << x.length_media << "B" << endl;
					cout << x.packet_type << endl;
					cout << "Zdrojova MAC adresa: " << x.source_mac << endl;
					cout << "Cielova MAC adresa: " << x.dest_mac;
					for (int i = 0; i < x.length_pcap; i++) {
						if (!(i % 16))
							cout << endl;
						if (!((i - 8) % 16))
							cout << "  ";
						printf("%02X ", x.e_data[i]);
					}
					cout << endl;
				}
			}
		}
	}
	return 0;
}