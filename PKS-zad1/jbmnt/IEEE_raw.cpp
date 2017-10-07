#include "IEEE_raw.h"
#include <iostream>
#include <pcap.h>
#include <string>

using namespace std;


IEEE_raw::IEEE_raw(string dMAC, string sMAC, string ethType, const u_char* data, int ethId, int media_len, int header_len, json jFile)
{
	source_mac = sMAC;
	dest_mac = dMAC;
	type = ethType;
	id = ethId;
	string tpp = jFile["eth.types"]["IEEE-raw"];
	packet_type = tpp;
	length_media = media_len;
	length_pcap = header_len;
	for (int a = 0; a < length_pcap; a++) {
		e_data[a] = (int)data[a];
	}
}


IEEE_raw::~IEEE_raw()
{
}
