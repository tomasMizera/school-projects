#pragma once
#include <string>
#include <pcap.h>
#include "Packet_general.h"

using namespace std;

class IEEE_llc : public Packet_general
{
public:
	IEEE_llc::IEEE_llc(string dMAC, string sMAC, string ethType, const u_char* data, int ethId, int media_len, int header_len, json jFile);
	~IEEE_llc();
};

