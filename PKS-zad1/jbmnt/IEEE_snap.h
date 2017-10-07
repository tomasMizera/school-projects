#pragma once
#include <string>
#include <pcap.h>
#include "Packet_general.h"

using namespace std;

class IEEE_snap : public Packet_general
{
public:
	IEEE_snap(string dMAC, string sMAC, string ethType, const u_char* data, int ethId, int media_len, int header_len, json jFile);
	~IEEE_snap();
};

