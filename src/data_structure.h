#ifndef __DATA_STRUCTURE_H_
#define __DATA_STRUCTURE_H_
#include <stdio.h>
#include <vector>
#include <cstring>
#include <math.h>
#include <algorithm>
#include <stdint.h>

typedef struct Rule {
	int PRI;  //priority
	unsigned char protocol[2];  // [0] : mask [1] : protocol
	unsigned char source_mask;
	unsigned char destination_mask;
	unsigned char source_ip[4];
	unsigned char destination_ip[4];
	unsigned short source_port[2];
	unsigned short destination_port[2];
}Rule;

typedef struct Packet
{
	unsigned int protocol;
	unsigned char source_ip[4];
	unsigned char destination_ip[4];
	unsigned short source_port;
	unsigned short destination_port;
}Packet;

#endif //__DATA_STRUCTURE_H_