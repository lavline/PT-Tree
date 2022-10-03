#ifndef __DATA_STRUCTURE_H_
#define __DATA_STRUCTURE_H_
#include <stdio.h>
#include <vector>
#include <cstring>
#include <math.h>
#include <algorithm>
#include <stdint.h>

typedef struct Rule {
	uint32_t pri;  //priority
	uint8_t protocol[2];  // [0] : mask [1] : protocol
	uint8_t Smask;
	uint8_t Dmask;
	uint8_t Sip[4];
	uint8_t Dip[4];
	uint16_t Sport[2];
	uint16_t Dport[2];
}Rule;

typedef struct Packet
{
	uint32_t protocol;
	uint8_t Sip[4];
	uint8_t Dip[4];
	uint16_t Sport;
	uint16_t Dport;
}Packet;

#endif //__DATA_STRUCTURE_H_