/*
 *	MIT License
 *
 *	Copyright(c) 2022 ShangHai Jiao Tong Univiersity CIT Laboratory.
 *
 *	Permission is hereby granted, free of charge, to any person obtaining a copy
 *	of this softwareand associated documentation files(the "Software"), to deal
 *	in the Software without restriction, including without limitation the rights
 *	to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
 *	copies of the Software, and to permit persons to whom the Software is
 *	furnished to do so, subject to the following conditions :
 *
 *	The above copyright noticeand this permission notice shall be included in all
 *	copies or substantial portions of the Software.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
 *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *	SOFTWARE.
 */

#ifndef __DATA_STRUCTURE_H_
#define __DATA_STRUCTURE_H_
#include <stdio.h>
#include <vector>
#include <cstring>
#include <math.h>
#include <algorithm>
#include <stdint.h>
#include <time.h>

typedef struct Rule {
	int pri;  //priority
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