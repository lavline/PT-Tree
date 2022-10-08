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

#include "gen.h"

void gen_trace(std::vector<Packet>& packets, std::vector<int>& check_list, std::vector<Rule>& rules, unsigned int size)
{
    std::random_device seed;
    std::mt19937 rd(seed());
    std::uniform_int_distribution<> dis(0, rules.size() - 1);

    unsigned int protocol[] = { 1,2,3,4,5,6,7,8,17,47,50,51,88,89 };

    unsigned int sip, dip, index;
    unsigned short sport, dport;
    unsigned int smask, dmask;
    for (unsigned int i = 0; i < size; i++) {
        Packet p;
        index = dis(rd);
        memcpy(&sip, rules[index].source_ip, sizeof(int));
        memcpy(&dip, rules[index].destination_ip, sizeof(int));
        smask = rules[index].source_mask; dmask = rules[index].destination_mask;
        if (smask == 0)sip = rd();
        else if (smask < 32) {
            int mbit = 32 - smask;
            unsigned int temp = sip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == sip >> mbit)sip = temp;
            else fprintf(stderr, "Error - gen sip error.\n");
        }
        memcpy(p.source_ip, &sip, sizeof(int));
        if (dmask == 0)dip = rd();
        else if (dmask < 32) {
            int mbit = 32 - dmask;
            unsigned int temp = dip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == dip >> mbit)dip = temp;
            else fprintf(stderr, "Error - gen dip error.\n");
        }
        memcpy(p.destination_ip, &dip, sizeof(int));
        int Pwidth = rules[index].source_port[1] - rules[index].source_port[0];
        if (Pwidth == 0)
            sport = rules[index].source_port[0];
        else {
            sport = rd() % Pwidth + rules[index].source_port[0];
            if (sport < rules[index].source_port[0] || sport > rules[index].source_port[1])
                fprintf(stderr, "Error - gen sport error.\n");
        }
        p.source_port = sport;
        Pwidth = rules[index].destination_port[1] - rules[index].destination_port[0];
        if (Pwidth == 0)
            dport = rules[index].destination_port[0];
        else {
            dport = rd() % Pwidth + rules[index].destination_port[0];
            if (dport < rules[index].destination_port[0] || dport > rules[index].destination_port[1])
                fprintf(stderr, "Error - gen dport error.\n");
        }
        p.destination_port = dport;
        if (rules[index].protocol[0] == 0)
            p.protocol = protocol[rd() % (sizeof(protocol) / 4)];
        else
            p.protocol = rules[index].protocol[1];

        check_list.emplace_back(index);
        packets.emplace_back(p);
    }
}

void gen_trace(std::vector<Packet>& packets, std::vector<Rule>& rules, unsigned int size)
{
    std::random_device seed;
    std::mt19937 rd(seed());
    std::uniform_int_distribution<> dis(0, rules.size() - 1);

    unsigned int protocol[] = { 1,2,3,4,5,6,7,8,17,47,50,51,88,89 };

    unsigned int sip, dip, index;
    unsigned short sport, dport;
    unsigned int smask, dmask;
    for (unsigned int i = 0; i < size; i++) {
        Packet p;
        index = dis(rd);
        memcpy(&sip, rules[index].source_ip, sizeof(int));
        memcpy(&dip, rules[index].destination_ip, sizeof(int));
        smask = rules[index].source_mask; dmask = rules[index].destination_mask;
        if (smask == 0)sip = rd();
        else if (smask < 32) {
            int mbit = 32 - smask;
            unsigned int temp = sip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == sip >> mbit)sip = temp;
            else fprintf(stderr, "Error - gen sip error.\n");
        }
        memcpy(p.source_ip, &sip, sizeof(int));
        if (dmask == 0)dip = rd();
        else if (dmask < 32) {
            int mbit = 32 - dmask;
            unsigned int temp = dip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == dip >> mbit)dip = temp;
            else fprintf(stderr, "Error - gen dip error.\n");
        }
        memcpy(p.destination_ip, &dip, sizeof(int));
        int Pwidth = rules[index].source_port[1] - rules[index].source_port[0];
        if (Pwidth == 0)
            sport = rules[index].source_port[0];
        else {
            sport = rd() % Pwidth + rules[index].source_port[0];
            if (sport < rules[index].source_port[0] || sport > rules[index].source_port[1])
                fprintf(stderr, "Error - gen sport error.\n");
        }
        p.source_port = sport;
        Pwidth = rules[index].destination_port[1] - rules[index].destination_port[0];
        if (Pwidth == 0)
            dport = rules[index].destination_port[0];
        else {
            dport = rd() % Pwidth + rules[index].destination_port[0];
            if (dport < rules[index].destination_port[0] || dport > rules[index].destination_port[1])
                fprintf(stderr, "Error - gen dport error.\n");
        }
        p.destination_port = dport;
        if (rules[index].protocol[0] == 0)
            p.protocol = protocol[rd() % (sizeof(protocol) / 4)];
        else
            p.protocol = rules[index].protocol[1];
        packets.emplace_back(p);
    }
}
