#ifndef __READ_H_
#define __READ_H_
#include "data_structure.h"

using namespace std;

int read_rules(const char* file_name, vector<Rule>& list);
int read_packets(const char* file_name, vector<Packet>& list, vector<int>& check_list);

int read_contest_rules(const char* file_name, vector<Rule>& list);
int read_contest_packets(const char* file_name, vector<Packet>& list, vector<int>& check_list);

#endif // !__READ_H_
