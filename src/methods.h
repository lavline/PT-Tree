#ifndef _METHODS_H
#define _MRTHODS_H
#include "pt_tree.h"
#include <thread>
#include <random>
#include <chrono>
#include "gen.h"


void single_thread(vector<uint8_t> set_field, int set_port, bool enable_log, int log_level, bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list);
void multi_thread(vector<uint8_t> set_field, int set_port, bool enable_log, int log_level, bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list);

void single_thread_cycle(vector<uint8_t> set_field, int set_port, bool enable_log, int log_level, bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list);
void multi_thread_cycle(vector<uint8_t> set_field, int set_port, bool enable_log, int log_level, bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list);

#endif // _METHODS_H

