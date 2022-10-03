#include <iostream>
#include <time.h>
#include <random>
#include "pt_tree.h"
#include "read.h"

using namespace std;

double get_nano_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000000000 + b->tv_nsec - a->tv_nsec;
}
double get_milli_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000 + (double)(b->tv_nsec - a->tv_nsec) / 1000000.0;
}

int main() {

	vector<Rule> rules;
	vector<Packet> packets;
	vector<int> fields{ 4,0,1 };
	vector<int> check_list;
	struct timespec t1, t2;

	/*char* rule_file = "/data/hq/ACL_data/acl1_256k.txt";
	char* packet_file = "/data/hq/ACL_data/acl1_256k_trace-1.txt";*/
	char* rule_file = "/home/lzhy/ACL_dataset/acl1_256k.txt";
	char* packet_file = "/home/lzhy/ACL_dataset/acl1_256k_trace-1.txt";

	if (!read_rules(rule_file, rules)) return -1;
	if (!read_packets(packet_file, packets, check_list)) return -1;
	set_maskHash();

	PTtree tree(fields, 1, 2);

	//double insert_cycle = 0;
	clock_gettime(CLOCK_REALTIME, &t1);
	for (auto&& r : rules) {
		tree.insert(r);
	}
	clock_gettime(CLOCK_REALTIME, &t2);
	double build_time = get_milli_time(&t1, &t2);
	cout << "construct time: " << build_time << "ms" << endl;
	cout << tree.totalNodes << endl;

	for (int i = 0; i < 10; ++i) {
		for (int j = 0; j < 2000; ++j) {
			tree.search(packets[j]);
		}
	}

	cout << "start search...\n";
	int res = 0;
	FILE* res_fp = NULL;
	res_fp = fopen("results.txt", "w");
	double search_time = 0;
	for (int i = 0; i < packets.size(); ++i) {
		clock_gettime(CLOCK_REALTIME, &t1);
		res = tree.search(packets[i]);
		clock_gettime(CLOCK_REALTIME, &t2);
		double _time = get_nano_time(&t1, &t2);
		search_time += _time;

		if (res != check_list[i]) {
			if (res > check_list[i] || !check_correct(rules[res], packets[i])) {
				fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", i, check_list[i], res);
				return -1;
			}
		}
		//int true_result = simple_search(rules, packets[i]);
		//if (res != true_result) {
		//	fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but result %d.\n", i, true_result, res);
		//	//return -1;
		//}
		fprintf(res_fp, "Packet %d \t Result %d \t Time(um) %f\n", i, res, _time / 1000.0);
	}
	fclose(res_fp);
	cout << "avg match time : " << search_time / packets.size() / 1000.0 << endl;

	return 0;
}
