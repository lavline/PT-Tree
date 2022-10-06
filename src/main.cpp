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

	string ipFieldName[8] = { "sip1", "sip2", "sip3", "sip4", "dip1", "dip2", "dip3", "dip4" };
	vector<Rule> rules;
	vector<Packet> packets;
	vector<int> check_list;
	struct timespec t1, t2;

	/*char* rule_file = "/data/hq/ACL_data/acl1_256k.txt";
	char* packet_file = "/data/hq/ACL_data/acl1_256k_trace-1.txt";*/
	char* rule_file = "/home/lzhy/ACL_dataset/fw4_256k.txt";
	char* packet_file = "/home/lzhy/ACL_dataset/fw4_256k_trace-1.txt";

	if (!read_rules(rule_file, rules)) return -1;
	if (!read_packets(packet_file, packets, check_list)) return -1;
	setmaskHash();

	// search config
	cout << "\nsearch config...\n";
	vector<vector<uint8_t>> fields;
	vector<uint8_t> tmp_fields;
	tmp_fields.resize(3);
	FILE* fp_l3 = fopen("./L3.txt", "r");
	if (fp_l3 == NULL) {
		fprintf(stderr, "error - can not open L3.txt\n");
		return 0;
	}
	while (fscanf(fp_l3, "%u %u %u \n", &tmp_fields[0], &tmp_fields[1], &tmp_fields[2]) != EOF) {
		fields.emplace_back(tmp_fields);
	}
	fclose(fp_l3);
	tmp_fields.resize(4);
	FILE* fp_l4 = fopen("./L4.txt", "r");
	if (fp_l4 == NULL) {
		fprintf(stderr, "error - can not open L4.txt\n");
		return 0;
	}
	while (fscanf(fp_l4, "%u %u %u %u \n", &tmp_fields[0], &tmp_fields[1], &tmp_fields[2], &tmp_fields[3]) != EOF) {
		fields.emplace_back(tmp_fields);
	}
	fclose(fp_l4);
	//cout << fields.size() << endl;
	double min_time = 100e9;
	double cur_time = 0;
	double best_time = 0;
	int best_config1, best_config2 = 1;
	struct timespec st1, st2;
	clock_gettime(CLOCK_REALTIME, &st1);
	for (int i = 0; i < fields.size(); ++i) {
		PTtree tree(fields[i], 1);
		for (auto&& r : rules) {
			tree.insert(r);
		}
		clock_gettime(CLOCK_REALTIME, &t1);
		for (int i = 0; i < 1000; ++i) {
			tree.search(packets[i]);
		}
		clock_gettime(CLOCK_REALTIME, &t2);
		cur_time = get_nano_time(&t1, &t2);
		//cout << cur_time / 1000000.0 << endl;
		if (cur_time < min_time) {
			min_time = cur_time;
			best_config1 = i;
			best_time = cur_time;
		}
	}
	{
		//out << best_time / 1000000.0 << endl;
		PTtree tree(fields[best_config1], 0);
		for (auto&& r : rules) {
			tree.insert(r);
		}
		clock_gettime(CLOCK_REALTIME, &t1);
		for (int i = 0; i < 1000; ++i) {
			tree.search(packets[i]);
		}
		clock_gettime(CLOCK_REALTIME, &t2);
		cur_time = get_nano_time(&t1, &t2);
		//cout << cur_time / 1000000.0 << endl;
		if (cur_time < min_time) {
			min_time = cur_time;
			best_config2 = 0;
			best_time = cur_time;
		}
	}
	clock_gettime(CLOCK_REALTIME, &st2);
	cout << "\tsearch config time: " << get_milli_time(&st1, &st2) / 1000.0 << "s\n";
	cout << "\tbest config: ";
	for (unsigned int _f : fields[best_config1])cout << ipFieldName[_f] << "->";
	cout << "\b\b  " << best_config2;
	cout << "\n\tbest time: " << best_time / 1000000.0 << "um\n";
	PTtree tree(fields[best_config1], best_config2);

	// insert
	cout << "\nstart build...\n";
	clock_gettime(CLOCK_REALTIME, &t1);
	for (auto&& r : rules) {
		tree.insert(r);
	}
	clock_gettime(CLOCK_REALTIME, &t2);
	double build_time = get_milli_time(&t1, &t2);
	cout << "\tconstruct time: " << build_time << "ms\n";
	//cout << tree.totalNodes << endl;

	cout << "\tmemory footprint: " << (double)tree.mem() / 1024.0 / 1024.0 << "MB\n";

	for (int i = 0; i < 10; ++i) {
		for (int j = 0; j < 1000; ++j) {
			tree.search(packets[j]);
		}
	}

	cout << "\nstart search...\n";
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
	cout << "\tAverage search time : " << search_time / packets.size() / 1000.0 << "um\n";

	// update
	int update_num = 5000;
	cout << "\nstart update...\n";
	clock_gettime(CLOCK_REALTIME, &t1);
	bool _u = tree.update(rules, update_num);
	clock_gettime(CLOCK_REALTIME, &t2);
	if (_u) {
		cout << "\tAverage update time: " << get_nano_time(&t1, &t2) / update_num / 2000.0 << "um\n";
	}
	return 0;
}
