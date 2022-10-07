#include <iostream>
#include <time.h>
#include <random>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include "pt_tree.h"
#include "read.h"

using namespace std;

double get_nano_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000000000 + b->tv_nsec - a->tv_nsec;
}
double get_milli_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000 + (double)(b->tv_nsec - a->tv_nsec) / 1000000.0;
} 

int main(int argc, char* argv[]) {
	if (argc == 1) { fprintf(stderr, "use -h(--help) to print the usage guideline.\n"); return 0; }
	string ipFieldName[8] = { "Sip1", "Sip2", "Sip3", "Sip4", "Dip1", "Dip2", "Dip3", "Dip4" };
	vector<Rule> rules;
	vector<Packet> packets;
	vector<int> check_list;
	struct timespec t1, t2;

	bool enable_log = false;
	bool enable_search_config = true;
	bool enable_update = false;
	int log_level = 1; // {1,2,3}
	vector<uint8_t> set_field;
	int set_port = 1;
	int opt;
	struct option opts[] = {
		{"ruleset", 1, NULL, 'r'},
		{"packet", 1, NULL, 'p'},
		{"fields", 1, NULL, 'f'},
		{"log", 1, NULL, 'l'},
		{"update", 0, NULL, 'u'},
		{"help", 0, NULL, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "r:p:f:l:uh", opts, NULL)) != -1) {
		switch (opt)
		{
		case 'r':
			cout << "read ruleset: " << optarg << endl;
			if (!read_rules(optarg, rules)) return -1;
			break;
		case 'p':
			cout << "read packets: " << optarg << endl;
			if (!read_packets(optarg, packets, check_list)) return -1;
			break;
		case 'f': {
			vector<int> tmp_in_field;
			int i = 0;
			while (optarg[i] != '\0') {
				if (optarg[i] != ',') {
					char c = optarg[i];
					tmp_in_field.emplace_back(atoi(&c));
				}
				++i;
			}
			cout << "set pTree field: ";
			for (i = 0; i < tmp_in_field.size() - 1; ++i) {
				cout << tmp_in_field[i] << " ";
				set_field.emplace_back(tmp_in_field[i]);
			}
			cout << "\nset aTree port field: " << tmp_in_field[i] << endl;
			set_port = tmp_in_field[i];
			break;
		}
		case 'l':
			enable_log = true;
			log_level = atoi(optarg);
			if (log_level < 1 || log_level>3) {
				fprintf(stderr, "error-unknown log level %d.\n", log_level);
				return -1;
			}
			cout << "enable log: level " << log_level << endl;
			break;
		case 'u':
			enable_update = true;
			cout << "enable update\n";
			break;
		case 'h':
			cout << "\n-r(--ruleset): Input the rule set file. This argument must be specified. (Example: [-r acl1])\n";
			cout << "-p(--packet):  Input the packet set file. If not set, the program will generate randomly. (Example: [-p acl1_trace])\n";
			cout << "-f(--fields):  Set the pTree and aTree used fields, using \',\' to separation. The last on is the port setting, 0 is source port, 1 is destination port.\n";
			cout << "               Using 0-3 to express source ip 1-4 byte and 4-7 to express destination ip 1-4 byte. (Example: [-f 4,0,1,1])\n";
			cout << "-l(--log):     Enable the log. Have three level 1-3. (Example: [-l 3])\n";
			cout << "-u(--update):  Enable update. (Example: [-u])\n";
			cout << "-h(--help):    Print the usage guideline.\n\n";
			return 0;
		case '?':
			fprintf(stderr, "error-unknown argument -%c.", optopt);
			return -1;
		default:
			break;
		}
	}

	setmaskHash();
	
	/***********************************************************************************************************************/
	// search config
	/***********************************************************************************************************************/
	if (set_field.size() == 0) {
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
			//cout << best_time / 1000000.0 << endl;
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
		for (unsigned int _f : fields[best_config1]) {
			cout << ipFieldName[_f] << ",";
			set_field.emplace_back(_f);
		}
		if (best_config2 == 0)cout << "Sport";
		else cout << "Dport";
		cout << "\n\tbest time: " << best_time / 1000000.0 << "um\n";
		set_port = best_config2;
	}
	
	PTtree tree(set_field, set_port);

	/***********************************************************************************************************************/
	// insert
	/***********************************************************************************************************************/
	cout << "\nstart build...\nUsing fields ";
	for (unsigned int x : set_field)cout << x << ",";
	cout << set_port << endl;
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

	/***********************************************************************************************************************/
	// update
	/***********************************************************************************************************************/
	if (enable_update) {
		int update_num = 5000;
		cout << "\nstart update...\n";
		clock_gettime(CLOCK_REALTIME, &t1);
		bool _u = tree.update(rules, update_num);
		clock_gettime(CLOCK_REALTIME, &t2);
		if (_u) {
			cout << "\tAverage update time: " << get_nano_time(&t1, &t2) / update_num / 2000.0 << "um\n";
		}
	}
	return 0;
}
