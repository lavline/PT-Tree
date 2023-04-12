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

#include <random>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include "pt_tree.h"
#include "read.h"
#include "gen.h"
#include "methods.h"

using namespace std; 

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
	int time_model = 1;
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

	while ((opt = getopt_long(argc, argv, "r:p:f:l:t:uh", opts, NULL)) != -1) {
		switch (opt)
		{
		case 'r':
			cout << "Read ruleset:  " << optarg << endl;
			if (!read_rules(optarg, rules)) return -1;
			break;
		case 'p':
			cout << "Rread packets: " << optarg << endl;
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
			cout << "Set pTree field: ";
			for (i = 0; i < tmp_in_field.size() - 1; ++i) {
				cout << tmp_in_field[i] << " ";
				set_field.emplace_back(tmp_in_field[i]);
			}
			cout << "\nSet aTree port field: " << tmp_in_field[i] << endl;
			set_port = tmp_in_field[i];
			break;
		}
		case 't': {
			time_model = atoi(optarg);
			if (time_model != 1 && time_model != 2) {
				cout << "The parameter of -t is incorrect.\n";
				return -1;
			}
			break;
		}
		case 'l':
			enable_log = true;
			log_level = atoi(optarg);
			if (log_level < 1 || log_level>3) {
				fprintf(stderr, "error-unknown log level %d.\n", log_level);
				return -1;
			}
			cout << "Enable log:    level " << log_level << endl;
			break;
		case 'u':
			enable_update = true;
			cout << "Enable update\n";
			break;
		case 'h':
			cout << "\n************************************************************************************************************************************************************\n";
			cout <<   "* -r(--ruleset): Input the rule set file. This argument must be specified. (Example: [-r acl1])                                                            *\n";
			cout <<   "* -p(--packet):  Input the packet set file. If not set, the program will generate randomly. (Example: [-p acl1_trace])                                     *\n";
			cout <<   "* -f(--fields):  Set the pTree and aTree used fields, using \',\' to separation. The last on is the port setting, 0 is source port, 1 is destination port.   *\n";
			cout <<   "*                Using 0-3 to express source ip 1-4 byte and 4-7 to express destination ip 1-4 byte. (Example: [-f 4,0,1,1])                               *\n";
			cout <<   "* -l(--log):     Enable the log. Have three level 1-3. (Example: [-l 3])                                                                                   *\n";
			cout <<   "* -u(--update):  Enable update. (Example: [-u])                                                                                                            *\n";
			cout <<   "* -t:  Using time or clock to monitor. 1: microsecond 2: clock (Example: [-t 2])                                                                           *\n";
			cout <<   "* -h(--help):    Print the usage guideline.                                                                                                                *\n";
			cout <<   "************************************************************************************************************************************************************\n\n";
			if (argc == 2)return 0;
			break;
		case '?':
			fprintf(stderr, "error-unknown argument -%c.", optopt);
			return -1;
		default:
			break;
		}
	}

	if (packets.size() == 0)gen_trace(packets, check_list, rules, 1000000);
	setmaskHash();
	
	/***********************************************************************************************************************/
	// search config
	/***********************************************************************************************************************/
	if (set_field.size() == 0) {
		//cout << "\nSearch config...\n";
		//int search_leavel = 1000;
		//vector<Packet> tmp_packets;
		//gen_trace(tmp_packets, rules, search_leavel);
		//vector<vector<uint8_t>> fields;
		//vector<uint8_t> tmp_fields;
		//tmp_fields.resize(3);
		//FILE* fp_l3 = fopen("./L3.txt", "r");
		//if (fp_l3 == NULL) {
		//	fprintf(stderr, "error - can not open L3.txt\n");
		//	return 0;
		//}
		//while (fscanf(fp_l3, "%u %u %u \n", &tmp_fields[0], &tmp_fields[1], &tmp_fields[2]) != EOF) {
		//	fields.emplace_back(tmp_fields);
		//}
		//fclose(fp_l3);
		//tmp_fields.resize(4);
		//FILE* fp_l4 = fopen("./L4.txt", "r");
		//if (fp_l4 == NULL) {
		//	fprintf(stderr, "error - can not open L4.txt\n");
		//	return 0;
		//}
		//while (fscanf(fp_l4, "%u %u %u %u \n", &tmp_fields[0], &tmp_fields[1], &tmp_fields[2], &tmp_fields[3]) != EOF) {
		//	fields.emplace_back(tmp_fields);
		//}
		//fclose(fp_l4);
		////cout << fields.size() << endl;
		//double min_time = 100e9;
		//double cur_time = 0;
		//double best_time = 0;
		//int best_config1, best_config2 = 1;
		//struct timespec st1, st2;
		//clock_gettime(CLOCK_REALTIME, &st1);
		//for (int i = 0; i < fields.size(); ++i) {
		//	PTtree tree(fields[i], 1);
		//	for (auto&& r : rules) {
		//		tree.insert(r);
		//	}
		//	clock_gettime(CLOCK_REALTIME, &t1);
		//	for (int j = 0; j < search_leavel; ++j) {
		//		tree.search(tmp_packets[j]);
		//	}
		//	clock_gettime(CLOCK_REALTIME, &t2);
		//	cur_time = get_nano_time(&t1, &t2);
		//	//cout << cur_time / 1000000.0 << endl;
		//	if (cur_time < min_time) {
		//		min_time = cur_time;
		//		best_config1 = i;
		//		best_time = cur_time;
		//	}
		//}
		//{
		//	//cout << best_time / 1000000.0 << endl;
		//	PTtree tree(fields[best_config1], 0);
		//	for (auto&& r : rules) {
		//		tree.insert(r);
		//	}
		//	clock_gettime(CLOCK_REALTIME, &t1);
		//	for (int i = 0; i < search_leavel; ++i) {
		//		tree.search(tmp_packets[i]);
		//	}
		//	clock_gettime(CLOCK_REALTIME, &t2);
		//	cur_time = get_nano_time(&t1, &t2);
		//	//cout << cur_time / 1000000.0 << endl;
		//	if (cur_time < min_time) {
		//		min_time = cur_time;
		//		best_config2 = 0;
		//		best_time = cur_time;
		//	}
		//}
		//clock_gettime(CLOCK_REALTIME, &st2);
		//cout << "|- Search config time:    " << get_milli_time(&st1, &st2) / 1000.0 << "s\n";
		//cout << "|- Best config:           ";
		//for (unsigned int _f : fields[best_config1]) {
		//	cout << ipFieldName[_f] << ",";
		//	set_field.emplace_back(_f);
		//}
		//if (best_config2 == 0)cout << "Sport";
		//else cout << "Dport";
		//cout << "\n|- Minimum lookup time:   " << best_time / 1000000.0 << "um\n";
		//set_port = best_config2;
		CacuInfo cacu(rules);
		cacu.read_fields();
		set_field = cacu.cacu_best_fields();
		set_port = 1;
	}
	for (int i = 0; i < set_field.size(); ++i)printf("%d ", set_field[i]);
	/*switch (time_model)
	{
	case 1: {
		single_thread(set_field, set_port, enable_log, log_level, enable_update, rules, packets, check_list);
		multi_thread(set_field, set_port, enable_log, log_level, enable_update, rules, packets, check_list);
		break;
	}
	case 2: {
		single_thread_cycle(set_field, set_port, enable_log, log_level, enable_update, rules, packets, check_list);
		multi_thread_cycle(set_field, set_port, enable_log, log_level, enable_update, rules, packets, check_list);
		break;
	}
	default:
		break;
	}*/

	cout << "\nProgram complete.\n\n";
	return 0;
}
