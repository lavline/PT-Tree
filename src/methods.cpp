#include "methods.h"

using namespace std;

void single_thread(vector<uint8_t> set_field, int set_port, bool enable_log, int log_level, bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list)
{
	struct timespec t1, t2;
	PTtree tree(set_field, set_port);

	/***********************************************************************************************************************/
	// insert
	/***********************************************************************************************************************/
	cout << "\nStart build for single thread...\n|- Using fields:     ";
	for (unsigned int x : set_field)cout << x << ",";
	cout << set_port << endl;
	clock_gettime(CLOCK_REALTIME, &t1);
	for (auto&& r : rules) {
		tree.insert(r);
	}
	clock_gettime(CLOCK_REALTIME, &t2);
	double build_time = get_milli_time(&t1, &t2);
	cout << "|- Construct time:   " << build_time << "ms\n";
	//cout << tree.totalNodes << endl;

	cout << "|- Memory footprint: " << (double)tree.mem() / 1024.0 / 1024.0 << "MB\n";

	/***********************************************************************************************************************/
	// warm up
	/***********************************************************************************************************************/
	for (int i = 0; i < 10; ++i) {
		for (int j = 0; j < 1000; ++j) {
			tree.search(packets[j]);
		}
	}

	/***********************************************************************************************************************/
	// Search
	/***********************************************************************************************************************/
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
				exit(-1);
			}
		}
		//int true_result = simple_search(rules, packets[i]);
		//if (res != true_result) {
		//	fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but result %d.\n", i, true_result, res);
		//	//return -1;
		//}
		//fprintf(res_fp, "Packet %d \t Result %d \t Time(um) %f\n", i, res, _time / 1000.0);
	}
	fclose(res_fp);
	cout << "|- Average search time: " << search_time / packets.size() / 1000.0 << "um\n";
	cout << "|- Throughput         : " << packets.size() * 1000.0 / search_time << "M/s\n";

	/***********************************************************************************************************************/
	// Print Log
	/***********************************************************************************************************************/
	if (enable_log) {
		cout << "\nPrint Log...\n";
		// level 1: print node information
		tree.print_node_info(log_level, rules.size());
		// level 2: print search information
		if (log_level > 1) {
			FILE* log_fp = NULL;
			if (log_level > 2) {
				log_fp = fopen("search_info.txt", "w");
				fprintf(log_fp, "Search Log [PACKET_ID ACC_INNERNODE ACC_LEAFNODE ACC_TABLE ACC_RULE ACC_IPNODE ACC_PORTNODE]\n\n");
			}
			double acc_inner, acc_leaf, acc_table, acc_rule;
			acc_inner = acc_leaf = acc_table = acc_rule = 0;
			for (int i = 0; i < packets.size(); ++i) {
				ACL_LOG log;
				tree.search_with_log(packets[i], log);
				acc_inner += log.innerNodes;
				acc_leaf += log.leafNodes;
				acc_table += log.tables;
				acc_rule += log.rules;
				if (log_level > 2)
					fprintf(log_fp, "%d\t%u\t%u\t%u\t%u\t%u\t%u\n", i, log.innerNodes, log.leafNodes, log.tables, log.rules, log.ipNodeList.size(), log.portNodeList.size());
			}
			cout << "|- Access innerNode avg num: " << acc_inner / packets.size() << endl;
			cout << "|- Access leafNode avg num:  " << acc_leaf / packets.size() << endl;
			cout << "|- Access table avg num:     " << acc_table / packets.size() << endl;
			cout << "|- Access rule avg num:      " << acc_rule / packets.size() << endl;
			if (log_level > 2) {
				cout << "|- Write search infomation to search_info.txt...\n";
				fclose(log_fp);
			}
		}
	}

	/***********************************************************************************************************************/
	// update
	/***********************************************************************************************************************/
	if (enable_update) {
		int update_num = 5000;
		cout << "\nStart update...\n";
		bool _u = tree.update(rules, update_num, t1, t2);
		if (_u) {
			cout << "|- Average update time: " << get_nano_time(&t1, &t2) / (update_num * 2.0) / 1000.0 << "um\n";
		}
	}
}

void multi_thread(vector<uint8_t> set_field, int set_port, bool enable_log, int log_level, bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list)
{
	printf("\nStart build for mulithread...\n|- Using fields:     ");
	for (unsigned int x : set_field)printf("%d,", x);
	printf("%d\n", set_port);
	PTtree tree(set_field, set_port);

	struct timespec st, et;
	clock_gettime(CLOCK_REALTIME, &st);
	tree.construct_for_multi(rules);
	clock_gettime(CLOCK_REALTIME, &et);

	printf("|- Construct time:   %f ms\n", get_milli_time(&st, &et));
	printf("|- Memory footprint: %f MB\n", (double)tree.mem() / 1024.0 / 1024.0);

	int thread_num = 2;
	for (; thread_num <= 32; thread_num *= 2) {
		int workloads = (packets.size() / thread_num) + 1;
		double throughput[thread_num];
		atomic_int32_t cur_packet(0);
		atomic_bool start_test(false);
		thread threads[thread_num];

		// multi-thread read
		for (int i = 0; i < thread_num; ++i) {
			threads[i] = thread([&](int id, int start_p, int end_p)->bool
				{
					struct timespec t1, t2;
					int res = -1;
					double s_time = 0;
					while (!start_test);
					for (int j = start_p; j < end_p; ++j) {
						clock_gettime(CLOCK_REALTIME, &t1);
						res = tree.search_multiThread(packets[j]);
						clock_gettime(CLOCK_REALTIME, &t2);
						double _time = get_nano_time(&t1, &t2);
						//printf("%f\n", _time);
						s_time += _time;
						if (res != check_list[j]) {
							if (res > check_list[j] || !check_correct(rules[res], packets[j])) {
								fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
								//printf("Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
								return false;
							}
						}
					}
					throughput[id] = 1000.0 * (end_p - start_p) / s_time;
					//printf("%d %d %f\n", start_p, end_p, s_time / (end_p - start_p) / 1000.0);
					//printf("id: %d throughput: %f\n", id, s_time / (end_p - start_p) / 1000.0);
					return true;
				}, i, i * workloads, (((i + 1) * workloads) > packets.size() ? packets.size() : ((i + 1) * workloads)));
		}

		start_test.store(true);
		double total_throughput = 0;
		for (int i = 0; i < thread_num; ++i) {
			threads[i].join();
			total_throughput += throughput[i];
		}
		start_test.store(false);
		printf("\n%d thread throughput: %f M/s\n", thread_num, total_throughput);

		// multi-thread read with write
		thread update_thread([&]()-> bool {
			random_device seed;
			mt19937 rd(seed());
			uniform_int_distribution<> dis(0, rules.size() - 1);
			int up_num[4] = { 0 };
			struct timespec t1, t2;
			double s_time = 0;
			while (!start_test);
			while (true) {
				if (cur_packet < 250000) {
					if (cur_packet % 10000 == 0) {
						int idx = dis(rd);
						clock_gettime(CLOCK_REALTIME, &t1);
						tree.remove_multiThread(rules[idx]);
						tree.insert_multiThread(rules[idx]);
						clock_gettime(CLOCK_REALTIME, &t2);
						s_time += get_nano_time(&t1, &t2);
						++up_num[0];
					}
				}
				else if (cur_packet < 500000) {
					if (cur_packet % 1000 == 0) {
						int idx = dis(rd);
						clock_gettime(CLOCK_REALTIME, &t1);
						tree.remove_multiThread(rules[idx]);
						tree.insert_multiThread(rules[idx]);
						clock_gettime(CLOCK_REALTIME, &t2);
						s_time += get_nano_time(&t1, &t2);
						++up_num[1];
					}
				}
				else if (cur_packet < 750000) {
					if (cur_packet % 100 == 0) {
						int idx = dis(rd);
						clock_gettime(CLOCK_REALTIME, &t1);
						tree.remove_multiThread(rules[idx]);
						tree.insert_multiThread(rules[idx]);
						clock_gettime(CLOCK_REALTIME, &t2);
						s_time += get_nano_time(&t1, &t2);
						++up_num[2];
					}
				}
				else {
					if (cur_packet % 10 == 0) {
						int idx = dis(rd);
						clock_gettime(CLOCK_REALTIME, &t1);
						tree.remove_multiThread(rules[idx]);
						tree.insert_multiThread(rules[idx]);
						clock_gettime(CLOCK_REALTIME, &t2);
						s_time += get_nano_time(&t1, &t2);
						++up_num[3];
					}
				}
				if (!start_test)break;
			}

			printf("\nupdate num --- stage1: %d stage2: %d stage3: %d stage4: %d\n", up_num[0], up_num[1], up_num[2], up_num[3]);
			int total_upNum = (up_num[0] + up_num[1] + up_num[2] + up_num[3]) * 2;
			printf("total operate num: %d avg update time: %f um throughput: %f M/s\n", total_upNum, s_time / total_upNum / 1000.0, 1000.0 * total_upNum / s_time);
			return true;
			});


		for (int i = 0; i < thread_num; ++i) {
			threads[i] = thread([&](int id, int start_p, int end_p)->bool
				{
					struct timespec t1, t2;
					int res = -1;
					double s_time = 0;
					while (!start_test);
					for (int j = start_p; j < end_p; ++j) {
						//printf("%d\n", j);
						clock_gettime(CLOCK_REALTIME, &t1);
						res = tree.search_multiThread(packets[j]);
						clock_gettime(CLOCK_REALTIME, &t2);
						++cur_packet;
						double _time = get_nano_time(&t1, &t2);
						//printf("%f\n", _time);
						s_time += _time;
						if (res != check_list[j]) {
							if (res != -1 && !check_correct(rules[res], packets[j])) {
								fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
								//printf("Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
								return false;
							}
						}
					}
					throughput[id] = 1000.0 * (end_p - start_p) / s_time;
					//printf("%d %d %f\n", start_p, end_p, s_time / (end_p - start_p) / 1000.0);
					//printf("id: %d throughput: %f\n", id, s_time / (end_p - start_p) / 1000.0);
					return true;
				}, i, i * workloads, (((i + 1) * workloads) > packets.size() ? packets.size() : ((i + 1) * workloads)));
		}

		start_test.store(true);
		total_throughput = 0;
		for (int i = 0; i < thread_num; ++i) {
			threads[i].join();
			total_throughput += throughput[i];
		}
		start_test.store(false);
		update_thread.join();
		printf("\n%d thread throughput with update: %f M/s\n", thread_num, total_throughput);
	}
}
