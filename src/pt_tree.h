#ifndef _PT_TREE_
#define _PT_TREE_
#include "data_structure.h"
#include <list>

#define SIP_1 0
#define SIP_2 1
#define SIP_3 2
#define SIP_4 3
#define DIP_1 4
#define DIP_2 5
#define DIP_3 6
#define DIP_4 7

using namespace std;

struct HashIndex {
	void* point;
	int pri;
	HashIndex() : point(NULL) {}
};
struct innerNode {
	uint16_t layer, id;
	HashIndex child[257];
	uint8_t ipIndex; // 0-3: sip 1-4; 4-7: dip 1-4
	bool childType; // 0: innernode; 1: leafnode
	innerNode(uint8_t a, bool b, uint16_t c, uint16_t d) : ipIndex(a), childType(b), layer(c), id(d) {}
};
struct leafNode {
	vector<Rule> rule;
	//class maskTree* subtree;
};
struct PortNode
{
	short index[32769];
	vector<pair<uint32_t, leafNode*>> child;
	PortNode() { for (int i = 0; i < 32769; ++i)index[i] = -1; }
};
struct ProtoNode {
	vector<short> index;
	//vector<unsigned int> pri;
	vector<pair<uint32_t, PortNode*>> child;
	ProtoNode() : index(256, -1) {}
};

struct ACL_LOG {
	int rules_num;
	int check_hashlist;
	vector<innerNode*> innernodes;
	vector<leafNode*> leafnodes;
	vector<PortNode*> portNodes;
	ACL_LOG() : rules_num(0), check_hashlist(0) {}
};

class PTtree {
private:
	vector<uint8_t> layertype;
	unsigned int maskHash[33][4];
public:
	innerNode* root;
	ProtoNode* as_tree;
	int nodeNum;
	vector<innerNode*> innernodeList;
	vector<leafNode*> leafnode;
	vector<leafNode*> as_leafnode;

	PTtree(int a, int b, int c, int d);
	PTtree(int a, int b, int c);
	~PTtree();
	void freeNode(innerNode* node);

	void insert(Rule& r);
	bool remove(Rule& r);
	int search(Packet& m);
	int search_with_log(Packet& m, ACL_LOG& log);

	size_t get_innernode_mem(innerNode* node);
	size_t get_leafnode_mem(leafNode* node);
	size_t get_mem(innerNode* node);
	size_t mem();

	void analyse_data(vector<Rule>& list);
};

int check_correct(Rule& a, Packet& b);
int simple_match(vector<Rule>& rules, Packet& b);

inline uint64_t GetCPUCycle()
{
#ifdef __x86_64__
	unsigned int lo, hi;
	__asm__ __volatile__("lfence" : : : "memory");
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return ((uint64_t)hi << 32) | lo;
#elif __aarch64__
	uint64_t v = 0;
	asm volatile("isb" : : : "memory");
	asm volatile("mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	printf("unknown arch\n");
	return 0;
#endif
}


#endif // !_PT_TREE_
