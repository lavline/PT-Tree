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

extern uint8_t maskHash[33][4];

struct IpTable
{
	uint32_t pri;
	uint32_t mask;
	vector<short> table;
	vector<pair<uint32_t, void*>> child; // first: pri second: pointer
	IpTable(uint32_t n) : table(1 << n, -1), pri(0), mask(n) {}
};

struct IpNode
{
	uint32_t id;
	uint16_t layer;
	uint8_t field; // 0-3: sip 1-4; 4-7: dip 1-4
	bool childType; // 0: innernode; 1: leafnode
	list<IpTable> tableList; // first: pri second: table
	IpNode(uint8_t _field, bool _cType, uint16_t _layer, uint32_t _id) : field(_field), childType(_cType), layer(_layer), id(_id) {}
};

struct IpChild {
	void* pointer;
	int pri;
	IpChild() : pointer(NULL) {}
};
struct IpNode_static {
	uint32_t id;
	uint16_t layer;
	uint8_t field; // 0-3: sip 1-4; 4-7: dip 1-4
	bool childType; // 0: innernode; 1: leafnode
	IpChild child[257];
	IpNode_static(uint8_t _field, bool _cType, uint16_t _layer, uint32_t _id) : field(_field), childType(_cType), layer(_layer), id(_id) {}
};
struct LeafNode {
	vector<Rule> rule;
};
struct PortNode_static
{
	uint32_t id;
	short table[32769];
	vector<pair<uint32_t, LeafNode*>> child;
	PortNode_static(uint32_t _id) :id(_id) { for (int i = 0; i < 32769; ++i)table[i] = -1; }
};
struct ProtoNode {
	vector<short> table;
	vector<pair<uint32_t, void*>> child;
	ProtoNode() : table(256, -1) {}
};

struct ACL_LOG {
	int rules;
	int tables;
	int innerNodes;
	int leafNodes;
	vector<void*> ipNodeList;
	vector<LeafNode*> pLeafNodeList;
	vector<void*> portNodeList;
	vector<LeafNode*> aLeafNodeList;
	ACL_LOG() : rules(0), tables(0), innerNodes(0), leafNodes(0) {}
};

class PTtree {
private:
	vector<uint8_t> layerFields;
	int portField, portStep;
public:
	void* pTree;
	ProtoNode* aTree;
	int totalNodes;
	vector<void*> ipNodeList;
	vector<void*> portNodeList;
	vector<LeafNode*> pLeafNodeList;
	vector<LeafNode*> aLeafNodeList;

	PTtree(vector<uint8_t>& list, int _portField);
	PTtree(vector<uint8_t>& list, int _portField, int _portStep);
	~PTtree();

	void freeStaticNode(IpNode_static* node);
	void freeNode(IpNode* node);

	void insert(Rule& r);
	bool remove(Rule& r);

	int search(Packet& p);
	int search_with_log(Packet& p, ACL_LOG& log);

	bool update(vector<Rule>& rules, int num, struct timespec& t1, struct timespec& t2);

	void print_node_info();

	size_t get_ipNode_mem(IpNode* node);
	size_t get_leafNode_mem(LeafNode* node);
	size_t get_static_mem(IpNode_static* node);
	size_t get_mem(IpNode* node);
	size_t mem();

	void analyse_ruleset(vector<Rule>& list);
};


int search_config(vector<vector<int>> list);
int check_correct(Rule& a, Packet& b);
int simple_search(vector<Rule>& rules, Packet& b);
void setmaskHash();

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
