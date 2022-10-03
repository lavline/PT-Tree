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

struct LeafNode {
	vector<Rule> rules;
};

struct PortNode_static
{
	short table[32769];
	vector<pair<uint32_t, LeafNode*>> child;  // first: pri second: pointer
	PortNode_static() { for (int i = 0; i < 32769; ++i)table[i] = -1; }
};

struct ProtoNode {
	vector<short> table;
	vector<pair<uint32_t, PortNode_static*>> child;  // first: pri second: pointer
	ProtoNode() : table(256, -1) {}
};

struct ipChild
{
	void* pointer;
	uint32_t pri;
	ipChild() :pointer(NULL), pri(0) {}
};

struct IpNode_static {
	uint16_t layer, id, field, cType;  // layer: node layer; id: node id; field: node setted field(0-3: sip1-4 4-7: dip1-4); cType: node child type(0: ipnode 1: leafnode) 
	ipChild child[257];
	IpNode_static(uint16_t a, uint16_t b, uint16_t c, uint16_t d) : layer(a), id(b), field(c), cType(d) {}
};

struct IpNode
{

};

struct LOG
{
	int cRules;
	int cTables;
	vector<void*> cIpNodes;
	vector<LeafNode*> cLeafNodes;
	vector<void*> cPortNodes;
	LOG(): cRules(0), cTables(0){}
};


class PTtree {
private:
	vector<int> layerFields;  // each layer selected field (0-3: sip1-4 4-7: dip1-4)
	int portField;  // 0: Sport 1: Dport
	int portStep;  // field divided step in first level
public:
	void* pTree; // prefix tuple cascading tree
	ProtoNode* aTree; // auxiliary tree
	int totalNodes;
	vector<void*> IpNodesList;
	vector<LeafNode*> ptLeafNodesList;
	vector<void*> PortNodesList;
	vector<LeafNode*> aLeafNodesList;
public:
	
	PTtree(vector<int>& list, int a, int b); // (fieldlist, portField: 0-sport, 1-dport, step)
	//~PTtree();

	void freeNode(void* node);

	void insert(const Rule& _r);
	bool remove(const Rule& _r);

	int search(const Packet& _p);
	int search_log(const Packet& _p, LOG& log);

	size_t get_innernode_mem(IpNode* node);
	size_t get_leafnode_mem(LeafNode* node);
	size_t get_mem(void* node);
	size_t total_mem();

	void analyse_rules(const vector<Rule>& rules);
	// void get_mask_ip(int _type, const Rule& _r, uint32_t& _mask, uint32_t& _ip);
};

void set_maskHash();

int check_correct(const Rule& _r, const Packet& _p);
int simple_search(const vector<Rule>& rules, const Packet& _p);

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
