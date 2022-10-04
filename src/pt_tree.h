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

struct IpChild {
	void* pointer;
	int pri;
	IpChild() : pointer(NULL) {}
};
struct IpNode_static {
	uint16_t layer, id;
	IpChild child[257];
	uint8_t field; // 0-3: sip 1-4; 4-7: dip 1-4
	bool childType; // 0: innernode; 1: leafnode
	IpNode_static(uint8_t a, bool b, uint16_t c, uint16_t d) : field(a), childType(b), layer(c), id(d) {}
};
struct LeafNode {
	vector<Rule> rule;
};
struct PortNode
{
	short index[32769];
	vector<pair<uint32_t, LeafNode*>> child;
	PortNode() { for (int i = 0; i < 32769; ++i)index[i] = -1; }
};
struct ProtoNode {
	vector<short> index;
	vector<pair<uint32_t, PortNode*>> child;
	ProtoNode() : index(256, -1) {}
};

struct ACL_LOG {
	int rules;
	int tables;
	vector<void*> ipNodeList;
	vector<LeafNode*> leafNodeList;
	vector<PortNode*> portNodeList;
	ACL_LOG() : rules(0), tables(0) {}
};

class PTtree {
private:
	vector<uint8_t> layerFields;
public:
	void* pTree;
	ProtoNode* aTree;
	int totalNodes;
	vector<void*> ipNodeList;
	vector<LeafNode*> pLeafNodeList;
	vector<LeafNode*> aLeafNodeList;

	PTtree(vector<uint8_t>& list);
	~PTtree();
	void freeStaticNode(IpNode_static* node);
	//void freeNode(IpNode* node);

	void insert(Rule& r);
	bool remove(Rule& r);
	int search(Packet& m);
	int search_with_log(Packet& m, ACL_LOG& log);

	//size_t get_ipNode_mem(void* node);
	size_t get_leafNode_mem(LeafNode* node);
	size_t get_static_mem(IpNode_static* node);
	size_t mem();

	void analyse_data(vector<Rule>& list);
};

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
