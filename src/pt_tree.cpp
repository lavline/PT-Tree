#include "pt_tree.h"

PTtree::PTtree(int a, int b, int c, int d) :root(NULL), as_tree(NULL), nodeNum(0)
{
	layertype.resize(4);
	layertype[0] = a;
	layertype[1] = b;
	layertype[2] = c;
	layertype[3] = d;

	for (int i = 0; i < 33; ++i) {
		if (i < 8) {
			maskHash[i][0] = i;
			maskHash[i][1] = 0;
			maskHash[i][2] = 0;
			maskHash[i][3] = 0;
		}
		else {
			maskHash[i][0] = 8;
			if (i < 16) {
				maskHash[i][1] = i - 8;
				maskHash[i][2] = 0;
				maskHash[i][3] = 0;
			}
			else {
				maskHash[i][1] = 8;
				if (i < 24) {
					maskHash[i][2] = i - 16;
					maskHash[i][3] = 0;
				}
				else {
					maskHash[i][2] = 8;
					maskHash[i][3] = i - 24;
				}
			}
		}
	}
}

PTtree::PTtree(int a, int b, int c) :root(NULL), as_tree(NULL), nodeNum(0)
{
	layertype.resize(3);
	layertype[0] = a;
	layertype[1] = b;
	layertype[2] = c;

	for (int i = 0; i < 33; ++i) {
		if (i < 8) {
			maskHash[i][0] = i;
			maskHash[i][1] = 0;
			maskHash[i][2] = 0;
			maskHash[i][3] = 0;
		}
		else {
			maskHash[i][0] = 8;
			if (i < 16) {
				maskHash[i][1] = i - 8;
				maskHash[i][2] = 0;
				maskHash[i][3] = 0;
			}
			else {
				maskHash[i][1] = 8;
				if (i < 24) {
					maskHash[i][2] = i - 16;
					maskHash[i][3] = 0;
				}
				else {
					maskHash[i][2] = 8;
					maskHash[i][3] = i - 24;
				}
			}
		}
	}
}

PTtree::~PTtree()
{
	//printf("delet\n");
	if (root != NULL) {
		freeNode(root);
	}
	if (as_tree != NULL) {
		for (auto&& inode : as_tree->child) {
			for (auto&& leaf : inode.second->child) {
				delete(leaf.second);
			}
			delete(inode.second);
		}
		delete(as_tree);
	}
}

void PTtree::freeNode(innerNode* node)
{
	if (node->childType) {
		for (auto&& hi : node->child) {
			if (hi.point != NULL)delete((leafNode*)hi.point);
		}
	}
	else {
		for (auto&& hi : node->child) {
			if (hi.point != NULL)freeNode((innerNode*)hi.point);
		}
	}
	delete(node);
}

void PTtree::insert(Rule& r)
{
	if (r.source_mask < 4 && r.destination_mask < 4) { //inser in assit tree
		if (as_tree == NULL) {
			as_tree = new ProtoNode();
		}
		int proto = r.protocol[1];
		int pr_id = as_tree->index[proto];
		int lp_id = r.destination_port[0] / 2, hp_id = r.destination_port[1] / 2;
		if (pr_id == -1) {
			as_tree->index[proto] = as_tree->child.size();
			PortNode* p_node = new PortNode();
			if (lp_id == hp_id) {
				p_node->index[lp_id] = 0;
			}
			else
			{
				p_node->index[32768] = 0;
			}
			leafNode* lnode = new leafNode();
			as_leafnode.emplace_back(lnode);
			lnode->rule.emplace_back(r);
			p_node->child.emplace_back(pair<uint32_t, leafNode*>(r.PRI, lnode));
			as_tree->child.emplace_back(pair<uint32_t, PortNode*>(r.PRI, p_node));
		}
		else {
			PortNode* p_node = as_tree->child[pr_id].second;
			if (r.PRI < as_tree->child[pr_id].first)as_tree->child[pr_id].first = r.PRI;
			int c_id;
			if (lp_id == hp_id)c_id = lp_id;
			else c_id = 32768;
			int le_id = p_node->index[c_id];
			if (le_id == -1) {
				p_node->index[c_id] = p_node->child.size();
				leafNode* lnode = new leafNode();
				as_leafnode.emplace_back(lnode);
				lnode->rule.emplace_back(r);
				p_node->child.emplace_back(pair<uint32_t, leafNode*>(r.PRI, lnode));
			}
			else {
				if (r.PRI < p_node->child[le_id].first)p_node->child[le_id].first = r.PRI;
				leafNode* lnode = p_node->child[le_id].second;
				lnode->rule.emplace_back(r);
			}
		}
	}
	else { // insert in PTtree
		if (root == NULL) {
			root = new innerNode(layertype[0], 0, 0, 0);
			innernodeList.emplace_back(root);
			++nodeNum;
		}
		innerNode* node = root;
		int level = layertype.size();
		int layer = 0;
		while (layer < level - 1) {
			unsigned int mask;
			unsigned int ip;
			switch (node->ipIndex)
			{
			case 0:
				mask = maskHash[(unsigned int)r.source_mask][0];
				ip = (unsigned int)r.source_ip[3];
				break;
			case 1:
				mask = maskHash[(unsigned int)r.source_mask][1];
				ip = (unsigned int)r.source_ip[2];
				break;
			case 2:
				mask = maskHash[(unsigned int)r.source_mask][2];
				ip = (unsigned int)r.source_ip[1];
				break;
			case 3:
				mask = maskHash[(unsigned int)r.source_mask][3];
				ip = (unsigned int)r.source_ip[0];
				break;
			case 4:
				mask = maskHash[(unsigned int)r.destination_mask][0];
				ip = (unsigned int)r.destination_ip[3];
				break;
			case 5:
				mask = maskHash[(unsigned int)r.destination_mask][1];
				ip = (unsigned int)r.destination_ip[2];
				break;
			case 6:
				mask = maskHash[(unsigned int)r.destination_mask][2];
				ip = (unsigned int)r.destination_ip[1];
				break;
			case 7:
				mask = maskHash[(unsigned int)r.destination_mask][3];
				ip = (unsigned int)r.destination_ip[0];
				break;
			default:
				break;
			}
			int ip_hash = mask == 8 ? ip : 256;
			if (node->child[ip_hash].point == NULL) {
				innerNode* newchild = new innerNode(layertype[layer + 1], 0, layer + 1, innernodeList.size());
				node->child[ip_hash].point = newchild;
				node->child[ip_hash].pri = r.PRI;
				innernodeList.emplace_back(newchild);
				++nodeNum;
				node = newchild;
			}
			else
			{
				if (r.PRI < node->child[ip_hash].pri)node->child[ip_hash].pri = r.PRI;
				node = (innerNode*)node->child[ip_hash].point;
			}
			++layer;
		}
		// process leafnode
		node->childType = 1;
		unsigned int mask;
		unsigned int ip;
		switch (node->ipIndex)
		{
		case 0:
			mask = maskHash[(unsigned int)r.source_mask][0];
			ip = (unsigned int)r.source_ip[3];
			break;
		case 1:
			mask = maskHash[(unsigned int)r.source_mask][1];
			ip = (unsigned int)r.source_ip[2];
			break;
		case 2:
			mask = maskHash[(unsigned int)r.source_mask][2];
			ip = (unsigned int)r.source_ip[1];
			break;
		case 3:
			mask = maskHash[(unsigned int)r.source_mask][3];
			ip = (unsigned int)r.source_ip[0];
			break;
		case 4:
			mask = maskHash[(unsigned int)r.destination_mask][0];
			ip = (unsigned int)r.destination_ip[3];
			break;
		case 5:
			mask = maskHash[(unsigned int)r.destination_mask][1];
			ip = (unsigned int)r.destination_ip[2];
			break;
		case 6:
			mask = maskHash[(unsigned int)r.destination_mask][2];
			ip = (unsigned int)r.destination_ip[1];
			break;
		case 7:
			mask = maskHash[(unsigned int)r.destination_mask][3];
			ip = (unsigned int)r.destination_ip[0];
			break;
		default:
			break;
		}
		int ip_hash = mask == 8 ? ip : 256;
		if (node->child[ip_hash].point == NULL) {
			leafNode* newchild = new leafNode();
			newchild->rule.emplace_back(r);
			node->child[ip_hash].point = newchild;
			node->child[ip_hash].pri = r.PRI;
			leafnode.emplace_back(newchild);
			++nodeNum;
		}
		else
		{
			if (r.PRI < node->child[ip_hash].pri)node->child[ip_hash].pri = r.PRI;
			leafNode* ln = (leafNode*)node->child[ip_hash].point;
			ln->rule.emplace_back(r);
		}
	}
}

bool PTtree::remove(Rule& r)
{
	if (r.source_mask < 4 && r.destination_mask < 4) { //inser in assit tree
		if (as_tree == NULL) {
			return false;
		}
		int proto = r.protocol[1];
		int pr_id = as_tree->index[proto];
		int lp_id = r.destination_port[0] / 2, hp_id = r.destination_port[1] / 2;
		if (pr_id == -1) {
			return false;
		}
		else {
			PortNode* p_node = as_tree->child[pr_id].second;
			int c_id;
			if (lp_id == hp_id)c_id = lp_id;
			else c_id = 32768;
			int le_id = p_node->index[c_id];
			if (le_id == -1) {
				return false;
			}
			else {
				leafNode* lnode = p_node->child[le_id].second;
				for (int i = 0; i < lnode->rule.size(); ++i) {
					if (lnode->rule[i].PRI == r.PRI) {
						lnode->rule.erase(lnode->rule.begin() + i);
						//lnode->rule[i].PRI = 0x7FFFFFFF;
						return true;
					}
				}
				return false;
			}
		}
	}
	else { // insert in PTtree
		if (root == NULL) {
			return false;
		}
		innerNode* node = root;
		int level = layertype.size();
		int layer = 0;
		while (layer < level - 1) {
			unsigned int mask;
			unsigned int ip;
			switch (node->ipIndex)
			{
			case 0:
				mask = maskHash[(unsigned int)r.source_mask][0];
				ip = (unsigned int)r.source_ip[3];
				break;
			case 1:
				mask = maskHash[(unsigned int)r.source_mask][1];
				ip = (unsigned int)r.source_ip[2];
				break;
			case 2:
				mask = maskHash[(unsigned int)r.source_mask][2];
				ip = (unsigned int)r.source_ip[1];
				break;
			case 3:
				mask = maskHash[(unsigned int)r.source_mask][3];
				ip = (unsigned int)r.source_ip[0];
				break;
			case 4:
				mask = maskHash[(unsigned int)r.destination_mask][0];
				ip = (unsigned int)r.destination_ip[3];
				break;
			case 5:
				mask = maskHash[(unsigned int)r.destination_mask][1];
				ip = (unsigned int)r.destination_ip[2];
				break;
			case 6:
				mask = maskHash[(unsigned int)r.destination_mask][2];
				ip = (unsigned int)r.destination_ip[1];
				break;
			case 7:
				mask = maskHash[(unsigned int)r.destination_mask][3];
				ip = (unsigned int)r.destination_ip[0];
				break;
			default:
				break;
			}
			int ip_hash = mask == 8 ? ip : 256;
			if (node->child[ip_hash].point == NULL) {
				return false;
			}
			else
			{
				node = (innerNode*)node->child[ip_hash].point;
			}
			++layer;
		}
		// process leafnode
		node->childType = 1;
		unsigned int mask;
		unsigned int ip;
		switch (node->ipIndex)
		{
		case 0:
			mask = maskHash[(unsigned int)r.source_mask][0];
			ip = (unsigned int)r.source_ip[3];
			break;
		case 1:
			mask = maskHash[(unsigned int)r.source_mask][1];
			ip = (unsigned int)r.source_ip[2];
			break;
		case 2:
			mask = maskHash[(unsigned int)r.source_mask][2];
			ip = (unsigned int)r.source_ip[1];
			break;
		case 3:
			mask = maskHash[(unsigned int)r.source_mask][3];
			ip = (unsigned int)r.source_ip[0];
			break;
		case 4:
			mask = maskHash[(unsigned int)r.destination_mask][0];
			ip = (unsigned int)r.destination_ip[3];
			break;
		case 5:
			mask = maskHash[(unsigned int)r.destination_mask][1];
			ip = (unsigned int)r.destination_ip[2];
			break;
		case 6:
			mask = maskHash[(unsigned int)r.destination_mask][2];
			ip = (unsigned int)r.destination_ip[1];
			break;
		case 7:
			mask = maskHash[(unsigned int)r.destination_mask][3];
			ip = (unsigned int)r.destination_ip[0];
			break;
		default:
			break;
		}
		int ip_hash = mask == 8 ? ip : 256;
		if (node->child[ip_hash].point == NULL) {
			return false;
		}
		else
		{
			leafNode* ln = (leafNode*)node->child[ip_hash].point;
			for (int i = 0; i < ln->rule.size(); ++i) {
				if (ln->rule[i].PRI == r.PRI) {
					ln->rule.erase(ln->rule.begin() + i);
					return true;
				}
			}
			return false;
		}
	}
}

int PTtree::search(Packet& m)
{
	innerNode* node_1 = root;
	unsigned int mask, ip;
	unsigned int es_ip, ed_ip;
	unsigned char e_protocol;
	unsigned short es_port, ed_port;
	e_protocol = m.protocol;
	memcpy(&es_ip, m.source_ip, 4);
	memcpy(&ed_ip, m.destination_ip, 4);
	es_port = m.source_port;
	ed_port = m.destination_port;

	unsigned int mip[4];
	for (int i = 0; i < 4; ++i) {
		switch (layertype[i])
		{
		case 0:
			mip[i] = (unsigned int)m.source_ip[3];
			break;
		case 1:
			mip[i] = (unsigned int)m.source_ip[2];
			break;
		case 2:
			mip[i] = (unsigned int)m.source_ip[1];
			break;
		case 3:
			mip[i] = (unsigned int)m.source_ip[0];
			break;
		case 4:
			mip[i] = (unsigned int)m.destination_ip[3];
			break;
		case 5:
			mip[i] = (unsigned int)m.destination_ip[2];
			break;
		case 6:
			mip[i] = (unsigned int)m.destination_ip[1];
			break;
		case 7:
			mip[i] = (unsigned int)m.destination_ip[0];
			break;
		default:
			break;
		}
	}
	unsigned int res = 0xFFFFFFFF;

	switch (layertype.size())
	{
	case 3: {
		int i_1[2] = { mip[0], 256 };
		for (int i = 0; i < 2; ++i) {
			if (node_1->child[i_1[i]].point == NULL || node_1->child[i_1[i]].pri > res)continue;
			innerNode* node_2 = (innerNode*)node_1->child[i_1[i]].point;
			int i_2[2] = { mip[1], 256 };
			for (int j = 0; j < 2; ++j) {
				if (node_2->child[i_2[j]].point == NULL || node_2->child[i_2[j]].pri > res)continue;
				innerNode* node_3 = (innerNode*)node_2->child[i_2[j]].point;
				int i_3[2] = { mip[2], 256 };
				for (int k = 0; k < 2; ++k) {
					if (node_3->child[i_3[k]].point == NULL || node_3->child[i_3[k]].pri > res)continue;
					leafNode* ln = (leafNode*)node_3->child[i_3[k]].point;
					for (auto&& r : ln->rule) {
						if (res < r.PRI)break;
						if (e_protocol != r.protocol[1] && r.protocol[0] != 0)continue; // check protocol
						if (ed_port < r.destination_port[0] || r.destination_port[1] < ed_port)continue;  // if destination port not match, check next
						if (es_port < r.source_port[0] || r.source_port[1] < es_port)continue;  // if source port not match, check next
						unsigned int m_bit = 32 - (unsigned int)r.destination_mask;  // comput the bit number need to move
						unsigned int _ip;
						if (m_bit != 32) {
							memcpy(&_ip, r.destination_ip, 4);
							if (ed_ip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next
						}
						m_bit = 32 - (unsigned int)r.source_mask;  // comput the bit number need to move
						if (m_bit != 32) {
							memcpy(&_ip, r.source_ip, 4);
							if (es_ip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next
						}
						res = r.PRI;
						break;
					}
				}
			}
		}
	}
	default:
		break;
	}

	if (as_tree != NULL) {
		int pro_id[2] = { as_tree->index[e_protocol],as_tree->index[0] };
		int port_id[2];
		for (int i = 0; i < 2; ++i) {
			if (pro_id[i] != -1 && res > as_tree->child[pro_id[i]].first) {
				PortNode* p_node = as_tree->child[pro_id[i]].second;
				port_id[0] = p_node->index[ed_port / 2]; port_id[1] = p_node->index[32768];
				for (int j = 0; j < 2; ++j) {
					if (port_id[j] != -1 && res > p_node->child[port_id[j]].first) {
						leafNode* ln = p_node->child[port_id[j]].second;
						for (auto&& r : ln->rule) {
							if (res < r.PRI)break;
							//if (e_protocol != r.protocol[1] && r.protocol[0] != 0)continue; // check protocol
							if (ed_port < r.destination_port[0] || r.destination_port[1] < ed_port)continue;  // if destination port not match, check next
							if (es_port < r.source_port[0] || r.source_port[1] < es_port)continue;  // if source port not match, check next
							unsigned int m_bit = 32 - (unsigned int)r.destination_mask;  // comput the bit number need to move
							unsigned int _ip;
							if (m_bit != 32) {
								memcpy(&_ip, r.destination_ip, 4);
								if (ed_ip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next
							}
							m_bit = 32 - (unsigned int)r.source_mask;  // comput the bit number need to move
							if (m_bit != 32) {
								memcpy(&_ip, r.source_ip, 4);
								if (es_ip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next
							}
							res = r.PRI;
							break;
						}
					}
				}
			}
		}
	}
	return res;
}

int PTtree::search_with_log(Packet& m, ACL_LOG& log)
{
	innerNode* node_1 = root;
	unsigned int mask, ip;
	unsigned int es_ip, ed_ip;
	unsigned char e_protocol;
	unsigned short es_port, ed_port;
	e_protocol = m.protocol;
	memcpy(&es_ip, m.source_ip, 4);
	memcpy(&ed_ip, m.destination_ip, 4);
	es_port = m.source_port;
	ed_port = m.destination_port;

	unsigned int mip[4];
	for (int i = 0; i < 4; ++i) {
		switch (layertype[i])
		{
		case 0:
			mip[i] = (unsigned int)m.source_ip[3];
			break;
		case 1:
			mip[i] = (unsigned int)m.source_ip[2];
			break;
		case 2:
			mip[i] = (unsigned int)m.source_ip[1];
			break;
		case 3:
			mip[i] = (unsigned int)m.source_ip[0];
			break;
		case 4:
			mip[i] = (unsigned int)m.destination_ip[3];
			break;
		case 5:
			mip[i] = (unsigned int)m.destination_ip[2];
			break;
		case 6:
			mip[i] = (unsigned int)m.destination_ip[1];
			break;
		case 7:
			mip[i] = (unsigned int)m.destination_ip[0];
			break;
		default:
			break;
		}
	}
	unsigned int res = 0xFFFFFFFF;
	if (layertype.size() == 3) {
		int i_1[2] = { mip[0], 256 };
		log.innernodes.emplace_back(node_1);
		for (int i = 0; i < 2; ++i) {
			if (node_1->child[i_1[i]].point == NULL || node_1->child[i_1[i]].pri > res)continue;
			innerNode* node_2 = (innerNode*)node_1->child[i_1[i]].point;
			int i_2[2] = { mip[1], 256 };
			log.innernodes.emplace_back(node_2);
			for (int j = 0; j < 2; ++j) {
				if (node_2->child[i_2[j]].point == NULL || node_2->child[i_2[j]].pri > res)continue;
				innerNode* node_3 = (innerNode*)node_2->child[i_2[j]].point;
				int i_3[2] = { mip[2], 256 };
				log.innernodes.emplace_back(node_3);
				for (int k = 0; k < 2; ++k) {
					if (node_3->child[i_3[k]].point == NULL || node_3->child[i_3[k]].pri > res)continue;
					leafNode* ln = (leafNode*)node_3->child[i_3[k]].point;
					log.leafnodes.emplace_back(ln);
					for (auto&& r : ln->rule) {
						++log.rules_num;
						if (res < r.PRI)break;
						if (e_protocol != r.protocol[1] && r.protocol[0] != 0)continue; // check protocol
						if (ed_port < r.destination_port[0] || r.destination_port[1] < ed_port)continue;  // if destination port not match, check next
						if (es_port < r.source_port[0] || r.source_port[1] < es_port)continue;  // if source port not match, check next
						unsigned int m_bit = 32 - (unsigned int)r.destination_mask;  // comput the bit number need to move
						unsigned int _ip;
						if (m_bit != 32) {
							memcpy(&_ip, r.destination_ip, 4);
							if (ed_ip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next
						}
						m_bit = 32 - (unsigned int)r.source_mask;  // comput the bit number need to move
						if (m_bit != 32) {
							memcpy(&_ip, r.source_ip, 4);
							if (es_ip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next
						}
						res = r.PRI;
						break;
					}
				}
			}
		}
	}

	if (as_tree != NULL) {
		int pro_id[2] = { as_tree->index[e_protocol],as_tree->index[0] };
		int port_id[2];
		for (int i = 0; i < 2; ++i) {
			if (pro_id[i] != -1 && res > as_tree->child[pro_id[i]].first) {
				PortNode* p_node = as_tree->child[pro_id[i]].second;
				log.portNodes.emplace_back(p_node);
				port_id[0] = p_node->index[ed_port / 2]; port_id[1] = p_node->index[32768];
				for (int j = 0; j < 2; ++j) {
					if (port_id[j] != -1 && res > p_node->child[port_id[j]].first) {
						leafNode* ln = p_node->child[port_id[j]].second;
						log.leafnodes.emplace_back(ln);
						for (auto&& r : ln->rule) {
							++log.rules_num;
							if (res < r.PRI)break;
							//if (e_protocol != r.protocol[1] && r.protocol[0] != 0)continue; // check protocol
							if (ed_port < r.destination_port[0] || r.destination_port[1] < ed_port)continue;  // if destination port not match, check next
							if (es_port < r.source_port[0] || r.source_port[1] < es_port)continue;  // if source port not match, check next
							unsigned int m_bit = 32 - (unsigned int)r.destination_mask;  // comput the bit number need to move
							unsigned int _ip;
							if (m_bit != 32) {
								memcpy(&_ip, r.destination_ip, 4);
								if (ed_ip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next
							}
							m_bit = 32 - (unsigned int)r.source_mask;  // comput the bit number need to move
							if (m_bit != 32) {
								memcpy(&_ip, r.source_ip, 4);
								if (es_ip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next
							}
							res = r.PRI;
							break;
						}
					}
				}
			}
		}
	}
	return res;
}

size_t PTtree::get_innernode_mem(innerNode* node)
{
	/*size_t sum = sizeof(innerNode) + sizeof(unsigned int) * node->hpri.size();
	for (list<HashIndex>::iterator it = node->HashIndexList.begin(); it != node->HashIndexList.end(); ++it) {
		sum = sum + sizeof(HashIndex) + sizeof(short) * it->index.size() + sizeof(void*) * it->child.size() + sizeof(int) * it->pri.size();
	}
	return sum;*/
}

size_t PTtree::get_leafnode_mem(leafNode* node)
{
	size_t sum = sizeof(leafNode) + sizeof(Rule) * node->rule.size();
	return sum;
}

size_t PTtree::get_mem(innerNode* node)
{
	size_t sum = sizeof(innerNode);
	if (node->childType == 0) {
		for (int i = 0; i < 257; ++i) {
			if (node->child[i].point != NULL)sum += get_mem((innerNode*)node->child[i].point);
		}
	}
	else {
		for (int i = 0; i < 257; ++i) {
			if (node->child[i].point != NULL)sum += get_leafnode_mem((leafNode*)node->child[i].point);
		}
	}
	return sum;
}

size_t PTtree::mem()
{
	size_t sum = 0;
	if (as_tree != NULL) {
		sum += sizeof(ProtoNode) + sizeof(short) * as_tree->index.size() + sizeof(pair<uint32_t, PortNode*>) * as_tree->child.size();
		for (auto&& inode : as_tree->child) {
			sum += sizeof(PortNode) + sizeof(pair<uint32_t, leafNode*>) * inode.second->child.size();
			for (auto&& leaf : inode.second->child) {
				sum += sizeof(leafNode) + leaf.second->rule.size() * sizeof(Rule);
			}
		}
	}
	return sum + get_mem(root);
}

void PTtree::analyse_data(vector<Rule>& list)
{
	char ip_name[8][6] = { "sip_1","sip_2","sip_3" ,"sip_4" ,"dip_1" ,"dip_2" ,"dip_3","dip_4" };
	double alpha[9];
	for (int i = 0; i < 9; ++i)alpha[i] = pow(2, i) / 511;

	FILE* fp = NULL;
	fp = fopen("data_analyse.txt", "w");
	vector<vector<vector<int>>> counter;
	counter.resize(8);
	for (int i = 0; i < 8; ++i) {
		counter[i].resize(9);
		for (int j = 0; j < 9; ++j) {
			counter[i][j].resize((int)pow(2, j));
			for (auto& ele : counter[i][j])ele = 0;
		}
	}
	for (auto& _r : list) {
		int k = 4;
		unsigned int mask = _r.source_mask;
		for (int j = 0; j < 4; j++) {
			unsigned int value = _r.source_ip[--k];
			int _m = maskHash[mask][j];
			value = value >> (8 - _m);
			++counter[j][_m][value];
		}
		k = 4;
		mask = _r.destination_mask;
		for (int j = 4; j < 8; j++) {
			unsigned int value = _r.destination_ip[--k];
			int _m = maskHash[mask][j - 4];
			value = value >> (8 - _m);
			++counter[j][_m][value];
		}
	}
	vector<vector<double>> gini(8, vector<double>(9, 0));
	for (int i = 0; i < 8; ++i) {
		for (int j = 0; j < 9; ++j) {
			int c_size = counter[i][j].size();
			double _y = 0;
			vector<double> _yy(c_size + 1, 0);
			for (int k = 0; k < c_size; ++k) {
				_y += counter[i][j][k];
			}
			if (_y != 0) {
				double tmp = 0;
				vector<int> tmp_y(counter[i][j]);
				sort(tmp_y.begin(), tmp_y.end());
				for (int k = 0; k < c_size; ++k) {
					tmp += tmp_y[k];
					_yy[k + 1] = tmp / _y;
					//printf("%lf ", _yy[k + 1]);
				}
				//printf("\n");
				double sum = 0, a = 0;
				for (int k = 0; k < c_size; ++k) {
					a = (_yy[k] + _yy[k + 1]) / 2.0 / c_size;
					sum += a;
				}
				gini[i][j] = (0.5 - sum) / 0.5;
			}
		}
		gini[i][0] = 1;
	}
	for (int i = 0; i < 8; ++i) {
		double _g = 0;
		fprintf(fp, "%s\n", ip_name[i]);
		for (int j = 0; j < 9; ++j) {
			fprintf(fp, "\tmask=%d", j);
			for (auto ele : counter[i][j]) {
				fprintf(fp, " %d", ele);
			}
			fprintf(fp, " gini=%lf\n", gini[i][j]);
			_g += (alpha[j] * gini[i][j]);
		}
		fprintf(fp, "total_gini=%lf\n", _g);
	}
	fclose(fp);
}

int check_correct(Rule& a, Packet& b)
{
	if (a.protocol[0] != 0 && (uint32_t)a.protocol[1] != b.protocol)return 0;
	int mask = 32 - (uint32_t)a.source_mask;
	uint32_t sip, dip;
	memcpy(&sip, a.source_ip, 4); memcpy(&dip, b.source_ip, 4);
	if (mask != 32 && (sip >> mask) != (dip >> mask))return 0;
	mask = 32 - (uint32_t)a.destination_mask;
	memcpy(&sip, a.destination_ip, 4); memcpy(&dip, b.destination_ip, 4);
	if (mask != 32 && (sip >> mask) != (dip >> mask))return 0;
	if (b.source_port < a.source_port[0] || b.source_port > a.source_port[1])return 0;
	if (b.destination_port < a.destination_port[0] || b.destination_port > a.destination_port[1])return 0;
	return 1;
}

int simple_match(vector<Rule>& rules, Packet& b)
{
	for (auto&& a : rules) {
		if (a.protocol[0] != 0 && (uint32_t)a.protocol[1] != b.protocol)continue;
		int mask = 32 - (uint32_t)a.source_mask;
		uint32_t sip, dip;
		memcpy(&sip, a.source_ip, 4); memcpy(&dip, b.source_ip, 4);
		if (mask != 32 && (sip >> mask) != (dip >> mask))continue;
		mask = 32 - (uint32_t)a.destination_mask;
		memcpy(&sip, a.destination_ip, 4); memcpy(&dip, b.destination_ip, 4);
		if (mask != 32 && (sip >> mask) != (dip >> mask))continue;
		if (b.source_port < a.source_port[0] || b.source_port > a.source_port[1])continue;
		if (b.destination_port < a.destination_port[0] || b.destination_port > a.destination_port[1])continue;
		return a.PRI;
	}
	return -1;
}
