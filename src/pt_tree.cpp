#include "pt_tree.h"

uint8_t maskHash[33][4];

void set_maskHash()
{
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

int check_correct(const Rule& _r, const Packet& _p)
{
	if (_r.protocol[0] != 0 && (uint32_t)_r.protocol[1] != _p.protocol)return 0;
	int mask = 32 - (uint32_t)_r.Smask;
	uint32_t rIp, pIp;
	memcpy(&rIp, _r.Sip, 4); memcpy(&pIp, _p.Sip, 4);
	if (mask != 32 && (rIp >> mask) != (pIp >> mask))return 0;
	mask = 32 - (uint32_t)_r.Dmask;
	memcpy(&rIp, _r.Dip, 4); memcpy(&pIp, _p.Dip, 4);
	if (mask != 32 && (rIp >> mask) != (pIp >> mask))return 0;
	if (_p.Sport < _r.Sport[0] || _p.Sport > _r.Sport[1])return 0;
	if (_p.Dport < _r.Dport[0] || _p.Dport > _r.Dport[1])return 0;
	return 1;
}

int simple_search(const vector<Rule>& rules, const Packet& _p)
{
	for (auto&& _r : rules) {
		if (_r.protocol[0] != 0 && (uint32_t)_r.protocol[1] != _p.protocol)continue;
		int mask = 32 - (uint32_t)_r.Smask;
		uint32_t rIp, pIp;
		memcpy(&rIp, _r.Sip, 4); memcpy(&pIp, _p.Sip, 4);
		if (mask != 32 && (rIp >> mask) != (pIp >> mask))continue;
		mask = 32 - (uint32_t)_r.Dmask;
		memcpy(&rIp, _r.Dip, 4); memcpy(&pIp, _p.Dip, 4);
		if (mask != 32 && (rIp >> mask) != (pIp >> mask))continue;
		if (_p.Sport < _r.Sport[0] || _p.Sport > _r.Sport[1])continue;
		if (_p.Dport < _r.Dport[0] || _p.Dport > _r.Dport[1])continue;
		return _r.pri;
	}
	return -1;
}

void PTtree::analyse_rules(const vector<Rule>& rules)
{
	char ip_name[8][6] = { "sip_1","sip_2","sip_3" ,"sip_4" ,"dip_1" ,"dip_2" ,"dip_3","dip_4" };
	double alpha[9];
	for (int i = 0; i < 9; ++i)alpha[i] = pow(2, i) / 511;

	FILE* fp = NULL;
	fp = fopen("ruleset_analyse.txt", "w");
	vector<vector<vector<int>>> counter;
	counter.resize(8);
	for (int i = 0; i < 8; ++i) {
		counter[i].resize(9);
		for (int j = 0; j < 9; ++j) {
			counter[i][j].resize((int)pow(2, j));
			for (auto& ele : counter[i][j])ele = 0;
		}
	}
	for (auto& _r : rules) {
		int k = 4;
		uint32_t mask = _r.Smask;
		for (int j = 0; j < 4; j++) {
			uint32_t value = _r.Sip[--k];
			int _m = maskHash[mask][j];
			value = value >> (8 - _m);
			++counter[j][_m][value];
		}
		k = 4;
		mask = _r.Dmask;
		for (int j = 4; j < 8; j++) {
			uint32_t value = _r.Dip[--k];
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

//void PTtree::get_mask_ip(int _type, const Rule& _r, uint32_t& _mask, uint32_t& _ip)
//{
//	switch (_type)
//	{
//	case 0:
//		_mask = maskHash[(uint32_t)_r.Smask][0];
//		_ip = (uint32_t)_r.Sip[3];
//		break;
//	case 1:
//		_mask = maskHash[(uint32_t)_r.Smask][1];
//		_ip = (uint32_t)_r.Sip[2];
//		break;
//	case 2:
//		_mask = maskHash[(uint32_t)_r.Smask][2];
//		_ip = (uint32_t)_r.Sip[1];
//		break;
//	case 3:
//		_mask = maskHash[(uint32_t)_r.Smask][3];
//		_ip = (uint32_t)_r.Sip[0];
//		break;
//	case 4:
//		_mask = maskHash[(uint32_t)_r.Dmask][0];
//		_ip = (uint32_t)_r.Dip[3];
//		break;
//	case 5:
//		_mask = maskHash[(uint32_t)_r.Dmask][1];
//		_ip = (uint32_t)_r.Dip[2];
//		break;
//	case 6:
//		_mask = maskHash[(uint32_t)_r.Dmask][2];
//		_ip = (uint32_t)_r.Dip[1];
//		break;
//	case 7:
//		_mask = maskHash[(uint32_t)_r.Dmask][3];
//		_ip = (uint32_t)_r.Dip[0];
//		break;
//	default:
//		break;
//	}
//}

PTtree::PTtree(vector<int>& list, int a, int b) : layerFields(list), pTree(NULL), aTree(NULL), totalNodes(0), portField(a), portStep(b) {}

void PTtree::insert(const Rule& _r)
{
	if (_r.Smask < 4 && _r.Dmask < 4) { //inser in assit tree
		if (aTree == NULL) {
			aTree = new ProtoNode();
			++totalNodes;
		}
		int proto = _r.protocol[1];  // 0 is wildcard
		int proto_idx = aTree->table[proto];
		int lport_idx, hport_idx;
		if (portField == 0) { lport_idx = _r.Sport[0] / portStep; hport_idx = _r.Sport[1] / portStep; }
		else { lport_idx = _r.Dport[0] / portStep; hport_idx = _r.Dport[1] / portStep; }

		// simple
		/*if (proto_idx == -1) {
			aTree->table[proto] = aTree->child.size();
			PortNode_static* pnode = new PortNode_static();
			aTree->child.emplace_back(pair<uint32_t, void*>(_r.pri, pnode));
			if (lport_idx == hport_idx)pnode->table[lport_idx] = 0;
			else pnode->table[pnode->table.size() - 1] = 0;
			LeafNode* lnode = new LeafNode();
			pnode->child.emplace_back(pair<uint32_t, LeafNode*>(_r.pri, lnode));
			lnode->rules.emplace_back(_r);
			aLeafNodesList.emplace_back(lnode);
		}
		else {
			PortNode_static* pnode = (PortNode_static*)aTree->child[proto_idx].second;
			if (_r.pri < aTree->child[proto_idx].first)aTree->child[proto_idx].first = _r.pri;
			short* port_idx;
			if (lport_idx == hport_idx)port_idx = &pnode->table[lport_idx];
			else port_idx = &pnode->table[pnode->table.size() - 1];
			if (*port_idx == -1) {
				*port_idx = pnode->child.size();
				LeafNode* lnode = new LeafNode();
				aLeafNodesList.emplace_back(lnode);
				lnode->rules.emplace_back(_r);
				pnode->child.emplace_back(pair<uint32_t, LeafNode*>(_r.pri, lnode));
			}
			else {
				if (_r.pri < pnode->child[*port_idx].first)pnode->child[*port_idx].first = _r.pri;
				LeafNode* lnode = pnode->child[*port_idx].second;
				lnode->rules.emplace_back(_r);
			}
		}*/

		// test
		PortNode_static* pnode = NULL;
		LeafNode* lnode = NULL;
		uint32_t port_idx, leaf_idx;

		if (proto_idx == -1) { // creat portnode
			aTree->table[proto] = aTree->child.size();
			pnode = new PortNode_static();
			aTree->child.emplace_back(pair<uint32_t, PortNode_static*>(_r.pri, pnode));
			++totalNodes;
		}
		else {
			pnode = aTree->child[proto_idx].second;
			if (_r.pri < aTree->child[proto].first)aTree->child[proto].first = _r.pri;
		}
		if (lport_idx == hport_idx)port_idx = lport_idx;
		else port_idx = 32768;
		leaf_idx = pnode->table[port_idx];
		if (leaf_idx == -1) {  // creat leafnode
			pnode->table[port_idx] = pnode->child.size();
			lnode = new LeafNode();
			pnode->child.emplace_back(pair<uint32_t, LeafNode*>(_r.pri, lnode));
			aLeafNodesList.emplace_back(lnode);
			++totalNodes;
		}
		else {
			if (_r.pri < pnode->child[leaf_idx].first)pnode->child[leaf_idx].first = _r.pri;
			lnode = pnode->child[leaf_idx].second;
		}
		lnode->rules.emplace_back(_r);
	}
	else { // insert in pt_tree
		switch (layerFields.size())
		{
		case 3: {
			if (pTree == NULL) {
				pTree = new IpNode_static(0, 0, layerFields[0], 0);
				IpNodesList.emplace_back(pTree);
				++totalNodes;
			}
			IpNode_static* node = (IpNode_static*)pTree;
			int layer = 0;
			uint32_t mask, ip;
			while (layer < 2) {
				switch (node->field)
				{
				case 0:
					mask = maskHash[(uint32_t)_r.Smask][0];
					ip = (uint32_t)_r.Sip[3];
					break;
				case 1:
					mask = maskHash[(uint32_t)_r.Smask][1];
					ip = (uint32_t)_r.Sip[2];
					break;
				case 2:
					mask = maskHash[(uint32_t)_r.Smask][2];
					ip = (uint32_t)_r.Sip[1];
					break;
				case 3:
					mask = maskHash[(uint32_t)_r.Smask][3];
					ip = (uint32_t)_r.Sip[0];
					break;
				case 4:
					mask = maskHash[(uint32_t)_r.Dmask][0];
					ip = (uint32_t)_r.Dip[3];
					break;
				case 5:
					mask = maskHash[(uint32_t)_r.Dmask][1];
					ip = (uint32_t)_r.Dip[2];
					break;
				case 6:
					mask = maskHash[(uint32_t)_r.Dmask][2];
					ip = (uint32_t)_r.Dip[1];
					break;
				case 7:
					mask = maskHash[(uint32_t)_r.Dmask][3];
					ip = (uint32_t)_r.Dip[0];
					break;
				default:
					break;
				}
				int ip_idx = mask == 8 ? ip : 256;
				if (node->child[ip_idx].pointer == NULL) { //create ipnode
					IpNode_static* newchild = new IpNode_static(layer + 1, IpNodesList.size(), layerFields[layer + 1], 0);
					node->child[ip_idx].pointer = newchild;
					node->child[ip_idx].pri = _r.pri;
					IpNodesList.emplace_back(newchild);
					++totalNodes;
					node = newchild;
				}
				else {
					if (_r.pri < node->child[ip_idx].pri)node->child[ip_idx].pri = _r.pri;
					node = (IpNode_static*)node->child[ip_idx].pointer;
				}
				++layer;
			}
			// process leafnode
			node->cType = 1;
			switch (node->field)
			{
			case 0:
				mask = maskHash[(uint32_t)_r.Smask][0];
				ip = (uint32_t)_r.Sip[3];
				break;
			case 1:
				mask = maskHash[(uint32_t)_r.Smask][1];
				ip = (uint32_t)_r.Sip[2];
				break;
			case 2:
				mask = maskHash[(uint32_t)_r.Smask][2];
				ip = (uint32_t)_r.Sip[1];
				break;
			case 3:
				mask = maskHash[(uint32_t)_r.Smask][3];
				ip = (uint32_t)_r.Sip[0];
				break;
			case 4:
				mask = maskHash[(uint32_t)_r.Dmask][0];
				ip = (uint32_t)_r.Dip[3];
				break;
			case 5:
				mask = maskHash[(uint32_t)_r.Dmask][1];
				ip = (uint32_t)_r.Dip[2];
				break;
			case 6:
				mask = maskHash[(uint32_t)_r.Dmask][2];
				ip = (uint32_t)_r.Dip[1];
				break;
			case 7:
				mask = maskHash[(uint32_t)_r.Dmask][3];
				ip = (uint32_t)_r.Dip[0];
				break;
			default:
				break;
			}
			int ip_idx = mask == 8 ? ip : 256;
			if (node->child[ip_idx].pointer == NULL) { //create leafnode
				LeafNode* newchild = new LeafNode();
				node->child[ip_idx].pointer = newchild;
				node->child[ip_idx].pri = _r.pri;
				newchild->rules.emplace_back(_r);
				ptLeafNodesList.emplace_back(newchild);
				++totalNodes;
			}
			else {
				if (_r.pri < node->child[ip_idx].pri)node->child[ip_idx].pri = _r.pri;
				LeafNode* lnode = (LeafNode*)node->child[ip_idx].pointer;
				lnode->rules.emplace_back(_r);
			}
			break;
		}
		default:
			break;
		}
	}
}

int PTtree::search(const Packet& _p)
{
	uint32_t mask, ip;
	uint32_t pSip, pDip;
	uint32_t pProtocol;
	uint16_t pSport, pDport;
	pProtocol = _p.protocol;
	memcpy(&pSip, _p.Sip, 4);
	memcpy(&pDip, _p.Dip, 4);
	pSport = _p.Sport;
	pDport = _p.Dport;
	uint32_t res = 0xFFFFFFFF;

	vector<uint32_t> pIp;
	for (auto cType : layerFields) {
		switch (cType)
		{
		case 0:
			pIp.emplace_back((uint32_t)_p.Sip[3]);
			break;
		case 1:
			pIp.emplace_back((uint32_t)_p.Sip[2]);
			break;
		case 2:
			pIp.emplace_back((uint32_t)_p.Sip[1]);
			break;
		case 3:
			pIp.emplace_back((uint32_t)_p.Sip[0]);
			break;
		case 4:
			pIp.emplace_back((uint32_t)_p.Dip[3]);
			break;
		case 5:
			pIp.emplace_back((uint32_t)_p.Dip[2]);
			break;
		case 6:
			pIp.emplace_back((uint32_t)_p.Dip[1]);
			break;
		case 7:
			pIp.emplace_back((uint32_t)_p.Dip[0]);
			break;
		default:
			break;
		}
	}

	// process pt_tree
	if (pTree != NULL) {
		switch (layerFields.size())
		{
		case 3: {
			IpNode_static* node_1 = (IpNode_static*)pTree;
			uint32_t i_1[2] = { pIp[0], 256 };
			for (int i = 0; i < 2; ++i) {
				if (node_1->child[i_1[i]].pointer == NULL || node_1->child[i_1[i]].pri > res)continue;
				IpNode_static* node_2 = (IpNode_static*)node_1->child[i_1[i]].pointer;
				uint32_t i_2[2] = { pIp[1], 256 };
				for (int j = 0; j < 2; ++j) {
					if (node_2->child[i_2[j]].pointer == NULL || node_2->child[i_2[j]].pri > res)continue;
					IpNode_static* node_3 = (IpNode_static*)node_2->child[i_2[j]].pointer;
					uint32_t i_3[2] = { pIp[2], 256 };
					for (int k = 0; k < 2; ++k) {
						if (node_3->child[i_3[k]].pointer == NULL || node_3->child[i_3[k]].pri > res)continue;
						LeafNode* ln = (LeafNode*)node_3->child[i_3[k]].pointer;
						for (auto&& r : ln->rules) {
							if (res < r.pri)break;
							if (pProtocol != r.protocol[1] && r.protocol[0] != 0)continue; // check protocol
							if (pDport < r.Dport[0] || r.Dport[1] < pDport)continue;  // if destination port not match, check next
							if (pSport < r.Sport[0] || r.Sport[1] < pSport)continue;  // if source port not match, check next
							uint32_t m_bit = 32 - (uint32_t)r.Dmask;  // comput the bit number need to move
							uint32_t _ip;
							if (m_bit != 32) {
								memcpy(&_ip, r.Dip, 4);
								if (pDip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next
							}
							m_bit = 32 - (uint32_t)r.Smask;  // comput the bit number need to move
							if (m_bit != 32) {
								memcpy(&_ip, r.Sip, 4);
								if (pSip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next
							}
							res = r.pri;
							break;
						}
					}
				}
			}
			break;
		}
		default:
			break;
		}
	}

	// process a_tree
	if (aTree != NULL) {
		int proto_idx[2] = { pProtocol,0 };
		int port_idx[2], c_idx;
		for (int i = 0; i < 2; ++i) {
			c_idx = aTree->table[proto_idx[i]];
			if (c_idx != -1 && res > aTree->child[c_idx].first) {
				PortNode_static* pnode = aTree->child[c_idx].second;
				if (portField == 0) port_idx[0] = pnode->table[pSport / portStep];
				else port_idx[0] = pnode->table[pDport / portStep];
				port_idx[1] = pnode->table[32768];
				for (int j = 0; j < 2; ++j) {
					c_idx = port_idx[j];
					if (c_idx != -1 && res > pnode->child[c_idx].first) {
						LeafNode* ln = pnode->child[c_idx].second;
						for (auto&& r : ln->rules) {
							if (res < r.pri)break;
							if (pDport < r.Dport[0] || r.Dport[1] < pDport)continue;  // if destination port not match, check next
							if (pSport < r.Sport[0] || r.Sport[1] < pSport)continue;  // if source port not match, check next
							uint32_t m_bit = 32 - (uint32_t)r.Dmask;  // comput the bit number need to move
							uint32_t _ip;
							if (m_bit != 32) {
								memcpy(&_ip, r.Dip, 4);
								if (pDip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next
							}
							m_bit = 32 - (uint32_t)r.Smask;  // comput the bit number need to move
							if (m_bit != 32) {
								memcpy(&_ip, r.Sip, 4);
								if (pSip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next
							}
							res = r.pri;
							break;
						}
					}
				}
			}
		}
	}

	return res;
}
