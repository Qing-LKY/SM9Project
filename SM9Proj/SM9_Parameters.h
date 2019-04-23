#pragma once

#include <string>
using namespace std;

#define BIG_LEN 2000

extern "C"
{
#include "miracl.h"
#include "mirdef.h"
}

/**
* SM9��������ʼ�����ͷ�
* @author YUAN
*/
class ParamSM9 {

private:
	ParamSM9();
	~ParamSM9();

public:
	/**
	* ��Բ������Ⱥ�ϵ����֤
	* �ο��㷨�ĵ���һ���֣�������3.5
	* @param var ��Ҫ��֤�ĵ�
	*/
	static bool isPointOnG1(epoint* var);

public:
	static big param_a;
	static big param_b;
	static big param_N;
	static big param_q;
	static big param_t;
	
	static epoint* param_P1;
	static ecn2 param_P2;
	static zzn2 norm_X;
	static miracl* mMip;

public:
	// ��ʼ�����ͷź���
	static bool init();
	static void release();
	
};