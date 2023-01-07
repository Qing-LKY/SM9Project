#pragma once

#include "SM9.h"
#include "MasterKeyPair.h"

#include <string>

using namespace std;

extern "C"
{
#include "miracl.h"
#include "mirdef.h"
}

class SM9_KGC : public SM9 {
public:
	SM9_KGC() {};
	~SM9_KGC() {};

public:
	static MasterKeyPair genSignMasterKeyPair();
	static MasterKeyPair genSignMasterKeyPairFromPri(const string& masterPrivateK);
	static string genSignPrivateKey(const string& masterPrivateK, const string& id);

	static MasterKeyPair genEncMasterKeyPair();
	static MasterKeyPair genEncMasterKeyPairFromPri(const string& masterPrivateK);
	static string genEncPrivateKey(const string& masterPrivateK, const string& id);

private:
	/**
	* ��G1������˽Կʱ����t_1��
	*
	* @param var		t_1
	* @param ke			˽Կ
	* @param id			�û���ʶ
	* @param hid		˽Կ���ɺ���ʶ���
	*
	* @return			true : ����t_1��Ϊ0�� false : ����t_1Ϊ0��
	* @note		���t1Ϊ0����KGC��Ҫ���²���ǩ�����������Կ�ԣ������������û���ǩ�������˽Կ��
	*/
	static bool calcT1(big& var, big& ke, const string& id, int hid);

	/**
	* ��G1������˽Կʱ����t_2��
	*
	* @param masterPrivateK	ǩ����˽Կ
	* @param id				�û���ʶ
	* @param hid			˽Կ���ɺ���ʶ���
	*
	* @return				t_1��Ϊ0ʱ����t_2��t_1Ϊ0ʱ���ؿա�
	* @note		���t1Ϊ0����KGC��Ҫ���²���ǩ�����������Կ�ԣ������������û���ǩ�������˽Կ��
	*/
	static string calcT2(const string& masterPrivateK, const string& id, int hid);
};