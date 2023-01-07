#include "KGC_main.h"

#include "SM9.h"
#include "SM9_KGC.h"
#include "SM9_Parameters.h"
#include "MasterKeyPair.h"
#include "Signature.h"

#include "../SM9Proj/utils/YHex.h"

#include <string>
#include <map>
#include <vector>
#include <set>
#include <algorithm>

#include <cstdio>
#include <malloc.h>
#include <cstdlib>
#include <ctime>

using namespace std;

char KGC_main::SAVE_FILE[] = "state.dat";
int KGC_main::MAGIC_NUMBER = 0xAF02022;

set<string> KGC_main::Users;
string KGC_main::current_uid;
int KGC_main::magic_tag;

string KGC_main::sign_pub;
string KGC_main::sign_ke;

string KGC_main::enc_pub;
string KGC_main::enc_ke;

KGC_main::KGC_main()
{
}

KGC_main::~KGC_main()
{
}

void KGC_main::initState()
{
	MasterKeyPair tmp;
	Users.clear();
	
	tmp = SM9_KGC::genSignMasterKeyPair();
	sign_pub = tmp.getPublicKey();
	sign_ke = tmp.getPrivateKey();
	
	tmp = SM9_KGC::genEncMasterKeyPair();
	enc_pub = tmp.getPublicKey();
	enc_ke = tmp.getPrivateKey();

	magic_tag = 1;
	current_uid.assign("root");
	Users.insert(current_uid);
	
	reloadEncKeys();
	reloadSignKeys();
}

#define DEBUG_LOAD

bool KGC_main::loadState()
{
	int t;
	FILE* fp;
	int n, len, mxlen;
	char* buf;
	string tmp;
	MasterKeyPair mainKey;

	fopen_s(&fp, SAVE_FILE, "r");
	if (fp == NULL) return false; // ���ļ�ʧ��

	fread(&len, sizeof(int), 1, fp);
	if (len != MAGIC_NUMBER) return fclose(fp), false; // �ļ����ܱ��ƻ���
	
	// ��ȡ tag
	fread(&magic_tag, sizeof(int), 1, fp);

	// ��ȡ mxlen
	fread(&mxlen, sizeof(int), 1, fp);
	mxlen++;
	if (mxlen > 100000)
	{
		// puts("Error when loadState: too large!");
		fclose(fp);
		return false;
	}
	buf = (char*)malloc(mxlen);
	if (buf == NULL) return fclose(fp), false; // failed malloc

	// ��ȡǩ����˽Կ
	fread(&len, sizeof(int), 1, fp);
	if (len > mxlen) return fclose(fp), false; // sth broken
	fread(buf, sizeof(char), len, fp);
	tmp.assign(buf, buf + len);
	// ����ǩ������Կ��
	mainKey = SM9_KGC::genSignMasterKeyPairFromPri(tmp); 
	sign_pub = mainKey.getPublicKey();
	sign_ke = mainKey.getPrivateKey();
	
	// ��ȡ��������Կ
	fread(&len, sizeof(int), 1, fp);
	if (len > mxlen) return fclose(fp), false; // sth broken
	fread(buf, sizeof(char), len, fp);
	tmp.assign(buf, buf + len);
	// ���ɼ�������Կ��
	mainKey = SM9_KGC::genEncMasterKeyPairFromPri(tmp);
	sign_pub = mainKey.getPublicKey();
	sign_ke = mainKey.getPrivateKey();

	// ��ȡ����
	fread(&n, sizeof(int), 1, fp);
	while (n--) 
	{
		// ���� uid
		fread(&len, sizeof(int), 1, fp);
		if (len > mxlen) return fclose(fp), false; // sth broken
		fread(buf, sizeof(char), len, fp);
		tmp.assign(buf, buf + len);
		Users.insert(tmp);
	}

	// ��ȡ��ǰ�û�
	fread(&len, sizeof(int), 1, fp);
	if (len > mxlen) return fclose(fp), false; // sth broken
	fread(buf, sizeof(char), len, fp);
	current_uid.assign(buf, buf + len);

	fread(&len, sizeof(int), 1, fp);
	if (len != MAGIC_NUMBER) return fclose(fp), false; // �ļ����ܱ��ƻ���

	free(buf);
	fclose(fp);
	return true;
}

bool KGC_main::saveState()
{
	FILE* fp;
	int len, mxlen;
	string prik;

	fopen_s(&fp, SAVE_FILE, "wb");
	if (fp == NULL) return false; // �����ļ�ʧ��

	fwrite(&MAGIC_NUMBER, sizeof(int), 1, fp);

	// ���� tag
	fwrite(&magic_tag, sizeof(int), 1, fp);

	// ���� mxlen
	mxlen = 0;
	mxlen = max(mxlen, (int)sign_ke.length());
	mxlen = max(mxlen, (int)enc_ke.length());
	for (auto uid : Users) mxlen = max(mxlen, (int)uid.length());
	fwrite(&mxlen, sizeof(int), 1, fp);

	// ���� sign_ke
	prik = sign_ke;
	len = prik.length();
	fwrite(&len, sizeof(int), 1, fp);
	fwrite(prik.c_str(), sizeof(char), len, fp);

	// ���� enc_ke
	prik = enc_ke;
	len = prik.length();
	fwrite(&len, sizeof(int), 1, fp);
	fwrite(prik.c_str(), sizeof(char), len, fp);
	
	// �����û�
	len = Users.size();
	fwrite(&len, sizeof(int), 1, fp);
	for (auto uid : Users) 
	{
		len = uid.length();
		fwrite(&len, sizeof(int), 1, fp);
		fwrite(uid.c_str(), sizeof(char), len, fp);
	}

	// ���浱ǰ�û�
	len = current_uid.size();
	fwrite(&len, sizeof(int), 1, fp);
	fwrite(current_uid.c_str(), sizeof(char), len, fp);

	fwrite(&MAGIC_NUMBER, sizeof(int), 1, fp);
	
	fclose(fp);
	return true;
}

bool KGC_main::checkSignKeys()
{
	string tmp;
	for (auto uid : Users)
	{
		tmp = SM9_KGC::genSignPrivateKey(sign_ke, uid);
		if (tmp.empty()) return false;
	}
	return true;
}

bool KGC_main::checkEncKeys()
{
	string tmp;
	for (auto uid : Users)
	{
		tmp = SM9_KGC::genEncPrivateKey(enc_ke, uid);
		if (tmp.empty()) return false;
	}
	return true;
}

bool KGC_main::reloadSignKeys()
{
	bool happen = 0;
	MasterKeyPair mainKey;
	while (!checkSignKeys())
	{
		magic_tag++;
		mainKey = SM9_KGC::genSignMasterKeyPair();
		sign_pub = mainKey.getPublicKey();
		sign_ke = mainKey.getPrivateKey();
		happen = 1;
	}
	if (happen)
	{
		puts("Warning: key reloads. Signature and Enc file generate before has been aborted!");
	}
	return true;
}

bool KGC_main::reloadEncKeys()
{
	bool happen = 0;
	MasterKeyPair mainKey;
	while (!checkEncKeys())
	{
		magic_tag++;
		mainKey = SM9_KGC::genEncMasterKeyPair();
		enc_pub = mainKey.getPublicKey();
		enc_ke = mainKey.getPrivateKey();
		happen = 1;
	}
	if (happen)
	{
		puts("Warning: key reloads. Signature and Enc file generate before has been aborted!");
	}
	return true;
}

void KGC_main::KGC_Boot()
{
	// ��ʼ�� SM9 ��׼����
	puts("Init system...");
	SM9::init();
	// �����ϴε�״̬
	puts("Auto loading...");
	if (loadState()) 
	{
		puts("Auto load success!");
	}
	else 
	{
		puts("Auto load failed. Reset the system...");
		initState();
	}
	return;
}

bool KGC_main::createUser(const string& uid)
{
	// �û�����
	if (Users.find(uid) != Users.end()) return false; // exist
	Users.insert(uid);
	reloadEncKeys();
	reloadSignKeys();
	return true;
}

bool KGC_main::switchUser(const string& uid)
{
	// �û��л�
	if (Users.find(uid) == Users.end()) return false; // not found
	current_uid = uid;
	return true;
}

string KGC_main::getSignPriKey()
{
	string uid, prik;
	uid = current_uid;
	prik = SM9_KGC::genSignPrivateKey(sign_ke, uid);
	return prik;
}

string KGC_main::getEncPriKey()
{
	string uid, prik;
	uid = current_uid;
	prik = SM9_KGC::genEncPrivateKey(enc_ke, uid);
	return prik;
}

string KGC_main::getSignPriKey(const string& uid) // use for debug
{
	string prik;
	prik = SM9_KGC::genSignPrivateKey(sign_ke, uid);
	if (prik.empty())
	{
		puts("Uid fits bad, system key reload!");
		reloadSignKeys();
		prik = SM9_KGC::genSignPrivateKey(sign_ke, uid);
	}
	return prik;
}

string KGC_main::getEncPriKey(const string& uid) // use for debug
{
	string prik;
	prik = SM9_KGC::genEncPrivateKey(enc_ke, uid);
	if (prik.empty())
	{
		puts("Uid fits bad, system key reload!");
		reloadEncKeys();
		prik = SM9_KGC::genEncPrivateKey(enc_ke, uid);
	}
	return prik;
}

Signature KGC_main::sign(const string& msg)
{
	Signature sig;
	sig = SM9::sign(sign_pub, getSignPriKey(), msg);
	return sig;
}

Signature KGC_main::sign(const string& msg, const string& uid)
{
	Signature sig;
	sig = SM9::sign(sign_pub, getSignPriKey(uid), msg);
	return sig;
}

bool KGC_main::verify(const string& uid, Signature sig, const string& msg)
{
	return SM9::verify(sign_pub, uid, sig, msg);
}

string KGC_main::encrypt(const string& uid, const string& msg)
{
	return SM9::encrypt(enc_pub, uid, msg);
}

string KGC_main::decrypt(const string& cipher)
{
	return SM9::decrypt(cipher, current_uid, getEncPriKey());
}

string KGC_main::decrypt(const string& cipher, const string& uid)
{
	return SM9::decrypt(cipher, uid, getEncPriKey(uid));
}

bool KGC_main::haveUser(const string& uid)
{
	return Users.find(uid) != Users.end();
}