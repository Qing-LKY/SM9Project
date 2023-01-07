#pragma once

#include <string>
#include <map>
#include <vector>
#include <set>

#include <cstdio>

#include "MasterKeyPair.h"
#include "Signature.h"

using namespace std;

class KGC_main {
public:
	KGC_main();
	~KGC_main();
public:
	static void KGC_Boot(); // ���� KGC��ִ�г�ʼ�������м��
	static bool switchUser(const string& uid); // �л���ǰ�û�
	static bool createUser(const string& uid); // �������û�
	static bool loadState();
	static bool saveState();
	static bool haveUser(const string& uid);

	static Signature sign(const string& msg); // ��ǰ�û��� msg ǩ��
	static bool verify(const string& uid, Signature sig, const string& msg); // ��֤ uid ��ǩ��

	static string encrypt(const string& uid, const string& msg);
	static string decrypt(const string& cipher);

	// Use for debug and test
	static Signature sign(const string& msg, const string& uid);
	static string decrypt(const string& cipher, const string& uid);

private:
	static void initState();
	static bool checkSignKeys();
	static bool checkEncKeys();
	static string getSignPriKey();
	static string getEncPriKey();
	static string getSignPriKey(const string& uid);
	static string getEncPriKey(const string& uid);
	static bool reloadSignKeys();
	static bool reloadEncKeys();

public:
	static set<string> Users;
	static string current_uid;
	static string sign_pub;
	static string enc_pub;

	static int magic_tag;  // �����궨 KGC �İ汾

private:
	static char SAVE_FILE[];
	static int MAGIC_NUMBER;
	static string sign_ke;
	static string enc_ke;
};