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

	static Signature sign(const string& msg); // ��ǰ�û��� msg ǩ��
	static bool verify(const string &uid, Signature sig, const string &msg); // ��֤ uid ��ǩ��


private:
	static void initState();
	static bool reloadKeys();
	static bool checkKeys();
	static string getPriKey();
	static string getPriKey(const string& uid);

public:
	static set<string> Users;
	static string current_uid;
	static MasterKeyPair mainKey;
	static int magic_tag;  // �����궨 KGC �İ汾

private:
	static char SAVE_FILE[];
	static int MAGIC_NUMBER;
};