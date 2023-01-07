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
	static void KGC_Boot(); // 启动 KGC，执行初始化和例行检查
	static bool switchUser(const string& uid); // 切换当前用户
	static bool createUser(const string& uid); // 创建新用户
	static bool loadState();
	static bool saveState();
	static bool haveUser(const string& uid);

	static Signature sign(const string& msg); // 当前用户对 msg 签名
	static bool verify(const string& uid, Signature sig, const string& msg); // 验证 uid 的签名

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

	static int magic_tag;  // 用来标定 KGC 的版本

private:
	static char SAVE_FILE[];
	static int MAGIC_NUMBER;
	static string sign_ke;
	static string enc_ke;
};