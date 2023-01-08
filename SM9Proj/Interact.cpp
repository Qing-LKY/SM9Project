#include "Interact.h"
#include "KGC_main.h"
#include "Signature.h"

#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>
#include <fstream>

#include "utils/YHex.h"
#include "utils/QFile.h"

using namespace std;

//#define INTERACT_DEBUG

Interact::Interact()
{
}

Interact::~Interact()
{
}

const int SHELL_WIDTH = 82;
const int PAR = 10;

const int BUF_SIZE = 1 << 14;
char Interact::buf[BUF_SIZE + 1];

void Interact::cutline(char c, int len)
{
	while (len--) putchar(c);
	puts("");
}

// 居中输出一行 不能超过 SHELL_WIDTH-2
void Interact::puts_middle(const char* s, char c)
{
	int n = strlen(s);
	int l, r;
	l = (SHELL_WIDTH - 2 - n) >> 1;
	r = SHELL_WIDTH - 2 - n - l;
	putchar(c);
	while (l--) putchar(' ');
	while (n--) putchar(*s++);
	while (r--) putchar(' ');
	putchar(c);
	puts("");
}

// 输出一个段落
// 段落从第 12 格开始，换行后从 10 格开始，并留出 10 格的空位
void Interact::puts_para(const char* s, char c)
{
	int n = strlen(s), len = SHELL_WIDTH - 2 - PAR * 2;
	// 第一行 SHELL_WIDTH-22 个字符
	for (int i = 1; *s; i++) 
	{
		putchar(c);
		int L, p, m = 0;
		L = i == 1 ? len - 2 : len;
		p = i == 1 ? PAR + 2 : PAR;
		while (p--) putchar(' ');
		while (L > 0 && *s != 0)
		{
			if (m == 0 && *s != ' ')
			{
				m = 0;
				while (*(s + m) != ' ' && *(s + m) != 0) m++;
				if (m > L) break;
			}
			putchar(*s++);
			L--;
			if (m > 0) m--;
		}
		p = PAR + L;
		while (p--) putchar(' ');
		putchar(c);
		puts("");
	}
}

void Interact::welcome()
{
	const char c = '#';
	cutline(c, SHELL_WIDTH);
	puts_middle(" ", c);
	puts_middle("***************************************", c);
	puts_middle("* Welcome to Security Mail Generator! *", c);
	puts_middle("***************************************", c);
	puts_middle(" ", c);
	puts_para("This is a digit signature system base on SM9. "
		"Register identity of you and your friends (such as email address) to our system, "
		"and we will be able to generate a signature for your message, "
		"and others can verify this through us."
		, c);
	puts_para("Even more, we provide a tool to encrypt your message text with your friend's uid, "
		"and the cipher can be decrypted by your friend through us!"
	, c);
	puts_para("Types `help' for more infomation", c);
	puts_middle(" ", c);
	cutline(c, SHELL_WIDTH);
	puts("");
}

string Interact::readline(const char* s)
{
	string r;
	printf(s);
	getline(cin, r);
	fflush(stdin);
	return r;
}

string Interact::wait_input()
{
	cout << "[" << KGC_main::magic_tag << "] " << KGC_main::current_uid << "$ ";
	string s;
	getline(cin, s);
	fflush(stdin);
	return s;
}

void Interact::do_help()
{
	puts("Supports following commands:");
	puts(" help  ---  to show this infomation");
	puts(" ls    ---  to list all registered uid");
	puts(" reg   ---  to start a register transaction");
	puts("            this will add a new uid to our system");
	puts(" su    ---  to switch current uid");
	puts(" sig   ---  to start a signature transaction");
	puts("            this will generate a msg text with your signature");
	puts(" ver   ---  to start a verify transaction");
	puts("            this will read the safe mail and verify it");
	puts(" save  ---  to save KGC state");
	puts(" enc   ---  to encrypt with an exist id");
	puts(" dec   ---  to decrypt with your id");
	puts(" exit  ---  to exit our system");
	
	puts("");
}

void Interact::do_ls()
{
	cout << "Total: " << KGC_main::Users.size() << endl;
	for (auto uid : KGC_main::Users)
	{
		cout << uid << "  ";
	}
	cout << endl;
	puts("");
}

void Interact::do_reg()
{
	string s;
	cout << "Input the uid you want to regster:" << endl;
	cout << "[e.g. qinglkyi]: ";
	getline(cin, s); 
	fflush(stdin);
	if (!KGC_main::createUser(s))
	{
		cout << "Error: " << s << " has been registered before!" << endl;
	}
	else
	{
		cout << "Success: " << s << " has been registered!" << endl;
	}
	puts("");
}

void Interact::do_su()
{
	string s;
	cout << "Input the uid you want to switch:" << endl;
	cout << "[e.g. qinglkyi]: ";
	getline(cin, s);
	fflush(stdin);
	if (!KGC_main::switchUser(s))
	{
		cout << "Error: " << s << " isn't registered! Type `reg' to start registering!" << endl;
	}
	else
	{
		cout << "Success! Welcome back, " << s << "!" << endl;
	}
	puts("");
}

void Interact::do_save()
{
	if (!KGC_main::saveState()) puts("Error: Failed to save state!");
	else puts("Successfully saved!");
	puts("");
}

void Interact::do_sig()
{
	int tmp;
	string fname, msg, text;
	Signature sig;

	puts("Input the text file you want to sign:");
	fname = readline("[e.g. mail.txt]: ");
	
	// get msg
	msg = QFile::get_file_content(fname);
	if (msg.empty()) goto END;

	// get signature
	sig = KGC_main::sign(msg);

#ifdef INTERACT_DEBUG
	cout << "debug info:" << endl;
	cout << YHex::Encode(sig.getH()) << endl;
	cout << YHex::Encode(sig.getS()) << endl;
	cout << KGC_main::current_uid << endl;
	cout << msg << endl;
	cout << msg.length() << endl;
#endif

	// generate signing txt
	fname += ".signed";
	text = QFile::gen_signed_text(msg, sig, KGC_main::current_uid);
	QFile::generate_file(fname, text);

END:
	puts("");
}

void Interact::do_ver()
{
	int tmp;
	string fname;
	FILE* fp;
	Signature sig;
	unsigned int pH, lH, pS, lS, pU, lU, pM, lM;
	string H, S, uid, msg;

	puts("Input the text file you want to verify:");
	fname = readline("[e.g. mail.signed]: ");

	fopen_s(&fp, fname.c_str(), "r");
	if (fp == NULL)
	{
		puts("Error: Failed to open file!");
		return;
	}
	tmp = fread(buf, 1, QFile::HEAD_LEN, fp);
	if (tmp != QFile::HEAD_LEN)
	{
		fclose(fp);
		puts("Error: Wrong format of signed file!");
		return;
	}
	
	tmp = sscanf_s(buf,
		".hd %d %d %d %d %d %d %d %d\n",
		&pH, &lH, &pS, &lS, &pU, &lU, &pM, &lM);
	if (tmp != 8)
	{
		fclose(fp);
		puts("Error: Wrong format of signed file!");
		return;
	}

#ifdef INTERACT_DEBUG
	printf(".hd %d %d %d %d %d %d %d %d\n", pH, lH, pS, lS, pU, lU, pM, lM);
#endif

	// get H S uid msg
	H = YHex::Decode(QFile::get_string_from_file(fp, pH, lH));
	S = YHex::Decode(QFile::get_string_from_file(fp, pS, lS));
	uid = QFile::get_string_from_file(fp, pU, lU);
	msg = QFile::get_string_from_file(fp, pM, lM);

#ifdef INTERACT_DEBUG
	cout << "debug info:" << endl;
	cout << YHex::Encode(H) << endl;
	cout << YHex::Encode(S) << endl;
	cout << uid << endl;
	cout << msg << endl;
	cout << msg.length() << endl;
#endif

	sig = Signature(H, S);

	tmp = KGC_main::verify(uid, sig, msg);

	if (tmp)
	{
		cout << "Verify successfully! It's signed by " << uid << "!" << endl;
	}
	else
	{
		cout << "Oops! It seems not verified!" << endl;
	}

	puts("");
	fclose(fp);
}

void Interact::do_dec()
{
	string fname;
	string msg, uid, cipher, text;
	int tmp;

	puts("Input the text file you want to decrypt:");
	fname = readline("[default: a.txt.enc]: ");

	if (fname == "") fname = "a.txt.enc";

	// get message
	text = QFile::get_file_content(fname);
	if (text.empty()) goto END;

	cipher = YHex::Decode(text);

	// decrypt
	msg = KGC_main::decrypt(cipher, KGC_main::current_uid);

#ifdef INTERACT_DEBUG
	cout << "Text:" << endl;
	cout << text << endl;
	cout << "Cipher len: " << cipher.length() << endl;
	cout << "Message len: " << msg.length() << endl;
	cout << "Message:" << endl;
	cout << msg << endl;
#endif
	
	if (msg.empty())
	{
		cout << "Wrong key!" << endl;
	}
	else
	{
		cout << "Success! Get:" << endl;
		cout << msg << endl;
	}

END:
	puts("");
	return;
}

void Interact::do_enc()
{
	string fname;
	string msg, uid, cipher, text;
	int tmp;

	puts("Input the text file you want to encrypt:");
	fname = readline("[default: a.txt]: ");

	if (fname == "") fname = "a.txt";

	puts("Input the target you want to send:");
	uid = readline("[default: root]: ");

	if (uid == "") uid = "root";

	if (!KGC_main::haveUser(uid))
	{
		cout << "Error: " << uid << " not found! Register it first!" << endl;
		goto END;
	}

	// get message
	msg = QFile::get_file_content(fname);
	if (msg.empty()) goto END;

	// encrypt
	cipher = KGC_main::encrypt(uid, msg);
	if (cipher.empty()) goto END;

	fname += ".enc";
	text = YHex::Encode(cipher);

#ifdef INTERACT_DEBUG
	cout << "Text:" << endl;
	cout << text << endl;
	cout << "Cipher len: " << cipher.length() << endl; 
	cout << "Message len: " << msg.length() << endl;
	cout << "Message:" << endl;
	cout << msg << endl;
#endif

	QFile::generate_file(fname, text);

END:
	puts("");
	return;
}

void Interact::main()
{
	int ti = 0;
	KGC_main::KGC_Boot();
	welcome();
	while (1)
	{
		if (ti == 0)
		{
			puts("Auto Save....");
			do_save();
			ti += 10;
			continue;
		}
		ti--;
		string cmd = wait_input();
		if (cmd.substr(0, 4) == "help")
		{
			do_help();
		}
		else if (cmd.substr(0, 2) == "ls")
		{
			do_ls();
		}
		else if (cmd.substr(0, 3) == "reg")
		{
			do_reg();
		}
		else if (cmd.substr(0, 2) == "su")
		{
			do_su();
		}
		else if (cmd.substr(0, 4) == "save")
		{
			do_save();
		}
		else if (cmd.substr(0, 3) == "sig")
		{
			do_sig();
		}
		else if (cmd.substr(0, 3) == "ver")
		{
			do_ver();
		}
		else if (cmd.substr(0, 4) == "exit")
		{
			puts("Auto Save....");
			do_save();
			cout << "See you next time, " << KGC_main::current_uid << " !" << endl;
			return;
		}
		else if (cmd.substr(0, 3) == "enc")
		{
			do_enc();
		}
		else if (cmd.substr(0, 3) == "dec")
		{
			do_dec();
		}
		else if (cmd == "")
		{
			// puts("");
		}
		else
		{
			puts("Unsupported commands. Type help to learn more.");
			puts("");
		}
	}
}