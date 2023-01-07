#include <cstdio>
#include <string>
#include <fstream>
#include <iostream>

#include "QFile.h"
#include "../Signature.h"
#include "YHex.h"

using namespace std;

QFile::QFile()
{
}

QFile::~QFile()
{
}

const int BUF_SIZE = 1 << 14;

char QFile::buf[BUF_SIZE];

void QFile::generate_file(const string& fname, const string& text)
{
	ofstream outf(fname.c_str(), ios::out | ios::trunc);
	if (outf.is_open())
	{
		outf << text;
		cout << "Success: generate `" << fname << "'." << endl;
		outf.close();
	}
	else
	{
		puts("Error: Failed to write file!");
	}
}

string QFile::get_file_content(const string& fname)
{
	FILE* fp;
	string text;
	int tmp;

	fopen_s(&fp, fname.c_str(), "r");
	if (fp == NULL)
	{
		cout << "Error: Failed to open file " << fname << " !" << endl;
		return text;
	}
	while ((tmp = fread(buf, 1, BUF_SIZE, fp)) == BUF_SIZE)
	{
		text += string(buf, buf + tmp);
	}
	text += string(buf, buf + tmp);
	fclose(fp);

	return text;
}

string QFile::get_string_from_file(FILE* fp, unsigned int off, unsigned int siz)
{
	int tmp;
	string s;

	fseek(fp, off, SEEK_SET);
	while (siz > BUF_SIZE)
	{
		tmp = fread(buf, 1, BUF_SIZE, fp);
		if (tmp != BUF_SIZE)
		{
			fclose(fp);
			puts("Error when get string from file!");
			s.clear();
			return s;
		}
		s += string(buf, buf + tmp);
		siz -= BUF_SIZE;
	}
	tmp = fread(buf, 1, siz, fp);
	s += string(buf, buf + tmp);

	return s;
}

// Warning: '\n' means '\r' and '\n' in windows text file!
#define __CR 1 

const char header_line[] = "====================== Signature Header ======================\r\n";

const int QFile::HEAD_LEN = 8 * 9 + 4 + 1 + __CR;

string QFile::gen_signed_text(const string& msg, const Signature& sig, const string& uid)
{
	// TODO: Forget to add magic tags into the text
	string all;
	// Header Message: ".hd ....\n"
	// TODO: A (A<<8)^B (B'<<8)^C ...
	unsigned int pH, lH, pS, lS, pU, lU, pM, lM;
	// deal with cr
	int _cr = 0;
	string T;

	all += header_line;
	_cr += __CR;

	pH = all.length() + HEAD_LEN + _cr;
	T = YHex::Encode(sig.getH());
	lH = T.length(); // fix bugs
	all += T + "\n";
	_cr += __CR;

	pS = all.length() + HEAD_LEN + _cr;
	T = YHex::Encode(sig.getS());
	lS = T.length();
	all += T + "\n";
	_cr += __CR;

	all += "Signed by ";
	pU = all.length() + HEAD_LEN + _cr;
	lU = uid.length();
	all += uid + "\n";
	_cr += __CR;

	all += header_line;
	_cr += __CR;

	pM = all.length() + HEAD_LEN + _cr;
	lM = msg.length();
	all += msg;

	sprintf_s(buf,
		".hd %9d%9d%9d%9d%9d%9d%9d%9d\n",
		pH, lH, pS, lS, pU, lU, pM, lM);

#ifdef INTERACT_DEBUG
	printf(".hd %d %d %d %d %d %d %d %d\n", pH, lH, pS, lS, pU, lU, pM, lM);
#endif
	all = string(buf) + all;
	return all;
}