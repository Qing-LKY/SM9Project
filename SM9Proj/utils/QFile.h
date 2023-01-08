#pragma once

#include <string>
#include "../Signature.h"

using namespace std;

// file utils by qinglkyi
class QFile
{
public:
	QFile();
	~QFile();

public:
	static string get_string_from_file(FILE* fp, unsigned int off, unsigned int siz);
	static string gen_signed_text(const string& msg, const Signature& sig, const string& uid);

	static void generate_file(const string& fname, const string& text);
	static string get_file_content(const string& fname);

	static const int HEAD_LEN;

private:
	static char buf[];
};