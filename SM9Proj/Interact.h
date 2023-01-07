#pragma once

#include "KGC_main.h"
#include "Signature.h"

class Interact 
{
public:
	Interact();
	~Interact();

public:
	static void welcome();
	static void cutline(char c, int len);
	static void puts_middle(const char* s, char c);
	static void puts_para(const char* s, char c);
	static string readline(const char* s);
	static string wait_input();
	static void main();

	static void do_help();
	static void do_ls();
	static void do_reg();
	static void do_su();
	static void do_save();
	static void do_sig();
	static void do_ver();
	static void do_enc();
	static void do_dec();

private:
	static char buf[];
};