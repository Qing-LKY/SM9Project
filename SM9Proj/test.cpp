#include "Interact.h"
#include "SM3/YSM3.h"
#include "utils/YHex.h"
#include "SM9.h"
#include "BigMath.h"
#include "Convert.h"
#include "Testor.h"

extern "C"
{
#include "miracl.h"
#include "mirdef.h"
}

#include <string>
#include <iostream>

#include <cstdio>

using namespace std;

int main()
{
	Interact::main();
	return 0;
}