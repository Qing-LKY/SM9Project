#include <time.h>

#include "SM9.h"
#include "Testor.h"

int main()
{
	clock_t tBegin, tTestEnd;
	clock_t tInitDone, tReleaseDone;

	tBegin = clock();

	SM9::init();
	tInitDone = clock();

	Testor::KGC_Standard_Test();
	tTestEnd = clock();

	SM9::release();
	tReleaseDone = clock();

	printf("\n��ʼ����ʱ:%ld ms\n", tInitDone - tBegin);
	printf("\n���Ժ�ʱ:%ld ms\n", tTestEnd - tInitDone);
	printf("\n�ͷź�ʱ:%ld ms\n", tReleaseDone - tTestEnd);
}
/*
extern "C"
{
#include "miracl.h"
#include "mirdef.h"
}

int main()
{
	int i;
	big x, e, m, y;
	FILE *fp;
	clock_t tBegin, tEnd;
	miracl *mip = mirsys(1000,16);
	x = mirvar(0);
	e = mirvar(0);
	m = mirvar(0);
	y = mirvar(0);

	errno_t err;
	err = fopen_s(&fp, "data.txt", "r+");
	mip->IOBASE = 16;
	cinnum(x, fp);
	cinnum(e, fp);
	cinnum(m,fp);
	fclose(fp);
	tBegin = clock();
	for (i = 0; i < 100; i++)
		powmod(x, e, m, y);
	tEnd = clock();
	cotnum(x, stdout);
	cotnum(e, stdout);
	cotnum(m, stdout);
	cotnum(y, stdout);

	printf("\n\n����100��1024���ص�ģָ�����������ĵ�ʱ��Ϊ:%ld ms\n\n", tEnd - tBegin);

	int gg;
	gg = mr_compare(e, e);
	printf("%d", false);

	return 0;
}
*/
