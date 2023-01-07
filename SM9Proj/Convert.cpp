#include "Convert.h"
#include "BigMath.h"
#include "SM9_Parameters.h"



Convert::Convert()
{
}


Convert::~Convert()
{
}

void Convert::gets_big(big& var, const unsigned char* buf, int length) {
	bytes_to_big(length, (const char*)buf, var);
}

// 国标: 7.2.2 整数变字符串
std::string Convert::puts_big(big& var) {
	// 存储空间的字节大小
	int length = var->len * sizeof(*(var->w)); // sizeof (mr_small)
	char *buffer = new char[length];
	int ret = big_to_bytes(length, var, buffer, FALSE);
	string result(buffer, ret);

	delete[] buffer;
	return result;
}

// 国标: 7.2.6 域元素变字符串 (length = BN_LEN)
std::string Convert::puts_big(big& var, int len) {
	int length = len * sizeof(*(var->w)); // sizeof (mr_small)
	char* buffer = new char[length];
	int ret = big_to_bytes(length, var, buffer, TRUE);
	string result(buffer, ret);

	delete[] buffer;
	return result;
}

bool Convert::gets_ecn2_byte128_xy(ecn2& var, const char* x_buf, const char* y_buf) {
	ecn2 r;
	zzn2 x, y;
	big a = NULL, b = NULL;

	BigMath::init_ecn2(r);
	BigMath::init_zzn2(x);
	BigMath::init_zzn2(y);
	BigMath::init_big(a);
	BigMath::init_big(b);

	bytes_to_big(BN_LEN, (char*)x_buf, b);
	bytes_to_big(BN_LEN, (char*)x_buf + BN_LEN, a);
	zzn2_from_bigs(a, b, &x);
	bytes_to_big(BN_LEN, (char*)y_buf, b);
	bytes_to_big(BN_LEN, (char*)y_buf + BN_LEN, a);
	zzn2_from_bigs(a, b, &y);
	BOOL ret = ecn2_set(&x, &y, &r);
	if (ret) ecn2_copy(&r, &var);

	BigMath::release_ecn2(r);
	BigMath::release_zzn2(x);
	BigMath::release_zzn2(y);
	BigMath::release_big(a);
	BigMath::release_big(b);

	return ret ? true : false;
}

bool Convert::gets_ecn2_byte128(ecn2& var, const char* buf) {
	ecn2 r;
	zzn2 x, y;
	big a = NULL, b = NULL;

	BigMath::init_ecn2(r);
	BigMath::init_zzn2(x);
	BigMath::init_zzn2(y);
	BigMath::init_big(a);
	BigMath::init_big(b);

	bytes_to_big( BN_LEN, (char*)buf, b );
	bytes_to_big( BN_LEN, (char*)buf + BN_LEN, a );
	zzn2_from_bigs(a, b, &x);
	bytes_to_big( BN_LEN, (char*)buf + BN_LEN * 2, b );
	bytes_to_big( BN_LEN, (char*)buf + BN_LEN * 3, a );
	zzn2_from_bigs( a, b, &y );
	BOOL ret = ecn2_set( &x, &y, &r );
	if (ret) ecn2_copy( &r, &var );

	BigMath::release_ecn2(r);
	BigMath::release_zzn2(x);
	BigMath::release_zzn2(y);
	BigMath::release_big(a);
	BigMath::release_big(b);

	return ret ? true : false;
}

std::string Convert::puts_ecn2_big(big& var) {
	big tmp = NULL;
	BigMath::init_big(tmp);
	redc(var, tmp);

	int length = tmp->len * sizeof(tmp->w);
	char *buffer = new char[length];
	int ret = big_to_bytes(length, tmp, buffer, TRUE);
	string result(buffer, ret);

	delete[] buffer;
	BigMath::release_big(tmp);
	return result;
}

std::string Convert::puts_ecn2_big(big& var, int len) {
	big tmp = NULL;
	BigMath::init_big(tmp);
	redc(var, tmp);

	int length = len * sizeof(tmp->w);
	char* buffer = new char[length];
	int ret = big_to_bytes(length, tmp, buffer, TRUE);
	string result(buffer, ret);

	delete[] buffer;
	BigMath::release_big(tmp);
	return result;
}

std::string Convert::puts_ecn2(ecn2& var) {
	string result;
	// F_p^m => (a_{m - 1}, ..., a_0)
	result.append(puts_ecn2_big(var.x.b, BN_LEN));
	result.append(puts_ecn2_big(var.x.a, BN_LEN));
	result.append(puts_ecn2_big(var.y.b, BN_LEN));
	result.append(puts_ecn2_big(var.y.a, BN_LEN));
	return result;
}

std::string Convert::puts_epoint(epoint* var) {
	big x = NULL;
	big y = NULL;
	string result;

	BigMath::init_big(x);
	BigMath::init_big(y);

	epoint_get(var, x, y);

	result.append(puts_big(x, BN_LEN));
	result.append(puts_big(y, BN_LEN));

	BigMath::release_big(x);
	BigMath::release_big(y);
	return result;
}

void Convert::gets_epoint(epoint* var, const char* buf) {
	big x = NULL;
	big y = NULL;

	BigMath::init_big(x);
	BigMath::init_big(y);

	gets_big(x, (const unsigned char*)buf, BN_LEN);
	gets_big(y, (const unsigned char*)buf + BN_LEN, BN_LEN);
	epoint_set(x, y, 0, var);

	BigMath::release_big(x);
	BigMath::release_big(y);
};


