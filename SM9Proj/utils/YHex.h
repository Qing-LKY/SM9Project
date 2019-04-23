
#ifndef YY_UTILS_YHEX_INCLUDE_H__
#define YY_UTILS_YHEX_INCLUDE_H__

/** \file YHex.h
* \brief C++-ʮ�����Ƹ�ʽ�ַ���ת��.
* ���ַ���ת��Ϊʮ������ʱ�����ΪСд������������Ǵ�д��Сд.
* ���������β����г��Ȳ���������ڸó����Ƿ���ڴ����ַ�����ʵ�ʳ����ǲ����жϵģ���������Լ���֤.
*/

#include <string>
using namespace std;

/**
* HEX CODEC.
*/
class YHex
{
public:
	/**
	* HEX encoding.
	*/
	static string Encode(const string& data, bool isUpperCase);

	/**
	* HEX encoding(LowerCase).
	*/
	static string Encode(const string& data) {
		return Encode(data, false);
	}

	/**
	* HEX decoding.
	*/
	static string Decode(const string& data);

	/**
	* HEX data format check.
	*
	* A valid character is in ["0123456789abcdef"], case-insensitive.
	*/
	static bool Check(const string& data);

private:
	static void Bin2Hex(bool isUpperCase, const char *bin_string, char *hex_string, int binLength);
	static void Hex2Bin(const char *hex_string, char* bin_string, int hexLength);

	/**
	* Hex Format check.
	* A valid hex character is in "0123456789ABCDEFabcdef".
	* @return 0 if all characters is valid; or the position of first invalid character, 1 represent the first character;
	* if nSrcLength<=0, or pSrc=nullptr, return 0.
	*/
	static int Check(const unsigned char* pSrc, int nSrcLength);

private:
	YHex() = delete;
	~YHex() = delete;
	YHex(const YHex&) = delete;
	YHex& operator=(const YHex&) = delete;

};
#endif