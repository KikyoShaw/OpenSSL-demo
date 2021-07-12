#include "StrClass.h"
#include <Windows.h>

const char BASE_CODE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//编码，参数：要编码的字符串指针，解码后存放的位置（编码字串长度的4/3），要编码的字符串长度 ->返回结果长度
int Base64Encode(char *lpString_, char *lpBuffer_, int sLen_)
{
	int ret = 0;
	int inSize = sLen_;
	const char*  ch64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int n, buflen, i, j;
	int pading = 0;
	int outLen;
	BYTE *buf;

	ret = inSize * 4 / 3 + (4 - inSize % 3) + 1;
	buflen = n = inSize;
	if (n % 3 != 0)  /* pad with '=' by using a temp buffer */
	{
		pading = 1;
		buflen = n + 3 - n % 3;
	}
	buf = new BYTE[buflen];
	memset(buf, 0, buflen);
	memcpy(buf, lpString_, n);
	outLen = inSize * 4 / 3 + (4 - inSize % 3);
	char *dst = new char[outLen + 1];
	memset(dst, 0, outLen + 1);
	for (i = 0, j = 0; i<buflen; i += 3, j += 4)
	{
		dst[j] = (buf[i] & 0xFC) >> 2;
		dst[j + 1] = ((buf[i] & 0x03) << 4) + ((buf[i + 1] & 0xF0) >> 4);
		dst[j + 2] = ((buf[i + 1] & 0x0F) << 2) + ((buf[i + 2] & 0xC0) >> 6);
		dst[j + 3] = buf[i + 2] & 0x3F;
	}
	for (i = 0; i<outLen; i++) /* map 6 bit value to base64 ASCII character */
		dst[i] = ch64[dst[i]];

	if (n % 3 != 0)
	{
		for (i = 0; i<3 - n % 3; i++)
			dst[outLen - i - 1] = '=';
	}

	if (inSize % 3 == 0)
		ret = inSize * 4 / 3;
	else
		ret = inSize * 4 / 3 + (4 - inSize % 3);

	if (lpBuffer_)
		memcpy(lpBuffer_, dst, ret);//o_outData->size);
	lpBuffer_[ret] = '\0';

	delete[] dst;
	delete[] buf;
	return ret;
}


//子函数 - 取密文的索引
char GetCharIndex(char c_) //内联函数可以省去函数调用过程，提速
{
	if ((c_ >= 'A') && (c_ <= 'Z'))
	{
		return c_ - 'A';
	}
	else if ((c_ >= 'a') && (c_ <= 'z'))
	{
		return c_ - 'a' + 26;
	}
	else if ((c_ >= '0') && (c_ <= '9'))
	{
		return c_ - '0' + 52;
	}
	else if (c_ == '+')
	{
		return 62;
	}
	else if (c_ == '/')
	{
		return 63;
	}
	else if (c_ == '=')
	{
		return 0;
	}
	return 0;
}

//解码，参数：密文，密文长度,结果
int Base64Decode(const char *inStr_, int inStrLen_, char *outStr_)   //解码函数
{
	static char lpCode[4];
	register int vLen = 0;
	if (inStrLen_ % 4)		//Base64编码长度必定是4的倍数，包括'='
	{
		outStr_[0] = '\0';
		return -1;
	}

	//把=去掉,本个接口会把=解析为\0，并且把返回长度也+1
	if (strstr(inStr_, "=="))
		vLen -= 2;
	else if (strstr(inStr_, "="))
		--vLen;

	while (inStrLen_ > 2)		//不足三个字符，忽略
	{
		lpCode[0] = GetCharIndex(inStr_[0]);
		lpCode[1] = GetCharIndex(inStr_[1]);
		lpCode[2] = GetCharIndex(inStr_[2]);
		lpCode[3] = GetCharIndex(inStr_[3]);

		*outStr_++ = (lpCode[0] << 2) | (lpCode[1] >> 4);
		*outStr_++ = (lpCode[1] << 4) | (lpCode[2] >> 2);
		*outStr_++ = (lpCode[2] << 6) | (lpCode[3]);

		inStr_ += 4;
		inStrLen_ -= 4;
		vLen += 3;
	}
	//为最后一个字符添加0
	outStr_[vLen] = '\0';
	return vLen;
}


string UTF8ToGBK(const char* strUTF8_)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8_, -1, NULL, 0);
	wchar_t* wszGBK = new wchar_t[len + 1];
	memset(wszGBK, 0, len * 2 + 2);
	MultiByteToWideChar(CP_UTF8, 0, strUTF8_, -1, wszGBK, len);
	len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);
	char* szGBK = new char[len + 1];
	memset(szGBK, 0, len + 1);
	WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGBK, len, NULL, NULL);
	string strTemp(szGBK);
	if (wszGBK) delete[] wszGBK;
	if (szGBK) delete[] szGBK;
	return strTemp;
}


string GBKToUTF8(const std::string& strGBK)
{
	string strOutUTF8 = "";
	WCHAR * str1;
	int n = MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, NULL, 0);
	str1 = new WCHAR[n];
	MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, str1, n);
	n = WideCharToMultiByte(CP_UTF8, 0, str1, -1, NULL, 0, NULL, NULL);
	char * str2 = new char[n];
	WideCharToMultiByte(CP_UTF8, 0, str1, -1, str2, n, NULL, NULL);
	strOutUTF8 = str2;
	delete[]str1;
	str1 = NULL;
	delete[]str2;
	str2 = NULL;
	return strOutUTF8;
}

void Reverser(char* str_, int StrLen_)
{
	//reverse
	int i = 0, j = StrLen_ - 1;
	char temp = 0;
	while (i < j)
	{
		temp = str_[i];
		str_[i] = str_[j];
		str_[j] = temp;
		++i;
		--j;
	}
}


const char hex_table[] = "0123456789abcdef";
int BytesToHexStr(char* p_szDest_, const unsigned char* p_szSour_, int p_iLength_)
{
	for (int i = 0; i<p_iLength_; i++)
	{
		*p_szDest_++ = hex_table[*p_szSour_ >> 4];
		*p_szDest_++ = hex_table[*p_szSour_ & 0x0f];
		p_szSour_++;
	}
	*p_szDest_ = '\0';
	return p_iLength_ * 2;
}

