#pragma once
#include <string>

using namespace std;

int  Base64Decode(const char *inStr_, int inStrLen_, char *outStr_);
int  Base64Encode(char *lpString_, char *lpBuffer_, int sLen_);
string  UTF8ToGBK(const char* strUTF8_);
string  GBKToUTF8(const std::string& strGBK);
void  Reverser(char* str_, int strLen_);
int BytesToHexStr(char* p_szDest_, const unsigned char* p_szSour_, int p_iLength_);