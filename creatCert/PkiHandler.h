#pragma once

#include "StrClass.h"

using namespace std;

#define GENERATE_KEY_ERROR                  -14000  //生成RSA密钥对失败
#define PEM_WRITE_BIO_ERROR                 -14001  //转换PEM格式失败
#define PRIKEY_NULL_ERROR                   -14002  //私钥为空
#define PUBKEY_NULL_ERROR                   -14003  //公钥为空
#define CERT_REQUEST_ERROR                  -14004  //证书请求失败
#define CERT_CREATE_ERROR                   -14005  //生成证书失败

typedef struct rsa_st RSA;
typedef struct x509_st X509;
typedef struct bio_st BIO;

class PkiHandler
{
public:
	PkiHandler();
	~PkiHandler();
	
	int GenerateRSAKey();
	int CreateCert(string& outCert_);
	int GetPriKey(string& priKey_);
	int GetPubKey(string& pubKey_);


private:
	BIO* _pubKeyBio;
	BIO* _priKeyBio;
	RSA* _rsaKeyPair;
	X509* _enCert;

};