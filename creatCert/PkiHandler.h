#pragma once

#include "StrClass.h"

using namespace std;

#define GENERATE_KEY_ERROR                  -14000  //����RSA��Կ��ʧ��
#define PEM_WRITE_BIO_ERROR                 -14001  //ת��PEM��ʽʧ��
#define PRIKEY_NULL_ERROR                   -14002  //˽ԿΪ��
#define PUBKEY_NULL_ERROR                   -14003  //��ԿΪ��
#define CERT_REQUEST_ERROR                  -14004  //֤������ʧ��
#define CERT_CREATE_ERROR                   -14005  //����֤��ʧ��

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