#include "PkiHandler.h"

#include "openssl\bio.h"
#include "openssl\pem.h"
#include "openssl\rsa.h"
#include "openssl\x509.h"
#include "openssl\x509v3.h"
#include "openssl\pkcs7.h"

typedef volatile int CRYPTO_REF_COUNT;
struct bio_st {
	const BIO_METHOD *method;
	/* bio, mode, argp, argi, argl, ret */
	long(*callback) (struct bio_st *, int, const char *, int, long, long);
	char *cb_arg;               /* first argument for the callback */
	int init;
	int shutdown;
	int flags;                  /* extra storage */
	int retry_reason;
	int num;
	void *ptr;
	struct bio_st *next_bio;    /* used by filter BIOs */
	struct bio_st *prev_bio;    /* used by filter BIOs */
	int references;
	uint64_t num_read;
	uint64_t num_write;
	CRYPTO_EX_DATA ex_data;
	CRYPTO_RWLOCK *lock;
};

struct X509_req_info_st {
	ASN1_ENCODING enc;          /* cached encoding of signed part */
	ASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
	X509_NAME *subject;         /* certificate request DN */
	X509_PUBKEY *pubkey;        /* public key of request */
	/*
	 * Zero or more attributes.
	 * NB: although attributes is a mandatory field some broken
	 * encodings omit it so this may be NULL in that case.
	 */
	STACK_OF(X509_ATTRIBUTE) *attributes;
};

struct X509_req_st {
	X509_REQ_INFO req_info;     /* signed certificate request data */
	X509_ALGOR sig_alg;         /* signature algorithm */
	ASN1_BIT_STRING *signature; /* signature */
	CRYPTO_REF_COUNT references;
	CRYPTO_RWLOCK *lock;
};




PkiHandler::PkiHandler()
{
	_rsaKeyPair = NULL;
	_pubKeyBio = NULL;
	_priKeyBio = NULL;
	_enCert = NULL;
}


PkiHandler::~PkiHandler()
{
	if (_rsaKeyPair)
		RSA_free(_rsaKeyPair);
	if (_priKeyBio)
		BIO_free(_priKeyBio);
	if (_pubKeyBio)
		BIO_free(_pubKeyBio);
	if (_enCert)
		X509_free(_enCert);
}

/*
*	Function	:GenerateRSAKey
*	Description	:生成RSA密钥对
*	Parameters	:
*	Return		:
*				成功返回0
*/
int PkiHandler::GenerateRSAKey()
{
	_rsaKeyPair = RSA_generate_key(2048, RSA_3, NULL, NULL);
	if (!_rsaKeyPair)
		return GENERATE_KEY_ERROR;

	_pubKeyBio = BIO_new(BIO_s_mem());
	_priKeyBio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(_priKeyBio, _rsaKeyPair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(_pubKeyBio, _rsaKeyPair);
	if (!_priKeyBio || !_pubKeyBio)
		return PEM_WRITE_BIO_ERROR;
	return 0;
}
 
/*
*	Function	:GetPriKey
*	Description	:获取私钥（PEM格式）
*	Parameters	:
*				char** priKey_			[out]存储私钥，内部分配空间使用完外部要释放（但外部释放会崩溃）
*	Return		:
*				成功返回0
*/
int PkiHandler::GetPriKey(string& priKey_)
{
	if (!_priKeyBio )
		return PRIKEY_NULL_ERROR;

	int pri_len = BIO_pending(_priKeyBio);
	
	// 密钥对读取到字符串    
	char* priKey = new char[pri_len+1];
	BIO_read(_priKeyBio, priKey, pri_len);
	priKey[pri_len] = '\0';

	priKey_ = priKey;
	delete[] priKey;
	return 0;
}

/*
*	Function	:GetPubKey
*	Description	:获取公钥（PEM格式）
*	Parameters	:
*				char** pubKey_			[out]存储公钥，内部分配空间使用完外部要释放（但外部释放会崩溃）
*	Return		:
*				成功返回0
*/
int PkiHandler::GetPubKey(string& pubKey_)
{
	if (!_pubKeyBio)
		return PUBKEY_NULL_ERROR;

	int pub_len = BIO_pending(_pubKeyBio);
	char* pubKey = new char[pub_len+1];
	BIO_read(_pubKeyBio, pubKey, pub_len);
	pubKey[pub_len] = '\0';

	pubKey_ = pubKey;
	delete[] pubKey;
	return 0;
}


/*
*	Function	:CreateCert
*	Description	:生成证书（PEM格式）
*	Parameters	:
*				string& outCert_			[in out]存储证书
*	Return		:
*				成功返回0
*/
int PkiHandler::CreateCert(string& outCert_)
{

	int ret = 0;
	X509 *x509 = NULL;
	X509_NAME *subject = NULL;
	X509_REQ *x509Req = NULL;
	EVP_PKEY *clientKey = NULL;
	BIO* certBio = NULL;
	char* outCert = NULL;

	if (!_rsaKeyPair)
	{
		ret = GENERATE_KEY_ERROR;
		goto end;
	}

	//提取密钥
	clientKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(clientKey, _rsaKeyPair);

	x509 = X509_new();
	X509_set_pubkey(x509, clientKey);

	// 设置属性
	subject = X509_get_subject_name(x509);
	// 国家
	X509_NAME_add_entry_by_txt(subject, SN_countryName, MBSTRING_UTF8,
		(unsigned char *)"CN", -1, -1, 0);
	// 省份
	X509_NAME_add_entry_by_txt(subject, SN_stateOrProvinceName, MBSTRING_UTF8,
		(unsigned char *)"GuangDong", -1, -1, 0);
	// 城市
	X509_NAME_add_entry_by_txt(subject, SN_localityName, MBSTRING_UTF8,
		(unsigned char *)"GuangZhou", -1, -1, 0);

	X509_set_subject_name(x509, subject);
	x509Req = X509_to_X509_REQ(x509, clientKey, EVP_sha1());
	if (!x509Req)
	{
		ret = CERT_REQUEST_ERROR;
		goto end;
	}

	_enCert = X509_new();
	//设置版本号
	X509_set_version(_enCert, 2);
	//设置证书序列号，这个sn就是CA中心颁发的第N份证书
	ASN1_INTEGER_set(X509_get_serialNumber(_enCert), 1);
	//设置证书开始时间
	X509_gmtime_adj(X509_get_notBefore(_enCert), 0);
	//设置证书结束时间
	X509_gmtime_adj(X509_get_notAfter(_enCert), (long)60 * 60 * 24);
	//设置证书的主体名称，req就是刚刚生成的请求证书
	X509_set_subject_name(_enCert, X509_REQ_get_subject_name(x509Req));
	//设置证书的公钥信息
	X509_set_pubkey(_enCert, X509_PUBKEY_get(x509Req->req_info.pubkey));

	//设置签名值
	X509_sign(_enCert, clientKey, EVP_sha1());
	//这样一份X509证书就生成了，下面的任务就是对它进行编码保存。
	//i2d_X509_bio(pbio, m_pClientCert); //DER格式
	certBio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(certBio, _enCert);//PEM格式
	if (certBio->num_write == 0)
	{
		ret = CERT_CREATE_ERROR;
		goto end;
	}

	outCert = new char[certBio->num_write + 1];
	BIO_read(certBio, outCert, certBio->num_write);
	(outCert)[certBio->num_write] = '\0';
	outCert_ = outCert;
end:
	if (x509)
		X509_free(x509);
	if (x509Req)
		X509_REQ_free(x509Req);
	if (certBio)
		BIO_free(certBio);
	if (clientKey)
		EVP_PKEY_free(clientKey);
	if (outCert)
		delete[] outCert;
	return ret;
}