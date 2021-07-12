
#include "PkiHandler.h"

int main()
{
	PkiHandler pki = PkiHandler();

	int RSA_num = pki.GenerateRSAKey();

	printf("RSA_num:%d\n",RSA_num);

	string pubkey = "";
	int PUK_num = pki.GetPubKey(pubkey);

	printf("pubkey:%s\n", pubkey.c_str());

	string pvkey = "";
	int PVK_num = pki.GetPriKey(pvkey);
	printf("pvkey:%s\n", pvkey.c_str());

	string certkey = "";
	int CERT_num = pki.CreateCert(certkey);
	printf("certkey:%s\n",certkey.c_str());

	return 0;

}