#include <node.h>

#include <malloc.h>
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#pragma comment(lib,"crypt32.lib")

#define ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define STRING_TYPE (CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG)
using namespace v8;

char* ConvertGBKToUtf8(LPTSTR strGBK)
{
	int len = MultiByteToWideChar(CP_ACP, 0, strGBK, -1, NULL, 0);
	WCHAR * wszUtf8 = new WCHAR[len + 1];
	memset(wszUtf8, 0, len * 2 + 2);
	MultiByteToWideChar(CP_ACP, 0, strGBK, -1, wszUtf8, len);

	len = WideCharToMultiByte(CP_UTF8, 0, wszUtf8, -1, NULL, 0, NULL, NULL);
	char *szUtf8 = new char[len + 1];
	memset(szUtf8, 0, len + 1);
	WideCharToMultiByte(CP_UTF8, 0, wszUtf8, -1, szUtf8, len, NULL, NULL);

	strGBK = szUtf8;
	delete[] wszUtf8;
	return szUtf8;
}

void ForEachMethod(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Local<Function> cb = Local<Function>::Cast(args[0]);

	HCERTSTORE hStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		ENCODING_TYPE,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"My");

	PCCERT_CONTEXT  pCertContext = NULL;
	int index = 0;
	while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)){

		PCERT_INFO  pCertInfo = pCertContext->pCertInfo;
		Local<Object> obj = Object::New(isolate);
		DWORD cbSize;
		LPTSTR pszName;
		LPTSTR pszString;

		//对象是否包含私钥
		obj->Set(String::NewFromUtf8(isolate, "HasPrivateKey"), Boolean::New(isolate, CertGetCertificateContextProperty(pCertContext, 2u, NULL, &cbSize)));
		//颁发给
		cbSize = CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0);	
		pszString = (LPTSTR)malloc(cbSize * sizeof(TCHAR));
		CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			pszString,
			cbSize); 	

		
		obj->Set(String::NewFromUtf8(isolate, "SubjectName"), String::NewFromUtf8(isolate, ConvertGBKToUtf8(pszString)));
	
		//证书的主题可分辨名称
		cbSize = CertNameToStr(
			pCertContext->dwCertEncodingType,
			&(pCertInfo->Subject),
			STRING_TYPE,
			NULL,
			0);

		pszString = (LPTSTR)malloc(cbSize * sizeof(TCHAR));

		cbSize = CertNameToStr(
			pCertContext->dwCertEncodingType,
			&(pCertInfo->Subject),
			STRING_TYPE,
			pszString,
			cbSize);
		obj->Set(String::NewFromUtf8(isolate, "Subject"), String::NewFromUtf8(isolate, ConvertGBKToUtf8(pszString)));


		//颁发者
		cbSize = CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			NULL,
			0);
		pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));
		CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			pszName,
			cbSize);
		obj->Set(String::NewFromUtf8(isolate, "IssuerName"), String::NewFromUtf8(isolate, pszName));


		//证书的证书颁发机构的名称
		cbSize = CertNameToStr(
			pCertContext->dwCertEncodingType,
			&(pCertInfo->Issuer),
			STRING_TYPE,
			NULL,
			0);
		pszString = (LPTSTR)malloc(cbSize * sizeof(TCHAR));
		cbSize = CertNameToStr(
			pCertContext->dwCertEncodingType,
			&(pCertInfo->Issuer),
			STRING_TYPE,
			pszString,
			cbSize);
		obj->Set(String::NewFromUtf8(isolate, "Issuer"), String::NewFromUtf8(isolate, pszString));


		// 证书的序列号
		cbSize = pCertInfo->SerialNumber.cbData;
		int* serialNumber = new int[cbSize];
		for (DWORD n = 0; n < cbSize; n++)
		{
			serialNumber[n] = pCertInfo->SerialNumber.pbData[cbSize - n - 1];
		}		
		obj->Set(String::NewFromUtf8(isolate, "SerialNumber"), Int32Array::New(ArrayBuffer::New(isolate, serialNumber, cbSize), 0, cbSize));

		cbSize = pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
		int* publicKey = new int[cbSize];
		for (DWORD n = 0; n < cbSize; n++)
		{
			publicKey[n] = pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData[n];
		}
		obj->Set(String::NewFromUtf8(isolate, "PublicKey"), Int32Array::New(ArrayBuffer::New(isolate, publicKey, cbSize), 0, cbSize));

		const unsigned argc = 2;
		Local<Value> argv[argc] = { obj, Number::New(isolate, index) };
		cb->Call(isolate->GetCurrentContext()->Global(), argc, argv);
		index++;
	}

	CertCloseStore(hStore, 0);
}

void init(Handle<Object> exports) {
	NODE_SET_METHOD(exports, "forEach", ForEachMethod);
}

NODE_MODULE(addon, init)
