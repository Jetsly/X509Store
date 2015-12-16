#include <node.h>

#include <malloc.h>
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#pragma comment(lib,"crypt32.lib")

using namespace v8;

void ForEachMethod(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Local<Function> cb = Local<Function>::Cast(args[0]);

	HCERTSTORE hStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"My");

	PCCERT_CONTEXT  pCertContext = NULL;
	int index = 0;
	while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)){

		PCERT_INFO  pCertInfo = pCertContext->pCertInfo;
		Local<Object> obj = Object::New(isolate);
		DWORD  dwData;
		//对象是否包含私钥
		obj->Set(String::NewFromUtf8(isolate, "HasPrivateKey"), Boolean::New(isolate, CertGetCertificateContextProperty(pCertContext, 2u, NULL, &dwData)));

		if (dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			NULL,
			0))
		{
			LPTSTR szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
			if (CertGetNameString(pCertContext,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				CERT_NAME_ISSUER_FLAG,
				NULL,
				szName,
				dwData)){
				//证书的证书颁发机构的名称
				obj->Set(String::NewFromUtf8(isolate, "Issuer"), String::NewFromUtf8(isolate, szName));
			}
		}
		else{
			//证书的证书颁发机构的名称
			obj->Set(String::NewFromUtf8(isolate, "Issuer"), String::NewFromUtf8(isolate, NULL));
		}

		if (dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0))
		{
			LPTSTR szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
			if (CertGetNameString(pCertContext,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				0,
				NULL,
				szName,
				dwData)){
				//证书的主题可分辨名称
				obj->Set(String::NewFromUtf8(isolate, "Subject"), String::NewFromUtf8(isolate, szName));
			}
		}
		else{
			//证书的主题可分辨名称
			obj->Set(String::NewFromUtf8(isolate, "Subject"), String::NewFromUtf8(isolate, NULL));
		}

		dwData = pCertInfo->SerialNumber.cbData;
		LPTSTR szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
		for (DWORD n = 0; n < dwData; n++)
		{
			szName[n]=pCertInfo->SerialNumber.pbData[dwData - (n + 1)];
		}
		// 证书的序列号
		obj->Set(String::NewFromUtf8(isolate, "SerialNumber"), String::NewFromUtf8(isolate, szName));

		const unsigned argc = 2;
		Local<Value> argv[argc] = { obj, Number::New(isolate, index) };
		args.GetReturnValue().Set(obj);
		cb->Call(isolate->GetCurrentContext()->Global(), argc, argv);
		break;
		index++;
	}

	CertCloseStore(hStore, 0);
}

void init(Handle<Object> exports) {
	NODE_SET_METHOD(exports, "forEach", ForEachMethod);
}

NODE_MODULE(addon, init)
