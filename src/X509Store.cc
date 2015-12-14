#include <node.h>

#include <malloc.h>
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#pragma comment(lib,"crypt32.lib")

using namespace v8;

//typedef struct _CERT_ INFO {
//	DWORD dwVersion;        //֤��汾  
//	CRYPT_INTEGER_BLOB SerialNumber;       //���к�  
//	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;     //ǩ���㷨  
//	CERT_NAME_BLOB Issuer;   //�䷢��  
//	FILETIME NotBefore;   //��Ч��(��)  
//	FILETIME NotAflee;    //��Ч��(ֹ)  
//	CERT_NAME_BLOB Subject;   //ӵ����  
//	CERT_PUBLIC_KEY_INFO SubiectPublicKevInfo;  //�û���Կ  
//	CRYPT_BIT_BLOB IssuerUniqueId��    //�䷢��Ψһ��ʶ  
//		CRYPT_BIT_BLOB SubjectUniqueId;    //ӵ����Ψһ��ʶ  
//	DWORD cExtension;    //��չ����  
//	PCERT_EXTENSION rgExtension;    //��չ  
//}

void CountMethod(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);

	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		0,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
		L"my");
	PCCERT_CONTEXT  pCertContext = NULL;
	int i = 0;
	while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)){
		i++;
	}
	CertCloseStore(hStore, 0);
	args.GetReturnValue().Set(Number::New(isolate, i));
}




void ForEachMethod(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Local<Function> cb = Local<Function>::Cast(args[0]);

	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		0,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
		L"my");

	PCCERT_CONTEXT  pCertContext = NULL;
	int index = 0;
	while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)){
		PCERT_INFO  pCertInfo = pCertContext->pCertInfo;
		Local<Object> obj = Object::New(isolate);
		obj->Set(String::NewFromUtf8(isolate, "Subject"),
			Int32Array::New(ArrayBuffer::New(isolate, pCertInfo->Subject.pbData, strlen((char*)pCertInfo->Subject.pbData)), 0, strlen((char*)pCertInfo->Subject.pbData)));
		//obj->Set(String::NewFromUtf8(isolate, "Issuer"),String::NewFromUtf8(isolate, DwordToString(pCertInfo->Issuer.cbData)));
		//obj->Set(String::NewFromUtf8(isolate, "SerialNumber"), String::NewFromUtf8(isolate, DwordToString(pCertInfo->SerialNumber.cbData)));

		const unsigned argc = 2;
		Local<Value> argv[argc] = { obj, Number::New(isolate, index) };
		args.GetReturnValue().Set(obj);
		//cb->Call(isolate->GetCurrentContext()->Global(), argc, argv);
		break;
		index++;
	}

	CertCloseStore(hStore, 0);
}

void init(Handle<Object> exports) {
	NODE_SET_METHOD(exports, "count", ForEachMethod);
	NODE_SET_METHOD(exports, "forEach", ForEachMethod);
}

NODE_MODULE(addon, init)