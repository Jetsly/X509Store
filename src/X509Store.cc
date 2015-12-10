#include <node.h>

#include <malloc.h>
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#pragma comment(lib,"crypt32.lib")

using namespace v8;

void CountMethod(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  HCERTSTORE hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
                        0, 
                        0, 
                        CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                        L"my");
  PCCERT_CONTEXT  pCertContext=NULL;              
  int i=0;        
  while(pCertContext=CertEnumCertificatesInStore(hStore,pCertContext)){
    i++;
  }          
  CertCloseStore(hStore,0);          
  args.GetReturnValue().Set(Number::New(isolate,i));
}

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "count", CountMethod);
}

NODE_MODULE(addon, init)