#include <node.h>

#include <malloc.h>
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#pragma comment(lib,"crypt32.lib")
#define ENCODING_TYPE (PKCS_7_ASN_ENCODING |X509_ASN_ENCODING)

using namespace v8;

void Method(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
                        0, 
                        0, 
                        CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                        L"my");
  args.GetReturnValue().Set(Number::New(isolate,1));
}

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "hello", Method);
}

NODE_MODULE(addon, init)