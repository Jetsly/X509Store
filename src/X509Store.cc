#include <node.h>
#using <System.dll>
#using <System.Security.dll>

using namespace v8;
using namespace System;
using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System::IO;

void Method(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  //Create new X509 store called teststore from the local certificate store.
  X509Store ^ store = gcnew X509Store( "teststore",StoreLocation::CurrentUser );
  store->Open( OpenFlags::ReadWrite );
  X509Certificate2Collection ^ storecollection2 = dynamic_cast<X509Certificate2Collection^>(store->Certificates);
  args.GetReturnValue().Set(Number::New(isolate,storecollection3->Count));
}

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "hello", Method);
}

NODE_MODULE(addon, init)