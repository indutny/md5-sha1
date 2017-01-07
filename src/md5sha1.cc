#include "node.h"
#include "nan.h"
#include "node_buffer.h"
#include "node_object_wrap.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "v8.h"

#include <string.h>

namespace md5sha1 {

using namespace node;
using namespace v8;

static RSA* GetPKey(char* data, size_t len) {
  RSA* rsa;
  BIO* bio = NULL;
  unsigned char* udata = reinterpret_cast<unsigned char*>(data);
  const unsigned char* p;

  p = udata;
  rsa = d2i_RSAPublicKey(NULL, &p, len);
  if (rsa != NULL)
    return rsa;

  p = udata;
  rsa = d2i_RSA_PUBKEY(NULL, &p, len );
  if (rsa != NULL)
    return rsa;

  p = udata;
  rsa = d2i_RSAPrivateKey(NULL, &p, len);
  if (rsa != NULL)
    return rsa;

  bio = BIO_new_mem_buf(data, len);
  assert(bio != NULL);
  rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if (rsa != NULL)
    return rsa;

  bio = BIO_new_mem_buf(data, len);
  assert(bio != NULL);
  rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if (rsa != NULL)
    return rsa;

  bio = BIO_new_mem_buf(data, len);
  assert(bio != NULL);
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if (rsa != NULL)
    return rsa;

  return NULL;
}


static NAN_METHOD(Sign) {
  if (info.Length() != 2 ||
      !Buffer::HasInstance(info[0]) ||
      !Buffer::HasInstance(info[1])) {
    return Nan::ThrowError(
        "Invalid arguments length, expected sign(input, key)");
  }

  RSA* pkey = GetPKey(Buffer::Data(info[1]), Buffer::Length(info[1]));
  if (pkey == NULL)
    return Nan::ThrowError("Invalid key, failed to parse public/private key");

  unsigned int out_len = RSA_size(pkey);
  unsigned char* out = new unsigned char[out_len];

  int r = RSA_sign(NID_md5_sha1,
                   reinterpret_cast<unsigned char*>(Buffer::Data(info[0])),
                   Buffer::Length(info[0]),
                   out,
                   &out_len,
                   pkey);
  RSA_free(pkey);
  if (!r) {
    delete[] out;
    return Nan::ThrowError("Failed to sign");
  }

  Local<Value> res = Nan::NewBuffer(reinterpret_cast<char*>(out), out_len)
      .ToLocalChecked();

  info.GetReturnValue().Set(res);
}


static NAN_METHOD(Verify) {
  if (info.Length() != 3 ||
      !Buffer::HasInstance(info[0]) ||
      !Buffer::HasInstance(info[1]) ||
      !Buffer::HasInstance(info[2])) {
    return Nan::ThrowError("Invalid arguments length, "
                           "expected verify(input, signature, key)");
  }

  RSA* pkey = GetPKey(Buffer::Data(info[2]), Buffer::Length(info[2]));
  if (pkey == NULL)
    return Nan::ThrowError("Invalid key, failed to parse public/private key");

  int r = RSA_verify(NID_md5_sha1,
                     reinterpret_cast<unsigned char*>(Buffer::Data(info[0])),
                     Buffer::Length(info[0]),
                     reinterpret_cast<unsigned char*>(Buffer::Data(info[1])),
                     Buffer::Length(info[1]),
                     pkey);
  RSA_free(pkey);

  info.GetReturnValue().Set(r ? Nan::True() : Nan::False());
}


class Digest : public ObjectWrap {
 public:
  static void Init(Handle<Object> target) {
    Local<FunctionTemplate> t = Nan::New<FunctionTemplate>(Digest::New);

    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(Nan::New("Digest").ToLocalChecked());

    Nan::SetPrototypeMethod(t, "update", Digest::Update);
    Nan::SetPrototypeMethod(t, "digest", Digest::Final);

    target->Set(Nan::New("Digest").ToLocalChecked(), t->GetFunction());
  }

 protected:
  Digest() {
    EVP_MD_CTX_init(&md5_);
    EVP_MD_CTX_init(&sha1_);

    int r;
    r = EVP_DigestInit_ex(&md5_, EVP_md5(), NULL);
    assert(r);
    r = EVP_DigestInit_ex(&sha1_, EVP_sha1(), NULL);
    assert(r);
  }

  ~Digest() {
    EVP_MD_CTX_cleanup(&md5_);
    EVP_MD_CTX_cleanup(&sha1_);
  }

  static NAN_METHOD(New) {
    Digest* d = new Digest();
    d->Wrap(info.This());

    info.GetReturnValue().Set(info.This());
  }

  static NAN_METHOD(Update) {
    Digest* d = ObjectWrap::Unwrap<Digest>(info.This());
    if (info.Length() < 1 || !Buffer::HasInstance(info[0]))
      return Nan::ThrowError("Invalid arguments length, expected update(data)");

    char* data = Buffer::Data(info[0]);
    int len = Buffer::Length(info[0]);

    int r;
    r = EVP_DigestUpdate(&d->md5_, data, len);
    if (r)
      r = EVP_DigestUpdate(&d->sha1_, data, len);

    if (!r)
      return Nan::ThrowError("Failed to update digest");

    info.GetReturnValue().Set(info.This());
  }

  static NAN_METHOD(Final) {
    Digest* d = ObjectWrap::Unwrap<Digest>(info.This());
    if (info.Length() < 1 || !Buffer::HasInstance(info[0]))
      return Nan::ThrowError("Invalid arguments length, expected update(data)");

    unsigned char* out =
        reinterpret_cast<unsigned char*>(Buffer::Data(info[0]));
    int len = Buffer::Length(info[0]);

    if (len != 36)
      return Nan::ThrowError("Invalid output length");

    unsigned int s;
    int r;

    s = 16;
    r = EVP_DigestFinal_ex(&d->md5_, out, &s);
    if (!r || s != 16)
      return Nan::ThrowError("DigestFinal md5 failed");

    s = 20;
    r = EVP_DigestFinal_ex(&d->sha1_, out + 16, &s);
    if (!r || s != 20)
      return Nan::ThrowError("DigestFinal sha1 failed");

    info.GetReturnValue().Set(info[0]);
  }

  EVP_MD_CTX md5_;
  EVP_MD_CTX sha1_;
};


static void Init(Handle<Object> target) {
  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  Nan::SetMethod(target, "sign", Sign);
  Nan::SetMethod(target, "verify", Verify);

  Digest::Init(target);
}

NODE_MODULE(md5sha1, Init);

}  // namespace rawcipher
