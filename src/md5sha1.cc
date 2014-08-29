#include "node.h"
#include "nan.h"
#include "node_buffer.h"
#include "node_object_wrap.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
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
  NanScope();

  if (args.Length() != 2 ||
      !Buffer::HasInstance(args[0]) ||
      !Buffer::HasInstance(args[1])) {
    return NanThrowError("Invalid arguments length, expected sign(input, key)");
  }

  RSA* pkey = GetPKey(Buffer::Data(args[1]), Buffer::Length(args[1]));
  if (pkey == NULL)
    return NanThrowError("Invalid key, failed to parse public/private key");

  unsigned int out_len = RSA_size(pkey);
  unsigned char* out = new unsigned char[out_len];

  int r = RSA_sign(NID_md5_sha1,
                   reinterpret_cast<unsigned char*>(Buffer::Data(args[0])),
                   Buffer::Length(args[0]),
                   out,
                   &out_len,
                   pkey);
  RSA_free(pkey);
  if (!r) {
    delete[] out;
    return NanThrowError("Failed to sign");
  }

  Local<Value> res = NanNewBufferHandle(reinterpret_cast<char*>(out), out_len);
  delete[] out;

  NanReturnValue(res);
}


static NAN_METHOD(Verify) {
  NanScope();

  if (args.Length() != 3 ||
      !Buffer::HasInstance(args[0]) ||
      !Buffer::HasInstance(args[1]) ||
      !Buffer::HasInstance(args[2])) {
    return NanThrowError("Invalid arguments length, "
                         "expected verify(input, signature, key)");
  }

  RSA* pkey = GetPKey(Buffer::Data(args[2]), Buffer::Length(args[2]));
  if (pkey == NULL)
    return NanThrowError("Invalid key, failed to parse public/private key");

  int r = RSA_verify(NID_md5_sha1,
                     reinterpret_cast<unsigned char*>(Buffer::Data(args[0])),
                     Buffer::Length(args[0]),
                     reinterpret_cast<unsigned char*>(Buffer::Data(args[1])),
                     Buffer::Length(args[1]),
                     pkey);
  RSA_free(pkey);

  NanReturnValue(r ? NanTrue() : NanFalse());
}


static void Init(Handle<Object> target) {
  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  NODE_SET_METHOD(target, "sign", Sign);
  NODE_SET_METHOD(target, "verify", Verify);

}

NODE_MODULE(md5sha1, Init);

}  // namespace rawcipher
