#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "utils.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include "../modules/secrets/secrets.h"

std::string FBToken::encrypt(Json::Value const& value) {
	return encrypt(Utils::writeJSON(value));
}

// const unsigned char *_fbtoken_iv=(16 bytes data);
// const unsigned char *_fbtoken_key=(32 bytes data);
// ^ secrets.h

extern std::string sha256(std::string const& input);

inline static unsigned char random_byte_safe() {
	unsigned char ret;
	RAND_bytes(&ret, 1);
	return ret;
}

std::string FBToken::encrypt(std::string const& value) {
	EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), nullptr, _fbtoken_key, _fbtoken_iv);
	char *out=(char*)malloc(4096);
	int outLen;
	EVP_EncryptUpdate(ctx, (unsigned char *)out, &outLen, (const unsigned char *)value.c_str(), value.size());
	std::string ret=Utils::base64Encode(std::string(out, outLen));
	free(out);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

std::string FBToken::decrypt(std::string const& _token) {
	std::string token=Utils::base64Decode(_token);
	EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), nullptr, _fbtoken_key, _fbtoken_iv);
	char *out=(char *)malloc(4096);
	int outLen;
	int enc_succ=EVP_DecryptUpdate(ctx, (unsigned char *)out, &outLen, (const unsigned char *)token.c_str(), token.size());
	if(!enc_succ) {
		free(out);
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}
	std::string ret(out, outLen);
	free(out);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

std::pair<std::string, std::string> Utils::generateRSAKeyPair() {
	EVP_PKEY *pKey=EVP_RSA_gen(2048);
	BIO *bio=BIO_new(BIO_s_mem());
	int succ=PEM_write_bio_PrivateKey(bio, pKey, nullptr, nullptr, 0, nullptr, nullptr);
	if(!succ) {
		BIO_free(bio);
		throw std::runtime_error("Failed to write private key");
	}
	char *content;
	size_t privateKey_size=BIO_get_mem_data(bio, &content);
	std::string privateKey(content, privateKey_size);
	BIO_reset(bio);
	succ=PEM_write_bio_PUBKEY(bio, pKey);
	if(!succ) {
		BIO_free(bio);
		throw std::runtime_error("Failed to write public key");
	}
	size_t publicKey_size=BIO_get_mem_data(bio, &content);
	std::string publicKey(content, publicKey_size);
	BIO_free(bio);
	EVP_PKEY_free(pKey);
	return std::make_pair(privateKey, publicKey);
}

std::string Utils::cv4Sign(std::string const& content) {
	const unsigned char *cv4Key=Secrets::getCv4Key();
	BIO *cv4KeyBuf=BIO_new_mem_buf((const void *)cv4Key, strlen((const char *)cv4Key));
	EVP_PKEY *key;
	if(!(key=PEM_read_bio_PrivateKey(cv4KeyBuf, nullptr, nullptr, nullptr))) {
		BIO_free(cv4KeyBuf);
		throw std::runtime_error("Failed to parse server private key");
	}
	BIO_free(cv4KeyBuf);
	EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(key, nullptr);
	if(!ctx) {
		EVP_PKEY_free(key);
		throw std::runtime_error("Failed to create encryption ctx");
	}
	if(EVP_PKEY_sign_init(ctx)<=0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		throw std::runtime_error("Failed to initialize encryption context for signature");
	}
	if(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256())<=0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		throw std::runtime_error("Failed to assign signature algorithm");
	}
	unsigned char signbuf[512];
	size_t signbuf_len=512;
	std::string digest=Utils::hex2str(sha256(content));
	if(EVP_PKEY_sign(ctx, signbuf, &signbuf_len, (const unsigned char *)digest.c_str(), 32)<=0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(key);
		char sslerror[128];
		ERR_error_string(ERR_get_error(), sslerror);
		printf("%s\n", sslerror);
		throw std::runtime_error("Failed to perform signature");
	}
	std::string to_ret=Utils::str2hex(std::string((char *)signbuf, signbuf_len));
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);
	return to_ret;
}

std::string Utils::generateUUID() {
	unsigned char content[18];
	RAND_bytes(content, 18);
	std::string ret=str2hexUpper(std::string((char *)content, 18));
	ret[8]='-';
	ret[13]='-';
	ret[18]='-';
	ret[23]='-';
	return ret;
}

std::string Utils::generateUUIDLowerCase() {
	unsigned char content[18];
	RAND_bytes(content, 18);
	std::string ret=str2hex(std::string((char *)content, 18));
	ret[8]='-';
	ret[13]='-';
	ret[18]='-';
	ret[23]='-';
	return ret;
}

uint32_t Utils::safeRandomNumber() {
	uint32_t ret;
	RAND_bytes((unsigned char *)&ret, 4);
	return ret;
}

unsigned char Utils::safeRandomByte() {
	return random_byte_safe();
}

std::string Utils::sha256(std::string const& input) {
	EVP_MD_CTX *mdctx=EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
	EVP_DigestUpdate(mdctx, input.c_str(), input.size());
	unsigned char output[32];
	unsigned int len;
	EVP_DigestFinal_ex(mdctx, output, &len);
	EVP_MD_CTX_destroy(mdctx);
	return str2hex(std::string((char *)output, 32));
}

std::string Utils::writeJSON(Json::Value const& value) {
	Json::StreamWriterBuilder jwb;
	jwb["commentStyle"]="None";
	jwb["indentation"]="";
	return Json::writeString(jwb, value);
}

bool Utils::parseJSON(std::string const& jsonContent, Json::Value *value, std::string *parsingError) {
	Json::CharReaderBuilder builder;
	builder["allowComments"]=false;
	builder["stackLimit"]=16;
	Json::CharReader *reader=builder.newCharReader();
	bool ret=reader->parse(jsonContent.c_str(), jsonContent.c_str()+jsonContent.size(), value, parsingError);
	delete reader;
	return ret;
}

std::string Utils::str2hexUpper(std::string const& input) {
	size_t output_len=input.size()*2;
	char *output=(char*)malloc(output_len+1);
	output[output_len]=0;
	size_t drp;
	int r=OPENSSL_buf2hexstr_ex(output, output_len+1, &drp, (const unsigned char*)input.c_str(), input.length(), '\x00');
	if(!r) {
		throw std::runtime_error("OPENSSL_buf2hexstr_ex: ERROR");
	}
	std::string toret(output);
	free(output);
	return toret;
}

std::string Utils::str2hex(std::string const& input) {
	std::string ret=str2hexUpper(input);
	size_t rl=ret.length();
	for(int i=0;i<rl;i++) {
		ret[i]=tolower(ret[i]);
	}
	return ret;
}

std::string Utils::hex2str(std::string const& input) {
	if(input.length()%2!=0) {
		return "";
	}
	unsigned char *buf=(unsigned char *)malloc(input.length()/2);
	size_t drp;
	int r=OPENSSL_hexstr2buf_ex(buf, input.length()/2, &drp, input.c_str(), 0);
	if(!r) {
		free(buf);
		return "";
	}
	std::string retv((char*)buf, drp);
	free(buf);
	return retv;
}

std::string Utils::base64Encode(std::string const& input) {
	char *out=(char *)malloc(((input.length()+input.length()%3+18)/3)*4);
	int len=EVP_EncodeBlock((unsigned char*)out, (const unsigned char*)input.c_str(), input.length());
	std::string ret(out, len);
	free(out);
	return ret;
}

std::string Utils::base64Decode(std::string const& _input) {
	std::string input(_input);
	while(input.length()%4!=0) {
		input.push_back('=');
	}
	unsigned char *out=(unsigned char *)malloc(3*(input.length()/4)+16);
	int len=EVP_DecodeBlock(out, (const unsigned char*)input.c_str(), input.length());
	if(len==-1) {
		free(out);
		return "";
	}
	std::string ret((char *)out, len);
	free(out);
	return ret;
}
