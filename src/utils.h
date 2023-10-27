#pragma once
#include <json/json.h>

class FBToken {
public:
	static std::string encrypt(std::string const& value);
	static std::string encrypt(Json::Value const& value);
	
	static std::string decrypt(std::string const& token);
};

namespace Utils {
	// private, public
	std::pair<std::string, std::string> generateRSAKeyPair();
	std::string cv4Sign(std::string const& content);
	
	std::string generateUUID();
	std::string generateUUIDLowerCase();
	unsigned char safeRandomByte();
	uint32_t safeRandomNumber();
	std::string sha256(std::string const& value);
	std::string writeJSON(Json::Value const& value);
	bool parseJSON(std::string const& jsonContent, Json::Value *value, std::string *parsingError=nullptr);
	std::string str2hexUpper(std::string const& input);
	std::string str2hex(std::string const& input);
	std::string hex2str(std::string const& input);
	std::string base64Encode(std::string const& input);
	std::string base64Decode(std::string const& input);
};