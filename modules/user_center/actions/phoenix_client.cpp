#include "../user_center.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "cpp-httplib/httplib.h"
#include "utils.h"
#include "secrets.h"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
extern httplib::Client dotcsClient;
extern httplib::Headers DotCS_Headers;
std::string get_check_num(std::string const &data);

namespace FBUC
{
	ACTION6(PhoenixLoginAction, "phoenix/login",
			std::optional<std::string>, login_token, "login_token",
			std::optional<std::string>, _username, "username",
			std::optional<std::string>, _password, "password",
			std::string, server_code, "server_code",
			std::string, server_passcode, "server_passcode",
			std::string, client_public_key, "client_public_key")
	{
		if (session->user)
		{
			throw InvalidRequestDemand{"Already logged in"};
		}
		std::string username;
		std::string password;
		if (!login_token->has_value())
		{
			if (!_username->has_value() || !_password->has_value())
			{
				throw InvalidRequestDemand{"Insufficient arguments"};
			}
			username = **_username;
			// password=Utils::sha256(Secrets::addSalt(**_password));
			password = **_password;
		}
		else
		{
			if (_username->has_value())
			{
				throw InvalidRequestDemand{"Conflicted arguments"};
			}
			Json::Value token_content;
			bool parsed = Utils::parseJSON(FBToken::decrypt(**login_token), &token_content, nullptr);
			if (!parsed || !token_content["username"].isString() || !token_content["password"].isString() || !token_content["newToken"].asBool())
			{
				return {false, "Invalid token"};
			}
			username = token_content["username"].asString();
			password = token_content["password"].asString();
		}
		std::shared_ptr<FBWhitelist::User> pUser = FBWhitelist::Whitelist::acquireUser(username);
		if (!pUser)
		{
			return {false, "无效用户名或一次性密码，注意: 为防止账号盗用，您不再能够使用用户中心的密码登录 PhoenixBuilder ，请使用 FBToken 或用户中心一次性密码登录。"};
		}
		if (!pUser->disable_all_security_measures)
		{
			if (login_token->has_value())
			{
				if (!pUser || pUser->password != password)
				{
					return {false, "Invalid username or password"};
				}
			}
			else
			{
				if (!pUser || Utils::sha256(pUser->phoenix_login_otp) != password)
				{
					return {false, "无效用户名或一次性密码，注意: 为防止账号盗用，您不再能够使用用户中心的密码登录 PhoenixBuilder ，请使用 FBToken 或用户中心一次性密码登录。"};
				}
				pUser->phoenix_login_otp = Utils::generateUUID();
			}
		}
		else
		{
			if (!login_token->has_value())
				password = Utils::sha256(Secrets::addSalt(**_password));
			if (!pUser || pUser->password != password)
			{
				return {false, "Invalid username or password"};
			}
		}

		auto user = pUser;
		if (!user->isDotCS)
		{
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no dotcs power] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "此账户已绑定DotCS,您无法使用本账户登录 FastBuilder APP"};
		}
		if (user->free && !user->expiration_date.stillAlive())
		{
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no payment] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "月额 Plan 失效已过或从未激活，请前往用户中心购买。"};
		}
		if (server_code == "::DRY::" && server_passcode == "::DRY::")
		{
			SPDLOG_INFO("Phoenix login (passed - dry): {}, IP: {}", *user->username, session->ip_address);
			std::string pubKey;
			if (!user->signing_key.has_value())
			{
				auto keyPair = Utils::generateRSAKeyPair();
				FBWhitelist::SigningKeyPair skp;
				skp.private_key = keyPair.first;
				skp.public_key = keyPair.second;
				pubKey = keyPair.second;
				user->signing_key = skp;
			}
			else
			{
				pubKey = (std::string)user->signing_key->public_key;
			}
			std::string privateSigningKeyProve = fmt::format("{}|{}", pubKey, *user->username);
			privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
			session->user = pUser;
			session->phoenix_only = true;
			std::string rettoken = "";
			if (!login_token->has_value())
			{
				Json::Value token;
				token["username"] = username;
				token["password"] = pUser->password;
				token["newToken"] = true;
				rettoken = FBToken::encrypt(token);
			}
			std::string respond_to;
			if (user->cn_username.has_value())
			{
				respond_to = user->cn_username;
			}
			return {true, "well done", "dry", true, "privateSigningKey", user->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
		}
		if (!user->nemc_access_info.has_value())
		{
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no helper] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "未创建辅助用户，请前往用户中心创建。", "translation", 7};
		}
		bool approved = false;
		if (!user->isAdministrator)
		{
			if (!approved && user->rentalservers.size())
			{
				for (auto const &ind : user->rentalservers)
				{
					if (*ind.second.content == *server_code)
					{
						approved = true;
						break;
					}
				}
			}
			if (!approved && !user->isCommercial)
			{
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [unauthorized server code] IP: {}", *user->username, *server_code, session->ip_address);
				return {false, "指定的租赁服号未授权，请前往用户中心设置", "translation", 13};
			}
		}
		NEMCUser nemcUser;
		if (user->nemc_temp_info.has_value())
		{
			nemcUser = user->nemc_temp_info;
		}
		if (!nemcUser.isLoggedIn())
		{
			try
			{
				nemcUser = user->nemc_access_info->auth();
				user->nemc_temp_info = nemcUser;
			}
			catch (NEMCError const &err)
			{
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
				return {false, err.description, "translation", err.translation > 0 ? err.translation : -1};
			}
		}
		std::string helperun;
		try
		{
			helperun = nemcUser.getUsername();
		}
		catch (NEMCError const &err)
		{
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
			return {false, err.description, "translation", err.translation > 0 ? err.translation : -1};
		}
		if (helperun.size() == 0)
		{
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [helper no username] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "辅助用户用户名设置无效，请前往用户中心重新设置", "translation", 9};
		}
		std::pair<std::string, std::string> chainInfo;
		try
		{
			chainInfo = nemcUser.doImpact(server_code, server_passcode, client_public_key, helperun);
		}
		catch (NEMCError const &err)
		{
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
			return {false, err.description, "translation", err.translation > 0 ? err.translation : -1};
		}
		SPDLOG_INFO("Phoenix login (passed): {} -> {}, Helper: {}, IP: {}", *user->username, *server_code, helperun, session->ip_address);
		std::string pubKey;
		if (!user->signing_key.has_value())
		{
			auto keyPair = Utils::generateRSAKeyPair();
			FBWhitelist::SigningKeyPair skp;
			skp.private_key = keyPair.first;
			skp.public_key = keyPair.second;
			pubKey = keyPair.second;
			user->signing_key = skp;
		}
		else
		{
			pubKey = (std::string)user->signing_key->public_key;
		}
		std::string privateSigningKeyProve = fmt::format("{}|{}", pubKey, *user->username);
		privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
		session->user = pUser;
		session->phoenix_only = true;
		std::string rettoken = "";
		if (!login_token->has_value())
		{
			Json::Value token;
			token["username"] = username;
			token["password"] = pUser->password;
			token["newToken"] = true;
			rettoken = FBToken::encrypt(token);
		}
		std::string respond_to;
		if (user->cn_username.has_value())
		{
			respond_to = user->cn_username;
		}
		return {true, "well done", "chainInfo", chainInfo.first, "ip_address", chainInfo.second, "uid", nemcUser.getUID(), "username", helperun, "privateSigningKey", user->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
	}

	 ACTION6(DotCS_APP_LoginAction, "dotcs/login",
		std::optional<std::string>, login_token, "login_token",
		std::optional<std::string>, _username, "username",
		std::optional<std::string>, _password, "password",
		std::string, _server_code, "server_code",
		std::string, _server_passcode, "server_passcode",
		std::string, client_public_key, "client_public_key") {
	
	 	if(session->user) {
	 		throw InvalidRequestDemand{"Already logged in"};
	 	}
	  	std::string username;
	  	std::string password;
	  	std::string server_code;
	  	std::string server_passcode;
	  	bool is_token_login_mode=false;
	  	if(!login_token->has_value()) {
	  		if(!_username->has_value()||!_password->has_value()) {
	  			throw InvalidRequestDemand{"Insufficient arguments"};
	  		}
	  		username=**_username;
	  		//password=Utils::sha256(Secrets::addSalt(**_password));
	  		password=**_password;
	  	}else{
	  		if(_username->has_value()) {
	  			throw InvalidRequestDemand{"Conflicted arguments"};
	  		}
	  		bool is_token_login_mode=false;
			username="__token__";
	  		password=**login_token;
	  		}
	  	server_code = _server_code;
	  	server_passcode = _server_passcode;
	  	Json::Value login_packet;
	  	login_packet["username"] = username;
	  	login_packet["password"] = password;
	  	login_packet["server_code"] = server_code;
	  	login_packet["server_passcode"] = server_passcode;
		login_packet["ip"] = session->ip_address;
	 	Json::StreamWriterBuilder writebuild;
	 	writebuild["emitUTF8"] = true;
	 	std::string login_text = Json::writeString(writebuild, login_packet);


		// 辅助用户部分未测试
	 	if (auto res = dotcsClient.Post("/fbuc_api/fb_app_login", DotCS_Headers, login_text, "application/json"))
	 	{
	 		if (res->status == 200)
	 		{
	
	 			Json::CharReaderBuilder ReaderBuilder;
	 			ReaderBuilder["emitUTF8"] = true;
	 			std::unique_ptr<Json::CharReader> charread(ReaderBuilder.newCharReader());
	 			std::string data = res->body;
	 			Json::Value root;
	 			std::string strerr;
	 			bool isok = charread->parse(data.c_str(), data.c_str() + data.size(), &root, &strerr);
	 			if (!isok || strerr.size() != 0)
	 			{
	 				return {false, "DotCS验证服务器的消息解析失败,可能是DotCS服务器未开启此接口。"};
	 			}
	 			bool success = root.get("success", false).asBool();
	 			if (success == true)
	 			{
	 				std::string fb_username = root.get("fb_name", "").asString();
	 				if (fb_username == "")
	 				{
	 					return {false, "FastBuilder未能成功获取到DotCS用户信息,请联系 DotCS 解决。"};
	 				}
	 				std::shared_ptr<FBWhitelist::User> pUser = FBWhitelist::Whitelist::acquireUser(fb_username);
	 				if (!pUser)
	 				{
	 					SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
	 					return {false, "无效的FastBuilder账户"};
	 				}
	 				if (!pUser->isDotCS)
	 				{
	 					SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
	 					return {false, "此账户在FastBuilder的记录中尚未绑定,请联系FastBuilder管理员进行绑定。"};
	 				}
	 				else
	 				{
						if (server_code == "::DRY::" && server_passcode == "::DRY::")
						{
							SPDLOG_INFO("Phoenix login (passed - dry): {}, IP: {}", pUser->username, session->ip_address);
							std::string pubKey;
							if (!pUser->signing_key.has_value())
							{
								auto keyPair = Utils::generateRSAKeyPair();
								FBWhitelist::SigningKeyPair skp;
								skp.private_key = keyPair.first;
								skp.public_key = keyPair.second;
								pubKey = keyPair.second;
								pUser->signing_key = skp;
							}
							else
							{
								pubKey = (std::string)pUser->signing_key->public_key;
							}
							std::string privateSigningKeyProve = fmt::format("{}|{}", pubKey, pUser->username);
							privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
							session->user = pUser;
							session->phoenix_only = true;
							std::string rettoken = "";
							if (!login_token->has_value())
							{
								Json::Value token;
								token["username"] = username;
								token["password"] = pUser->password;
								token["newToken"] = true;
								rettoken = FBToken::encrypt(token);
							}
							std::string respond_to;
							if (pUser->cn_username.has_value())
							{
								respond_to = pUser->cn_username;
							}
							return {true, "well done", "dry", true, "privateSigningKey", pUser->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
						}
						if (!pUser->nemc_access_info.has_value())
						{
							SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no helper] IP: {}", pUser->username, server_code, session->ip_address);
							return {false, "未创建辅助用户，请前往FastBuilder 用户中心创建。", "translation", 7};
						}
						NEMCUser nemcUser;
						if (pUser->nemc_temp_info.has_value())
						{
							nemcUser = pUser->nemc_temp_info;
						}
						if (!nemcUser.isLoggedIn())
						{
							try
							{
								nemcUser = pUser->nemc_access_info->auth();
								pUser->nemc_temp_info = nemcUser;
							}
							catch (NEMCError const &err)
							{
								SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", pUser->username, server_code, err.description, session->ip_address);
								return {false, err.description, "translation", err.translation > 0 ? err.translation : -1};
							}
						}
						std::string helperun;
						try
						{
							helperun = nemcUser.getUsername();
						}
						catch (NEMCError const &err)
						{
							SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", pUser->username, server_code, err.description, session->ip_address);
							return {false, err.description, "translation", err.translation > 0 ? err.translation : -1};
						}
						if (helperun.size() == 0)
						{
							SPDLOG_INFO("Phoenix login (rejected): {} -> {} [helper no username] IP: {}", pUser->username, server_code, session->ip_address);
							return {false, "辅助用户用户名设置无效，请前往用户中心重新设置", "translation", 9};
						}
						std::pair<std::string, std::string> chainInfo;
						try
						{
							chainInfo = nemcUser.doImpact(server_code, server_passcode, client_public_key, helperun);
						}
						catch (NEMCError const &err)
						{
							SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", pUser->username, server_code, err.description, session->ip_address);
							return {false, err.description, "translation", err.translation > 0 ? err.translation : -1};
						}
						SPDLOG_INFO("Phoenix login (passed): {} -> {}, Helper: {}, IP: {}", pUser->username, server_code, helperun, session->ip_address);
						std::string pubKey;
						if (!pUser->signing_key.has_value())
						{
							auto keyPair = Utils::generateRSAKeyPair();
							FBWhitelist::SigningKeyPair skp;
							skp.private_key = keyPair.first;
							skp.public_key = keyPair.second;
							pubKey = keyPair.second;
							pUser->signing_key = skp;
						}
						else
						{
							pubKey = (std::string)pUser->signing_key->public_key;
						}
						std::string privateSigningKeyProve = fmt::format("{}|{}", pubKey, pUser->username);
						privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
						session->user = pUser;
						session->phoenix_only = true;
						std::string rettoken = "";
						if (!login_token->has_value())
						{
							Json::Value token;
							token["username"] = username;
							token["password"] = pUser->password;
							token["newToken"] = true;
							rettoken = FBToken::encrypt(token);
						}
						std::string respond_to;
						if (pUser->cn_username.has_value())
						{
							respond_to = pUser->cn_username;
						}
						return {true, "well done", "chainInfo", chainInfo.first, "ip_address", chainInfo.second, "uid", nemcUser.getUID(), "username", helperun, "privateSigningKey", pUser->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
	 				}
	 			}
	 			else
	 			{
	 				return {false, root.get("message", "未知DotCS验证服务器错误").asString()};
	 			}
	 		}
	 		else
	 		{
	 			return {false, "DotCS验证服务器无法服务或验证未通过"};
	 		}
	 	}
	 	else
	 	{
	 		return {false, "DotCS验证服务器暂时无法访问,请等待恢复"};
	 	}













		}
	// ACTION6(PhoenixLoginAction, "dotcs/login",
	// 		std::optional<std::string>, login_token, "login_token",
	// 		std::optional<std::string>, _username, "username",
	// 		std::optional<std::string>, _password, "password",
	// 		std::string, server_code, "server_code",
	// 		std::string, server_passcode, "server_passcode",
	// 		std::string, client_public_key, "client_public_key") {
	// 	if(session->user) {
	// 		throw InvalidRequestDemand{"Already logged in"};
	// 	}
	// 	std::string username;
	// 	std::string password;
	// 	bool is_token_login_mode=false;
	// 	if(!login_token->has_value()) {
	// 		if(!_username->has_value()||!_password->has_value()) {
	// 			throw InvalidRequestDemand{"Insufficient arguments"};
	// 		}
	// 		username=**_username;
	// 		//password=Utils::sha256(Secrets::addSalt(**_password));
	// 		password=**_password;
	// 	}else{
	// 		if(_username->has_value()) {
	// 			throw InvalidRequestDemand{"Conflicted arguments"};
	// 		}
	// 		bool is_token_login_mode=false;
	// 		Json::Value token_content;
	// 		bool parsed=Utils::parseJSON(FBToken::decrypt(**login_token), &token_content, nullptr);
	// 		if(!parsed||!token_content["username"].isString()||!token_content["password"].isString()||!token_content["newToken"].asBool()) {
	// 			return {false, "Invalid token"};
	// 		}
	// 		username="__token__";
	// 		password=**login_token;
	// 		}
	// 	Json::Value login_packet;
	// 	login_packet["username"] = username;
	// 	login_packet["password"] = password;
	 //
	// 	Json::StreamWriterBuilder writebuild;
	// 	writebuild["emitUTF8"] = true;
	// 	std::string login_text = Json::writeString(writebuild, login_packet);
	// 	if (auto res = dotcsClient.Post("/fbuc_api/fb_app_login", DotCS_Headers, login_text, "application/json"))
	// 	{
	// 		if (res->status == 200)
	// 		{
	 //
	// 			Json::CharReaderBuilder ReaderBuilder;
	// 			ReaderBuilder["emitUTF8"] = true;
	// 			std::unique_ptr<Json::CharReader> charread(ReaderBuilder.newCharReader());
	// 			std::string data = res->body;
	// 			Json::Value root;
	// 			std::string strerr;
	// 			bool isok = charread->parse(data.c_str(), data.c_str() + data.size(), &root, &strerr);
	// 			if (!isok || strerr.size() != 0)
	// 			{
	// 				return {false, "DotCS验证服务器的消息解析失败,可能是DotCS服务器未开启此接口。"};
	// 			}
	// 			bool success = root.get("success", false).asBool();
	// 			if (success == true)
	// 			{
	// 				std::string fb_username = root.get("fb_name", "").asString();
	// 				if (fb_username == "")
	// 				{
	// 					return {false, "FastBuilder未能成功获取到DotCS用户信息,请联系 DotCS 解决。"};
	// 				}
	// 				std::shared_ptr<FBWhitelist::User> pUser = FBWhitelist::Whitelist::acquireUser(fb_username);
	// 				if (!pUser)
	// 				{
	// 					SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
	// 					return {false, "无效的FastBuilder账户","translation"};
	// 				}
	// 				else if (pUser->DotCS_User_Name != username)
	// 				{
	// 					SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
	// 					return {false, "此账户绑定的FastBuilder用户名与FastBuilder所记载的不一致。如果您的DotCS用户名或FastBuilder用户名被更改了,可联系另一个平台的管理员进行更正"};
	// 				}
	// 				if (!pUser->isDotCS)
	// 				{
	// 					SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
	// 					return {false, "此账户在FastBuilder的记录中尚未绑定,请联系FastBuilder管理员进行绑定。"};
	// 				}
	// 				else
	// 				{
	// 					FBWhitelist::User *rawUser = pUser.get();
	// 					if (user_unique_map.contains(rawUser))
	// 					{
	// 						userlist_mutex.lock();
	// 						userlist.erase(user_unique_map[rawUser]);
	// 						user_unique_map[rawUser] = session->session_id;
	// 						userlist_mutex.unlock();
	// 					}
	// 					else
	// 					{
	// 						userlist_mutex.lock();
	// 						user_unique_map[rawUser] = session->session_id;
	// 						userlist_mutex.unlock();
	// 					}
	// 					session->user = pUser;
	// 					std::string user_theme = pUser->preferredtheme.has_value() ? (*pUser->preferredtheme) : "bootstrap";
	// 					session->token_login = false;
	// 					session->phoenix_only = false;
	// 					*pUser->keep_reference = true;
	// 					if(server_code=="::DRY::"&&server_passcode=="::DRY::") {
	// 						SPDLOG_INFO("Phoenix login (DotCS APP) (passed - dry): {}, IP: {}", fb_username, session->ip_address);
	// 						std::string pubKey;
	// 						if(!user->signing_key.has_value()) {
	// 							auto keyPair=Utils::generateRSAKeyPair();
	// 							FBWhitelist::SigningKeyPair skp;
	// 							skp.private_key=keyPair.first;
	// 							skp.public_key=keyPair.second;
	// 							pubKey=keyPair.second;
	// 							user->signing_key=skp;
	// 						}else{
	// 							pubKey=(std::string)user->signing_key->public_key;
	// 						}
	// 						std::string privateSigningKeyProve=fmt::format("{}|{}", pubKey, fb_username);
	// 						privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
	// 						session->user=pUser;
	// 						session->phoenix_only=true;
	// 						std::string rettoken="";
	// 						if(!login_token->has_value()) {
	// 							Json::Value token;
	// 							token["username"]=username;
	// 							token["password"]=pUser->password;
	// 							token["newToken"]=true;
	// 							rettoken=FBToken::encrypt(token);
	// 						}
	// 						std::string respond_to;
	// 						if(user->cn_username.has_value()) {
	// 							respond_to=user->cn_username;
	// 						}
	// 						return {true, "well done", "dry", true, "privateSigningKey", user->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
	// 					}
	// 					if(!pUser->nemc_access_info.has_value()) {
	// 						SPDLOG_INFO("Phoenix login (DotCS APP)(rejected): {} -> {} [no helper] IP: {}", fb_username, *server_code, session->ip_address);
	// 						return {false, "未创建辅助用户，请前往幻梦互联用户中心创建。", "translation", -1};
	// 					}
	// 					return {false, "测试消息", "translation", -1};
	// 					//SPDLOG_INFO("User Center login (passed-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
	// 					//return {true, "Welcome", "theme", user_theme, "isadmin", *pUser->isAdministrator};
	// 				}
	// 			}
	// 			else
	// 			{
	// 				return {false, root.get("message", "未知DotCS验证服务器错误").asString()};
	// 			}
	// 		}
	// 		else
	// 		{
	// 			return {false, "DotCS验证服务器无法服务或验证未通过"};
	// 		}
	// 	}
	// 	else
	// 	{
	// 		return {false, "DotCS验证服务器暂时无法访问,请等待恢复"};
	// 	}
	// }
	LACTION1(PhoenixTransferStartTypeAction, "phoenix/transfer_start_type",
			 std::string, content, "content")
	{
		if (!session->user->nemc_temp_info.has_value())
		{
			throw ServerErrorDemand{"No login found"};
		}
		return {true, "", "data", NEMCCalculateStartType(content, session->user->nemc_temp_info->getUID())};
	}

	LACTION1(PhoenixTransferChecknumAction, "phoenix/transfer_check_num",
			 std::string, data, "data")
	{
		auto v = get_check_num(data);
		if (!v.length())
		{
			return {false, "Failed"};
		}
		return {true, "Perfect", "value", v};
	}

	LACTION0(GetPhoenixTokenAction, "get_phoenix_token")
	{
		DirectReturnDemand d;
		d.type = "text/plain";
		Json::Value token;
		token["username"] = session->user->username;
		token["password"] = session->user->password;
		token["newToken"] = true;
		d.content = FBToken::encrypt(token);
		d.disposition = "attachment;filename=fbtoken";
		throw d;
	}

	static FBUCActionCluster phoenixClientActions(0, {Action::enmap(new PhoenixLoginAction),
													  Action::enmap(new DotCS_APP_LoginAction),
													  Action::enmap(new PhoenixTransferStartTypeAction),
													  Action::enmap(new PhoenixTransferChecknumAction),
													  Action::enmap(new GetPhoenixTokenAction)});
};
