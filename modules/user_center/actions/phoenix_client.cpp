#include "../user_center.h"
#include "utils.h"
#include "secrets.h"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

std::string get_check_num(std::string const& data);

namespace FBUC {
	ACTION6(PhoenixLoginAction, "phoenix/login",
			std::optional<std::string>, login_token, "login_token",
			std::optional<std::string>, _username, "username",
			std::optional<std::string>, _password, "password",
			std::string, server_code, "server_code",
			std::string, server_passcode, "server_passcode",
			std::string, client_public_key, "client_public_key") {
		if(session->user) {
			throw InvalidRequestDemand{"Already logged in"};
		}
		std::string username;
		std::string password;
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
			Json::Value token_content;
			bool parsed=Utils::parseJSON(FBToken::decrypt(**login_token), &token_content, nullptr);
			if(!parsed||!token_content["username"].isString()||!token_content["password"].isString()||!token_content["newToken"].asBool()) {
				return {false, "Invalid token"};
			}
			username=token_content["username"].asString();
			password=token_content["password"].asString();
		}
		std::shared_ptr<FBWhitelist::User> pUser=FBWhitelist::Whitelist::acquireUser(username);
		if(!pUser) {
			return {false, "无效用户名或一次性密码，注意: 为防止账号盗用，您不再能够使用用户中心的密码登录 PhoenixBuilder ，请使用 FBToken 或用户中心一次性密码登录。"};
		}
		if(!pUser->disable_all_security_measures) {
			if(login_token->has_value()) {
				if(!pUser||pUser->password!=password) {
					return {false, "Invalid username or password"};
				}
			}else{
				if(!pUser||Utils::sha256(pUser->phoenix_login_otp)!=password) {
					return {false, "无效用户名或一次性密码，注意: 为防止账号盗用，您不再能够使用用户中心的密码登录 PhoenixBuilder ，请使用 FBToken 或用户中心一次性密码登录。"};
				}
				pUser->phoenix_login_otp=Utils::generateUUID();
			}
		}else{
			if(!login_token->has_value())
				password=Utils::sha256(Secrets::addSalt(**_password));
			if(!pUser||pUser->password!=password) {
				return {false, "Invalid username or password"};
			}
		}
		auto user=pUser;
		if(user->free&&!user->expiration_date.stillAlive()) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no payment] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "月额 Plan 失效已过或从未激活，请前往用户中心购买。"};
		}
		if(server_code=="::DRY::"&&server_passcode=="::DRY::") {
			SPDLOG_INFO("Phoenix login (passed - dry): {}, IP: {}", *user->username, session->ip_address);
			std::string pubKey;
			if(!user->signing_key.has_value()) {
				auto keyPair=Utils::generateRSAKeyPair();
				FBWhitelist::SigningKeyPair skp;
				skp.private_key=keyPair.first;
				skp.public_key=keyPair.second;
				pubKey=keyPair.second;
				user->signing_key=skp;
			}else{
				pubKey=(std::string)user->signing_key->public_key;
			}
			std::string privateSigningKeyProve=fmt::format("{}|{}", pubKey, *user->username);
			privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
			session->user=pUser;
			session->phoenix_only=true;
			std::string rettoken="";
			if(!login_token->has_value()) {
				Json::Value token;
				token["username"]=username;
				token["password"]=pUser->password;
				token["newToken"]=true;
				rettoken=FBToken::encrypt(token);
			}
			std::string respond_to;
			if(user->cn_username.has_value()) {
				respond_to=user->cn_username;
			}
			return {true, "well done", "dry", true, "privateSigningKey", user->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
		}
		if(!user->nemc_access_info.has_value()) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no helper] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "未创建辅助用户，请前往用户中心创建。", "translation", 7};
		}
		bool approved=false;
		if(!user->isAdministrator) {
			if(!approved&&user->rentalservers.size()) {
				for(auto const& ind:user->rentalservers) {
					if(*ind.second.content==*server_code) {
						approved=true;
						break;
					}
				}
			}
			if(!approved&&!user->isCommercial) {
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [unauthorized server code] IP: {}", *user->username, *server_code, session->ip_address);
				return {false, "指定的租赁服号未授权，请前往用户中心设置", "translation", 13};
			}
		}
		NEMCUser nemcUser;
		if(user->nemc_temp_info.has_value()) {
			nemcUser=user->nemc_temp_info;
		}
		if(!nemcUser.isLoggedIn()) {
			try {
				nemcUser=user->nemc_access_info->auth();
				user->nemc_temp_info=nemcUser;
			}catch(NEMCError const& err) {
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
				return {false, err.description, "translation", err.translation>0?err.translation:-1};
			}
		}
		std::string helperun;
		try {
			helperun=nemcUser.getUsername();
		}catch(NEMCError const& err) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
			return {false, err.description, "translation", err.translation>0?err.translation:-1};
		}
		if(helperun.size()==0) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [helper no username] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "辅助用户用户名设置无效，请前往用户中心重新设置", "translation", 9};
		}
		std::pair<std::string, std::string> chainInfo;
		try {
			chainInfo=nemcUser.doImpact(server_code, server_passcode, client_public_key, helperun);
		}catch(NEMCError const& err) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
			return {false, err.description, "translation", err.translation>0?err.translation:-1};
		}
		SPDLOG_INFO("Phoenix login (passed): {} -> {}, Helper: {}, IP: {}", *user->username, *server_code, helperun, session->ip_address);
		std::string pubKey;
		if(!user->signing_key.has_value()) {
			auto keyPair=Utils::generateRSAKeyPair();
			FBWhitelist::SigningKeyPair skp;
			skp.private_key=keyPair.first;
			skp.public_key=keyPair.second;
			pubKey=keyPair.second;
			user->signing_key=skp;
		}else{
			pubKey=(std::string)user->signing_key->public_key;
		}
		std::string privateSigningKeyProve=fmt::format("{}|{}", pubKey, *user->username);
		privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
		session->user=pUser;
		session->phoenix_only=true;
		std::string rettoken="";
		if(!login_token->has_value()) {
			Json::Value token;
			token["username"]=username;
			token["password"]=pUser->password;
			token["newToken"]=true;
			rettoken=FBToken::encrypt(token);
		}
		std::string respond_to;
		if(user->cn_username.has_value()) {
			respond_to=user->cn_username;
		}
		return {true, "well done", "chainInfo", chainInfo.first, "ip_address", chainInfo.second, "uid", nemcUser.getUID(), "username", helperun, "privateSigningKey", user->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
	}
	
	LACTION1(PhoenixTransferStartTypeAction, "phoenix/transfer_start_type",
			std::string, content, "content") {
		if(!session->user->nemc_temp_info.has_value()) {
			throw ServerErrorDemand{"No login found"};
		}
		return {true, "", "data", NEMCCalculateStartType(content, session->user->nemc_temp_info->getUID())};
	}
	
	LACTION1(PhoenixTransferChecknumAction, "phoenix/transfer_check_num",
			std::string, data, "data") {
		auto v=get_check_num(data);
		if(!v.length()) {
			return {false, "Failed"};
		}
		return {true, "Perfect", "value", v};
	}
	
	LACTION0(GetPhoenixTokenAction, "get_phoenix_token") {
		DirectReturnDemand d;
		d.type="text/plain";
		Json::Value token;
		token["username"]=session->user->username;
		token["password"]=session->user->password;
		token["newToken"]=true;
		d.content=FBToken::encrypt(token);
		d.disposition="attachment;filename=fbtoken";
		throw d;
	}
	
	static FBUCActionCluster phoenixClientActions(0, {
		Action::enmap(new PhoenixLoginAction),
		Action::enmap(new PhoenixTransferStartTypeAction),
		Action::enmap(new PhoenixTransferChecknumAction),
		Action::enmap(new GetPhoenixTokenAction)
	});
};
