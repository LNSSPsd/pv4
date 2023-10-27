#pragma once
#if !__has_include("modules/private/nemc_helper.h")

#ifndef NEMC_HELPER_PRIVATE_HEADER_INCLUDED

#include <bsoncxx/document/element.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/builder/stream/array.hpp>
#include <variant>
#include <optional>

struct NEMCError {
	std::string description;
	int translation=-1;
};

class NEMCUser {
private:
	std::string some_secret;
	
	bsoncxx::array::value stored_arr_value = bsoncxx::builder::stream::array{}<<bsoncxx::builder::stream::finalize;
public:
	NEMCUser() { };
	NEMCUser(bsoncxx::document::element const& userInfo);
	operator bsoncxx::array::view();
	
	bool isLoggedIn() const;
	std::string getUsername() const;
	void setUsername(std::string const& username) const;
	std::pair<std::string, std::string> doImpact(std::string const& serverCode, std::string const& serverPasscode, std::string const& clientKey, std::string const& username) const;
	inline std::string getUID() const { return "0"; };
	
	bool operator==(NEMCUser const& value) const;
	
	friend class NEMCUserAuthInfo;
};

class NEMCUserAuthInfo {
private:
	std::string some_sercret;
public:
	std::string verify_url="https://google.com";
	std::string randid_used;
private:
	bsoncxx::array::value stored_arr_value = bsoncxx::builder::stream::array{}<<bsoncxx::builder::stream::finalize;
public:
	NEMCUserAuthInfo() { };
	NEMCUserAuthInfo(bsoncxx::document::element const& authInfo);
	operator bsoncxx::array::view();
	std::string getJitsuMeiAddress() const;
	NEMCUser auth() const;
	
	bool operator==(NEMCUserAuthInfo const& value) const;
	inline bool has_user() const { return false; }
	inline bool has_device() const { return false; }
	
	
	static NEMCUserAuthInfo loginWithEmail(std::string const& email, std::string const& password, std::string const& randId);
	static NEMCUserAuthInfo createGuest(std::string const& randId);
	static NEMCUserAuthInfo createGuest(NEMCUserAuthInfo const& device);
};

std::string NEMCCalculateStartType(std::string const& content, std::string const& uid);

#endif

#else

#include "modules/private/nemc_helper.h"

#endif