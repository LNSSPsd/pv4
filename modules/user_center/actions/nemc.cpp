#include "../user_center.h"
#include "nemc_helper.h"
#include <fmt/format.h>

namespace FBUC {
	LACTION0(GetHelperStatusAction, "get_helper_status") {
		FBWhitelist::User *user=session->user.get();
		if(!user->nemc_access_info.has_value()||!user->nemc_access_info->has_user()||(user->free&&!user->expiration_date.stillAlive())) {
			return {true, "success", "set", false};
		}
		std::string un="???";
		try {
			NEMCUser nemcUser;
			if(user->nemc_temp_info.has_value()) {
				nemcUser=user->nemc_temp_info;
			}
			if(!nemcUser.isLoggedIn()) {
				try {
					nemcUser=user->nemc_access_info->auth();
					user->nemc_temp_info=nemcUser;
				}catch(NEMCError const& err) {
					if(err.translation==-2) {
						try {
							auto addr=user->nemc_access_info->getJitsuMeiAddress();
							return {true, "ok", "set", true, "need_realname", true, "realname_addr", addr};
						}catch(NEMCError const& rverr) {
							return {false, "Identification verification is required, but failed to get address."};
						}
					}
					throw std::runtime_error(err.description);
				}
			}
			un=nemcUser.getUsername();
		}catch(std::exception const& err) {
			//SPDLOG_DEBUG("GetHelperStatus: Error: {}", err.what());
		}catch(NEMCError const& err) {
			//SPDLOG_DEBUG("GetHelperStatus: Error: {}", err.description);
		}
		return {true, "ok", "set", true, "need_realname", false, "username", un};
	}
	
	LACTION1(HelperOperationAction, "helper_operation",
			std::optional<std::string>, username, "username") {
		FBWhitelist::User *user=session->user.get();
		if(user->free&&!user->expiration_date.stillAlive()) {
			return {false, "月额 Plan 未激活"};
		}
		if(username->has_value()) {
			if((*username)->length()<6||(*username)->length()>16) {
				return {false, "辅助用户 昵称长度不得少于 7 字符或长于 16 字符。"};
			}
		}
		try {
			NEMCUser nemcUser;
			if(!user->nemc_access_info.has_value()||!user->nemc_access_info->has_user()) {
				NEMCUserAuthInfo authInfo;
				if(user->nemc_access_info.has_value()&&!user->nemc_access_info->has_user()) {
					try {
						authInfo=NEMCUserAuthInfo::createGuest(*user->nemc_access_info);
					}catch(NEMCError const& err) {
						return {false, "Failed to create guest"};
					}
				}else{
					try {
						authInfo=NEMCUserAuthInfo::createGuest(session->device_creation_randid);
					}catch(NEMCError const& err) {
						return {false, "Failed to create guest"};
					}
				}
				if(!authInfo.has_device()&&authInfo.verify_url.size()) {
					session->device_creation_randid=authInfo.randid_used;
					return {false, "请按指示完成网易验证码验证后再试", "verify_url", authInfo.verify_url};
				}
				user->nemc_access_info=authInfo;
				if(!authInfo.has_user()&&authInfo.verify_url.size()) {
					return {false, "请按指示完成网易验证码验证后再试", "verify_url", authInfo.verify_url};
				}
				try {
					nemcUser=authInfo.auth();
					user->nemc_temp_info=nemcUser;
				}catch(NEMCError const& err) {
					if(err.translation==-2) {
						return {false, fmt::format("Failed to authenticate: {}", err.description), "need_realname", true};
					}
					return {false, fmt::format("Failed to authenticate: {}", err.description)};
				}
			}else{
				if(user->nemc_temp_info.has_value()) {
					nemcUser=user->nemc_temp_info;
				}
				if(!nemcUser.isLoggedIn()) {
					try {
						nemcUser=user->nemc_access_info->auth();
					}catch(NEMCError const& err) {
						return {false, fmt::format("Failed to authenticate to server: {}", err.description)};
					}
					user->nemc_temp_info=nemcUser;
				}
			}
			try {
				nemcUser.setUsername(**username);
			}catch(NEMCError const& error_val) {
				return {false, fmt::format("Failed to set username: {}", error_val.description)};
			}
		}catch(std::exception const& err) {
			return {false, "Unknown exception occured"};
		}
		return {true, "ok"};
	}
	
	LACTION2(BindNeteaseAccountAction, "bind_netease_account_action",
			std::string, email, "email",
			std::string, password, "password") {
		return {false, "暂未开放"};
		if(password->length()!=32) {
			return {false, "无效请求"};
		}
		try {
			NEMCUserAuthInfo authInfo=NEMCUserAuthInfo::loginWithEmail(email, password, session->device_creation_randid);
			if(authInfo.verify_url.size()) {
				session->device_creation_randid=authInfo.randid_used;
				return {false, "请按指示完成网易验证码验证后再试", "verify_url", authInfo.verify_url};
			}
			session->user->nemc_binded_account=authInfo;
		}catch(NEMCError const& err) {
			return {false, err.description};
		}
		return {true};
	}
	
	static FBUCActionCluster nemcGeneralActions(0, {
		Action::enmap(new GetHelperStatusAction),
		Action::enmap(new HelperOperationAction),
		Action::enmap(new BindNeteaseAccountAction)
	});
};