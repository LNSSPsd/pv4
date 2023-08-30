#include "../user_center.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "cpp-httplib/httplib.h"
#include "utils.h"
#include "secrets.h"
#include "Captcha.h"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <regex>
#include <openssl/hmac.h>

extern httplib::Client dotcsClient;
extern httplib::Headers DotCS_Headers;
static int hmac_algo_sha1(const char *byte_secret, const char *byte_string, char *out)
{
	unsigned int len = 20;
	unsigned char *result = HMAC(EVP_sha1(), (unsigned char *)byte_secret, 10, (unsigned char *)byte_string, 8, (unsigned char *)out, &len);
	return result == 0 ? 0 : len;
}

static uint64_t get_current_time()
{
	using namespace std::chrono;
	auto now = system_clock::now();
	auto dur = now.time_since_epoch();
	return duration_cast<std::chrono::seconds>(dur).count();
}

namespace FBUC
{
	ACTION2(APIListAction, "api",
			std::optional<std::string>, with_prefix, "with_prefix",
			std::optional<std::string>, jump_to, "jump_to")
	{
		std::string prefix = with_prefix->has_value() ? **with_prefix : "";
		struct ActionResult result = {true, "ok"};
		bool include_login_only = (bool)session->user;
		for (auto const &i : fbuc_actions)
		{
			if (include_login_only || !i.second->mandatory_login())
			{
				result.additional_items[i.second->action_name] = fmt::format("{}/api/{}", prefix, i.second->action_name);
			}
		}
		if (jump_to->has_value())
		{
			if (result.additional_items[**jump_to])
			{
				throw RedirectDemand{result.additional_items[**jump_to].asString()};
			}
			else
			{
				return {false, "No such entry to jump to."};
			}
		}
		if (session->user && session->user->isAdministrator)
		{
			Json::Value ext_map;
			for (auto const &i : fbuc_administrative_actions)
			{
				ext_map[i.second->action_name] = fmt::format("{}/api/administrative/{}", prefix, i.second->action_name);
			}
			result.additional_items["ext"] = ext_map;
		}
		if (session->user)
		{
			result.additional_items["username"] = *session->user->username;
			result.additional_items["is_DotCS"] = *session->user->isDotCS;
			result.additional_items["DotCS_User_Name"] = *session->user->DotCS_User_Name;
			result.additional_items["theme"] = session->user->preferredtheme.has_value() ? *session->user->preferredtheme : "bootstrap";
		}
		return result;
	}

	ACTION4(LoginAction, "login",
			std::optional<std::string>, _username, "username",
			std::optional<std::string>, _password, "password",
			std::string, mfa_code, "mfa_code",
			std::optional<std::string>, token, "token")
	{
		if (session->user)
		{
			throw InvalidRequestDemand{"Already logged in"};
		}
		std::string username;
		std::string password;
		bool is_token_login = false;
		if (!token->has_value())
		{
			if (!_username->has_value() || !_password->has_value())
			{
				throw InvalidRequestDemand{"Insufficient arguments"};
			}
			username = **_username;
			password = Utils::sha256(Secrets::addSalt(**_password));
		}
		else
		{
			is_token_login = true;
			if (_username->has_value())
			{
				throw InvalidRequestDemand{"Conflicted arguments"};
			}
			Json::Value token_content;
			bool parsed = Utils::parseJSON(FBToken::decrypt(**token), &token_content, nullptr);
			if (!parsed || !token_content["username"].isString() || !token_content["password"].isString() || !token_content["newToken"].asBool())
			{
				return {false, "Invalid token"};
			}
			username = token_content["username"].asString();
			password = token_content["password"].asString();
		}
		std::shared_ptr<FBWhitelist::User> pUser = FBWhitelist::Whitelist::acquireUser(username);
		if (!pUser || pUser->password != password)
		{
			SPDLOG_INFO("User Center login (rejected): Username: {}, IP: {}", username, session->ip_address);
			return {false, "Invalid username, password, or MFA code."};
		}
		if (!pUser->disable_all_security_measures)
		{
			if (pUser->two_factor_authentication_secret.has_value() && pUser->two_factor_authentication_secret->length() != 15)
			{
				if (mfa_code->length() != 6)
				{
					SPDLOG_INFO("User Center login (rejected): Username: {}, IP: {}", username, session->ip_address);
					return {false, "Invalid username, password, or MFA code."};
				}
				char secret[17];
				OTPData data;
				totp_new(&data, pUser->two_factor_authentication_secret->c_str(), hmac_algo_sha1, get_current_time, 6, 30);
				int val = totp_verify(&data, mfa_code->c_str(), time(nullptr), 2);
				if (!val)
				{
					return {false, "Invalid username, password, or MFA code."};
				}
			}
			else
			{
				if (is_token_login || mfa_code->length() != 0)
				{
					// 1. Token login but no MFA set
					// 2. No MFA set but requester gives a MFA
					SPDLOG_INFO("User Center login (rejected): Username: {}, IP: {}", username, session->ip_address);
					return {false, "Invalid username, password, or MFA code."};
				}
			}
		}

		FBWhitelist::User *rawUser = pUser.get();
		if (user_unique_map.contains(rawUser))
		{
			userlist_mutex.lock();
			userlist.erase(user_unique_map[rawUser]);
			user_unique_map[rawUser] = session->session_id;
			userlist_mutex.unlock();
		}
		else
		{
			userlist_mutex.lock();
			user_unique_map[rawUser] = session->session_id;
			userlist_mutex.unlock();
		}
		if (*pUser->isDotCS)
		{
			SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", username, session->ip_address);
			return {false, "此账户已绑定 DotCS,请使用 DotCS 账户登录。"};
		}
		else
		{
			session->user = pUser;
			std::string user_theme = pUser->preferredtheme.has_value() ? (*pUser->preferredtheme) : "bootstrap";
			session->token_login = token->has_value();
			session->phoenix_only = false;
			*pUser->keep_reference = true;
			SPDLOG_INFO("User Center login (passed): Username: {}, IP: {}", username, session->ip_address);
			return {true, "Welcome", "theme", user_theme, "isadmin", *pUser->isAdministrator};
		}
	}
	ACTION2(Login_DotCS_Action, "login_dotcs",
			std::optional<std::string>, _username, "username",
			std::optional<std::string>, _password, "password")
	{
		if (!_username->has_value() || !_password->has_value())
		{
			throw InvalidRequestDemand{"Insufficient arguments"};
		}
		std::string username;
		std::string password;
		if (session->user)
		{
			throw InvalidRequestDemand{"Already logged in"};
		}
		username = **_username;
		password = **_password;
		Json::Value login_packet;
		login_packet["username"] = username;
		login_packet["password"] = password;

		Json::StreamWriterBuilder writebuild;
		writebuild["emitUTF8"] = true;
		std::string login_text = Json::writeString(writebuild, login_packet);
		if (auto res = dotcsClient.Post("/fbuc_api/fb_user_login", DotCS_Headers, login_text, "application/json"))
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
					else if (pUser->DotCS_User_Name != username)
					{
						SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
						return {false, "此账户绑定的FastBuilder用户名与FastBuilder所记载的不一致。如果您的DotCS用户名或FastBuilder用户名被更改了,可联系另一个平台的管理员进行更正"};
					}
					if (!pUser->isDotCS)
					{
						SPDLOG_INFO("User Center login (rejected-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
						return {false, "此账户在FastBuilder的记录中尚未绑定,请联系FastBuilder管理员进行绑定。"};
					}
					else
					{
						FBWhitelist::User *rawUser = pUser.get();
						if (user_unique_map.contains(rawUser))
						{
							userlist_mutex.lock();
							userlist.erase(user_unique_map[rawUser]);
							user_unique_map[rawUser] = session->session_id;
							userlist_mutex.unlock();
						}
						else
						{
							userlist_mutex.lock();
							user_unique_map[rawUser] = session->session_id;
							userlist_mutex.unlock();
						}
						session->user = pUser;
						std::string user_theme = pUser->preferredtheme.has_value() ? (*pUser->preferredtheme) : "bootstrap";
						session->token_login = false;
						session->phoenix_only = false;
						*pUser->keep_reference = true;
						SPDLOG_INFO("User Center login (passed-dotcs): Username: {}, IP: {}", fb_username, session->ip_address);
						return {true, "Welcome", "theme", user_theme, "isadmin", *pUser->isAdministrator};
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

	ACTION0(CaptchaAction, "captcha")
	{
		std::vector<uint8_t> buf;
		std::string the_captcha;
		if (generateCaptcha(buf, the_captcha) != 0)
		{
			throw ServerErrorDemand{"Unknown error"};
		}
		session->last_captcha = the_captcha;
		throw DirectReturnDemand{
			std::string((const char *)&buf.front(), buf.size()),
			"image/png"};
	}

	LACTION0(LogoutAction, "logout")
	{
		userlist_mutex.lock();
		*session->user->keep_reference = false;
		user_unique_map.erase(session->user.get());
		userlist.erase(session->session_id);
		userlist_mutex.unlock();
		return {true, "OK"};
	}

	LACTION0(FetchProfileAction, "fetch_profile")
	{
		FBWhitelist::User &user = *session->user;
		std::string blc = "机器人绑定码在 Token 登录状态下不能被显示。";
		bool is_can_show_blc = true;
		bool is_hidden_by_default_blc = true;
		if (session->user->isDotCS)
		{
			is_can_show_blc = false;
			is_hidden_by_default_blc = false;
			blc = "由于 DotCS 的安全机制,您不得使用机器人绑定码做任何事情。";
		}
		else if (!session->token_login)
		{
			is_hidden_by_default_blc = false;
			blc = fmt::format("v|{}!{}", *(user.username), Utils::sha256(Secrets::add_external_bot_salt(user.username)));
		}
		Json::Value jsonArray(Json::arrayValue);
		Json::Value DotCS_License = jsonArray;
		std::string cn_username = user.cn_username.has_value() ? *(user.cn_username) : "";
		Json::Value slots;
		if (session->user->isDotCS)
		{	
			Json::Value jsonArray(Json::arrayValue);
			slots = jsonArray;
		}
		else
		{
			slots = user.rentalservers.toDescriptiveJSON();
		}
		bool is_2fa = user.two_factor_authentication_secret.has_value();
		float mp_duration;
		if (session->user->isDotCS)
		{
			mp_duration = -1;
			Json::Value login_packet;
			login_packet["username"] = session->user->DotCS_User_Name;
			Json::StreamWriterBuilder writebuild;
			writebuild["emitUTF8"] = true;
			std::string login_text = Json::writeString(writebuild, login_packet);
			if (auto res = dotcsClient.Post("/fbuc_api/fb_user_license_list", DotCS_Headers, login_text, "application/json"))
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
						Json::Value jsonArray(Json::arrayValue);
						Json::Value error_tip_license;
						error_tip_license["name"] = "获取失败";
						error_tip_license["data"] = "DotCS验证服务器的消息解析失败,可能是DotCS服务器未开启此接口";
						DotCS_License = jsonArray;
					} else {
						bool success = root.get("success", false).asBool();
						if (success == true)
						{
							DotCS_License = root.get("license", "[]");
						}
						else
						{
							Json::Value jsonArray(Json::arrayValue);
							Json::Value error_tip_license;
							error_tip_license["name"] = "获取失败";
							error_tip_license["data"] = "未知DotCS验证服务器错误";
							DotCS_License = jsonArray;
						}
					}

				}
				else
				{
					Json::Value jsonArray(Json::arrayValue);
					Json::Value error_tip_license;
					error_tip_license["name"] = "获取失败";
					error_tip_license["data"] = "DotCS验证服务器无法服务或验证未通过";
					DotCS_License = jsonArray;
				}
			}
			else
			{
				Json::Value jsonArray(Json::arrayValue);
				Json::Value error_tip_license;
				error_tip_license["name"] = "获取失败";
				error_tip_license["data"] = "DotCS验证服务器暂时无法访问,请等待恢复";
				DotCS_License = jsonArray;
			}
		}
		else
		{

			if (!session->user->free)
			{
				mp_duration = -1;
			}
			else if (!session->user->expiration_date.stillAlive())
			{
				mp_duration = 0;
			}
			else
			{
				mp_duration = round(((session->user->expiration_date - time(nullptr)) / 86400.00) * 100.0) / 100.0;
			}
		}
		int32_t user_points = session->user->points.has_value() ? session->user->points : 0;
		if (!user.phoenix_login_otp.has_value())
		{
			user.phoenix_login_otp = Utils::generateUUID();
		}
		std::string phoenix_otp = user.phoenix_login_otp;
		return {true, "Well done", // 是否成功,消息
								   // 下面的就是各种键值了,例如下面的 ` "blc",blc ` 表示的是 "blc":blc (json 表达)
				"is_dotcs", (bool)session->user->isDotCS,
				"dotcs_username", session->user->DotCS_User_Name,
				"blc", blc,
				"is_can_show_blc", is_can_show_blc,
				"is_hidden_by_default_blc", is_hidden_by_default_blc,
				"cn_username", cn_username,
				"slots", slots,
				"is_2fa", is_2fa,
				"monthly_plan_duration", mp_duration,
				"license", DotCS_License,
				"points", user_points,
				"nemcbind_status", session->user->nemc_binded_account.has_value(),
				"phoenix_otp", phoenix_otp,
				"no_security", (bool)user.disable_all_security_measures};
	}
	LACTION1(SaveClientUsernameAction, "save_client_username",
			 std::string, username, "cnun")
	{
		if (username->length() > 32)
		{
			return {false, "用户名太长"};
		}
		session->user->cn_username = *username;
		return {true, "", "username", *username};
	}

	LACTION3(SaveSlotAction, "save_slot",
			 std::string, slotid, "slotid",
			 std::optional<std::string>, content, "content",
			 std::optional<std::string>, operation, "operation")
	{
		FBWhitelist::User *user = session->user.get();
		if (!user->rentalservers.size())
		{
			throw InvalidRequestDemand{"NO WAY"};
		}
		auto &slot = user->rentalservers[slotid];
		if (!slot)
		{
			return {false, "内部错误: slotid 无效"};
		}
		if (!content->has_value() && **operation != "remove")
		{
			throw InvalidRequestDemand{"Invalid request"};
		}
		if (**operation != "remove")
		{
			std::string scontent = **content;
			if (scontent.length() > 16 || scontent.length() < 4)
			{
				return {false, "过于夸张的租赁服号长度"};
			}
			uint32_t val = 0;
			try
			{
				val = std::stoi(scontent);
			}
			catch (...)
			{
				return {false, "无效租赁服号"};
			}
			if (slot.lastdate)
			{
				if (slot.locked)
				{
					return {false, "不可以更改已经写入的固定 slot"};
				}
				time_t sugosu = time(nullptr) - slot.lastdate;
				if (sugosu <= 2592000)
				{
					float ato = round(((2592000 - sugosu) / 86400.0) * 100.0) / 100.0;
					return {false, fmt::format("{} 天之后方可修改此 slot", ato)};
				}
			}
			slot.lastdate = time(nullptr);
			slot.content = scontent;
			return {true, "Well done", "slots", user->rentalservers.toDescriptiveJSON()};
		}
		else
		{
			user->rentalservers.erase_slot(slotid);
			return {true, "ok", "slots", user->rentalservers.toDescriptiveJSON()};
		}
	}

	LACTION2(ChangePasswordAction, "change_password",
			 std::string, originalPassword, "originalPassword",
			 std::string, newPassword, "newPassword")
	{
		if (!session->user->isDotCS){
			if (session->token_login && !session->user->disable_all_security_measures)
			{
				throw InvalidRequestDemand{"Changing password is forbidden for token-login users."};
			}
			if (originalPassword->length() != 64 || newPassword->length() != 64 || newPassword == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			{
				throw InvalidRequestDemand{"Invalid Request"};
			}
			FBWhitelist::User *user = session->user.get();
			if (user->password != Utils::sha256(Secrets::addSalt(*originalPassword)))
			{
				return {false, "原密码不正确"};
			}
			user->password = Utils::sha256(Secrets::addSalt(newPassword));
			return {true, "ok"};
		} else {
			return {false, "你没有权限修改密码"};
		}
	}

	LACTION0(GetThemeInfoAction, "get_theme_info")
	{
		return {true, "", "data", *session->user->preferredtheme};
	}

	LACTION1(ApplyThemeAction, "apply_theme",
			 std::string, theme, "name")
	{
		if (theme->size() < 2 || theme->size() > 32)
		{
			throw InvalidRequestDemand{"Invalid theme string given"};
		}
		session->user->preferredtheme = theme;
		return {true};
	}

	ACTION3(RegisterAction, "register",
			std::string, username, "username",
			std::string, password, "password",
			std::string, captcha, "captcha")
	{
		if (password->length() != 64)
			throw InvalidRequestDemand{"Invalid request"};
		if (!session->verifyCaptcha(captcha))
		{
			return {false, "验证码不正确"};
		}
		std::regex username_req("^[A-Za-z0-9]+$", std::regex_constants::ECMAScript);
		std::smatch matching_buf;
		std::string perm_un = *username;
		if (!std::regex_match(perm_un, matching_buf, username_req))
		{
			return {false, "无效用户名"};
		}
		if (password == "2dcc453c31b52d2b1137e0d02e823d64dbf3c722551c545e8889d8e45f54fa32")
			return {false, "无效密码"};
		if (FBWhitelist::Whitelist::acquireUser(username))
			return {false, "用户名被占用"};
		std::optional<FBWhitelist::User> user = FBWhitelist::Whitelist::createUser(username, Utils::sha256(Secrets::addSalt(password)));
		if (!user.has_value())
		{
			throw ServerErrorDemand{"Unknown exception"};
		}
		*user->keep_reference = true;
		session->user = std::make_shared<FBWhitelist::User>(*user);
		session->token_login = false;
		session->phoenix_only = false;
		SPDLOG_INFO("User Center register: Username: {}, IP: {}", *username, session->ip_address);
		return {true};
	}

	LACTION0(Kickstart2FAAction, "kickstart_2fa")
	{
		if (session->user->disable_all_security_measures)
			throw InvalidRequestDemand{"User is forbidden from enabling 2FA"};
		if (session->user->two_factor_authentication_secret.has_value())
		{
			throw InvalidRequestDemand{"User already under 2FA"};
		}
		OTPDataPack *otpdata = new OTPDataPack;
		otpdata->secret[16] = 0;
		otp_random_base32(16, otpdata->secret);
		session->tmp_otp = std::shared_ptr<OTPDataPack>(otpdata);
		totp_new(&(otpdata->data), otpdata->secret, hmac_algo_sha1, get_current_time, 6, 30);
		char out[256] = {0};
		otpuri_build_uri(&(otpdata->data), "FastBuilder", session->user->username->c_str(), "SHA1", out);
		QRCode qrcode;
		uint8_t qrcodeBytes[qrcode_getBufferSize(4)];
		qrcode_initText(&qrcode, qrcodeBytes, 4, ECC_LOW, out);
		cv::Mat qr_image = cv::Mat::zeros(qrcode.size, qrcode.size, CV_8UC3);
		qr_image = cv::Scalar(255, 255, 255, 255);
		for (uint8_t y = 0; y < qrcode.size; y++)
		{
			for (uint8_t x = 0; x < qrcode.size; x++)
			{
				if (qrcode_getModule(&qrcode, x, y))
				{
					cv::Vec3b &s = qr_image.at<cv::Vec3b>(cv::Point(x, y));
					s[0] = 0;
					s[1] = 0;
					s[2] = 0;
				}
			}
		}
		cv::Mat larger_qr_image;
		cv::resize(qr_image, larger_qr_image, cv::Size(250, 250), 0, 0, cv::INTER_AREA);
		std::vector<uint8_t> out_buf;
		cv::imencode(".png", larger_qr_image, out_buf);
		return {true, "ok", "plainkey", std::string(otpdata->secret), "qrcode", fmt::format("data:image/png;base64,{}", Utils::base64Encode(std::string((const char *)&out_buf.front(), out_buf.size())))};
	}

	LACTION1(FinishRegistering2FAAction, "finish_registering_2fa",
			 std::string, code, "code")
	{
		if (!session->tmp_otp)
		{
			throw InvalidRequestDemand{"Invalid request"};
		}
		int val = totp_verify(&session->tmp_otp->data, code->c_str(), time(nullptr), 2);
		if (!val)
		{
			char wanted[7];
			wanted[6] = 0;
			totp_now(&session->tmp_otp->data, wanted);
			session->tmp_otp = nullptr;
			return {false, fmt::format("无效验证码, 预期值: {}", wanted)};
		}
		session->user->two_factor_authentication_secret = std::string(session->tmp_otp->secret);
		session->tmp_otp = nullptr;
		return {true, "ok"};
	}

	LACTION0(Retract2FAAction, "retract_2fa")
	{
		if (!session->user->two_factor_authentication_secret.has_value())
		{
			throw InvalidRequestDemand{"Invalid request"};
		}
		session->user->two_factor_authentication_secret.unset();
		return {true};
	}

	LACTION0(DisableAllSecurityMeasuresAction, "disable_all_security_measures")
	{
		session->user->disable_all_security_measures = true;
		return {true};
	}

	static FBUCActionCluster accountGeneralActions(0, {Action::enmap(new APIListAction),
													   Action::enmap(new LoginAction),
													   Action::enmap(new Login_DotCS_Action),
													   Action::enmap(new CaptchaAction),
													   Action::enmap(new LogoutAction),
													   Action::enmap(new FetchProfileAction),
													   Action::enmap(new SaveClientUsernameAction),
													   Action::enmap(new SaveSlotAction),
													   Action::enmap(new ChangePasswordAction),
													   Action::enmap(new GetThemeInfoAction),
													   Action::enmap(new ApplyThemeAction),
													   Action::enmap(new RegisterAction),
													   Action::enmap(new Kickstart2FAAction),
													   Action::enmap(new FinishRegistering2FAAction),
													   Action::enmap(new Retract2FAAction),
													   Action::enmap(new DisableAllSecurityMeasuresAction)});
};
