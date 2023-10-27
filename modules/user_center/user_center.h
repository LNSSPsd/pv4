#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <shared_mutex>
#include <optional>
#include "action.h"
#include "whitelist.h"

extern "C" {
#include "cotp/cotp.h"
#include "cotp/otpuri.h"
#include "qrcode/qrcode.h"
}

struct Product;

namespace FBWhitelist {
	struct User;
};

struct OTPDataPack {
	char secret[17];
	OTPData data;
};

namespace FBUC {
	struct PaymentIntent;
	struct UserSession {
		std::shared_ptr<FBWhitelist::User> user;
		std::string session_id;
		std::string last_captcha;
		bool token_login;
		std::vector<Product *> cart;
		std::shared_ptr<PaymentIntent> payment_intent;
		//PaymentIntent *payment_intent=nullptr;
		std::shared_ptr<OTPDataPack> tmp_otp;
		time_t last_alive;
		bool phoenix_only=false;
		std::string ip_address;
		std::mutex op_lock;
		std::string device_creation_randid;
		
		bool verifyCaptcha(std::string const& captcha_value);
	};
	
	struct PaymentIntent {
		std::weak_ptr<UserSession> session;
		unsigned int price=0;
		unsigned int helper_price=0;
		unsigned int stripe_price=0;
		int points_delta=0; // Positive: subject of increment, Negative: subject of reduction
		std::vector<Product *> content;
		bool needs_verify=false;
		bool banned_from_payment=false;
		bool card_only=false;
		bool approved=false;
		bool paired=false;
		std::string pairee;
		std::string stripe_pid;
	};
	
	struct ErrorDemand {
		std::string stack_dump;
		std::string error_message;
		ErrorDemand(std::string const& error_message);
		
		virtual std::string error_name() const=0;
		virtual int status() const=0;
		virtual std::string print_with_stack_dump() const;
	};
	
	struct RedirectDemand {
		std::string target;
	};
	
	struct InvalidRequestDemand : ErrorDemand {
		InvalidRequestDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const;
		virtual std::string error_name() const;
	};
	
	
	struct AccessDeniedDemand : ErrorDemand {
		AccessDeniedDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const;
		virtual std::string error_name() const;
	};
	
	struct UnauthorizedDemand : ErrorDemand {
		UnauthorizedDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const;
		virtual std::string error_name() const;
	};
	
	struct ServerErrorDemand : ErrorDemand {
		ServerErrorDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const;
		virtual std::string error_name() const;
	};
	
	struct DirectReturnDemand {
		std::string content;
		std::string type;
		std::string disposition;
	};
	
	typedef std::shared_ptr<FBUC::UserSession> Session;
	
	void finalizePaymentIntent(std::shared_ptr<FBUC::PaymentIntent> intent, FBWhitelist::User *user, std::string const& helper_name);
};

class FBUCActionCluster {
	int type;
	std::vector<std::string> actions;
public:
	FBUCActionCluster(int type, std::unordered_map<std::string, FBUC::Action *> const&);
	~FBUCActionCluster();
};

extern std::unordered_map<std::string, FBUC::Action *> fbuc_actions;
extern std::unordered_map<std::string, FBUC::Action *> fbuc_administrative_actions;

extern std::unordered_map<std::string, FBUC::Action *> &select_action_set(int id);

extern std::unordered_map<std::string, std::shared_ptr<FBUC::UserSession>> userlist;
extern std::unordered_map<FBWhitelist::User *,std::string> user_unique_map;
extern std::shared_mutex userlist_mutex;
extern std::unordered_map<std::string, std::shared_ptr<FBUC::PaymentIntent>> payment_intents;
extern std::shared_mutex payments_mutex;

template <typename T>
bool FBUC::ActionArgument<T>::parse(Json::Value const& input) {
	if constexpr(std::is_same<T, std::string>::value) {
		if(!input[argument_name].isString()) {
			return false;
		}
		value=input[argument_name].asString();
	}else if constexpr(std::is_same<T, uint32_t>::value) {
		if(!input[argument_name].isUInt()) {
			return false;
		}
		value=input[argument_name].asUInt();
	}else if constexpr(std::is_same<T, uint64_t>::value) {
		if(!input[argument_name].isUInt64()) {
			return false;
		}
		value=input[argument_name].asUInt64();
	}else if constexpr(std::is_same<T, int32_t>::value) {
		if(!input[argument_name].isInt()) {
			return false;
		}
		value=input[argument_name].asInt();
	}else if constexpr(std::is_same<T, int64_t>::value) {
		if(!input[argument_name].isInt64()) {
			return false;
		}
		value=input[argument_name].asInt64();
	}else if constexpr(std::is_same<T, std::optional<bool>>::value) {
		if(!input[argument_name].isBool()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asBool();
	}else if constexpr(std::is_same<T, bool>::value) {
		if(!input[argument_name].isBool()) {
			return false;
		}
		value=input[argument_name].asBool();
	}else if constexpr(std::is_same<T, std::optional<FBWhitelist::User>>::value) {
		if(!input[argument_name].isString()) {
			value=std::nullopt;
			return true;
		}
		value=FBWhitelist::Whitelist::findUser(input[argument_name].asString());
	}else if constexpr(std::is_same<T, FBWhitelist::User>::value) {
		if(!input[argument_name].isString())
			return false;
		auto possiblyUser=FBWhitelist::Whitelist::findUser(input[argument_name].asString());
		if(!possiblyUser.has_value())
			return false;
		value=*possiblyUser;
	}else if constexpr(std::is_same<T, std::optional<std::string>>::value) {
		if(!input[argument_name].isString()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asString();
	}else if constexpr(std::is_same<T, std::optional<uint32_t>>::value) {
		if(!input[argument_name].isUInt()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asUInt();
	}else if constexpr(std::is_same<T, std::optional<uint64_t>>::value) {
		if(!input[argument_name].isUInt64()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asUInt64();
	}else if constexpr(std::is_same<T, std::optional<int32_t>>::value) {
		if(!input[argument_name].isInt()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asInt();
	}else if constexpr(std::is_same<T, std::optional<int64_t>>::value) {
		if(!input[argument_name].isInt64()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asInt64();
	}else if constexpr(std::is_same<T, std::shared_ptr<FBUC::UserSession>>::value) {
		if(!input[argument_name].isString()) {
			value=nullptr;
			return false;
		}
		userlist_mutex.lock_shared();
		value=userlist[input[argument_name].asString()];
		userlist_mutex.unlock_shared();
		return true;
	}else{
		throw std::runtime_error("FBUC::ActionArgument: type not accepted");
	}
	return true;
}

template<typename ...Args>
void FBUC::ActionResult::parseAdditionalItems(std::string const& key, Json::Value val, Args&& ...args) {
	additional_items[key]=val;
	parseAdditionalItems(std::forward<Args>(args)...);
}

template<typename ...Args>
FBUC::ActionResult::ActionResult(bool stat, std::string const& message, Args&& ...args) {
	success=stat;
	this->message=message;
	parseAdditionalItems(std::forward<Args>(args)...);
}

template <typename T>
FBUC::ActionArgumentInternal *FBUC::ActionArgument<T>::copy() const {
	return (FBUC::ActionArgumentInternal *)new FBUC::ActionArgument<T>(argument_name);
}
