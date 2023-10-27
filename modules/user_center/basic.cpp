#include "user_center.h"
#include <fmt/format.h>

bool FBUC::UserSession::verifyCaptcha(std::string const& captcha_value) {
	if(!last_captcha.length())
		return false;
	bool ret=last_captcha==captcha_value;
	last_captcha="";
	return ret;
}

std::unordered_map<std::string, FBUC::Action *> fbuc_actions;
std::unordered_map<std::string, FBUC::Action *> fbuc_administrative_actions;

std::unordered_map<std::string, FBUC::Action *> &select_action_set(int id) {
	if(id==0) {
		return fbuc_actions;
	}else if(id==1) {
		return fbuc_administrative_actions;
	}else{
		throw std::runtime_error("Unknown action set ID");
	}
}

FBUCActionCluster::FBUCActionCluster(int type, std::unordered_map<std::string, FBUC::Action *> const& assigning_map) {
	this->type=type;
	auto &h_map=select_action_set(type);
	for(auto const &i:assigning_map) {
		h_map[i.first]=i.second;
		actions.push_back(i.first);
	}
}

FBUCActionCluster::~FBUCActionCluster() {
	auto &h_map=select_action_set(type);
	for(auto const& i:actions) {
		delete h_map[i];
		h_map.erase(i);
	}
}

std::unordered_map<std::string, std::shared_ptr<FBUC::UserSession>> userlist;
std::unordered_map<FBWhitelist::User *,std::string> user_unique_map;
std::shared_mutex userlist_mutex;
std::unordered_map<std::string, std::shared_ptr<FBUC::PaymentIntent>> payment_intents;
std::shared_mutex payments_mutex;

FBUC::ErrorDemand::ErrorDemand(std::string const& error_message) {
	this->error_message=error_message;
	stack_dump="(OMITTED)";
}

std::string FBUC::ErrorDemand::print_with_stack_dump() const {
	return fmt::format("{} {}\n\n{}\n\n==== Stack dump ====\n{}", status(), error_name(), error_message, stack_dump);
}

int FBUC::InvalidRequestDemand::status() const {
	return 400;
}

std::string FBUC::InvalidRequestDemand::error_name() const {
	return "Invalid Request";
}

int FBUC::AccessDeniedDemand::status() const {
	return 403;
}

std::string FBUC::AccessDeniedDemand::error_name() const {
	return "Access Denied";
}

int FBUC::UnauthorizedDemand::status() const {
	return 401;
}

std::string FBUC::UnauthorizedDemand::error_name() const {
	return "Unauthorized";
}

int FBUC::ServerErrorDemand::status() const {
	return 500;
}

std::string FBUC::ServerErrorDemand::error_name() const {
	return "Server Exception";
}
