#include "user_center.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "cpp-httplib/httplib.h"
#include "whitelist.h"
#include "utils.h"
#include "secrets.h"
#include "products.h"
#include <memory>
#include <thread>
#include <shared_mutex>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <openssl/hmac.h>

#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/array.hpp>

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;

extern mongocxx::pool mongodb_pool;
httplib::Headers DotCS_Headers {
	{"dlfaps","123456"} //DotCS Key(别想了,源代码里面写的Key是错误的)
};
httplib::Client stripeClient("https://api.stripe.com");
httplib::Client dotcsClient("192.168.1.11",21512);
void FBUC::finalizePaymentIntent(std::shared_ptr<FBUC::PaymentIntent> intent, FBWhitelist::User *user, std::string const& helper_name) {
	auto pSession=intent->session.lock();
	if(pSession) {
		pSession->cart.clear();
	}
	if(intent->points_delta) {
		user->points+=intent->points_delta;
	}
	std::string desc=fmt::format("Δpts = {}\n",intent->points_delta);
	Json::Value descContent(Json::arrayValue);
	for(Product *i:intent->content) {
		i->execute_on(*user);
		desc+=fmt::format("{}:{} - {} CNY\n", i->product_id(), i->product_name(), i->price());
		descContent.append(i->toJSON());
	}
	intent->paired=true;
	intent->approved=true;
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["payments"].insert_one(document{}<<"username"<<user->username<<"price"<<(int32_t)intent->price<<"helper_price"<<(int32_t)intent->helper_price<<"helper"<<helper_name<<"content"<<Utils::writeJSON(descContent)<<"description"<<desc<<"date"<<bsoncxx::types::b_date(std::chrono::milliseconds{time(nullptr)*1000})<<finalize);
}

namespace FBUC {
	static void enter_action_clust(FBUC::Action *action, Json::Value& parsed_args, const httplib::Request& req, httplib::Response& res, bool administrative=false);
};

static void FBUC::enter_action_clust(FBUC::Action *action, Json::Value& parsed_args, const httplib::Request& req, httplib::Response& res, bool administrative) {
	std::string sessionId="";
	if(req.has_header("Authorization")) {
		std::string sessionId_cookie=req.get_header_value("Authorization");
		std::regex sessionId_regex("^Bearer (.*?)$", std::regex_constants::ECMAScript);
		std::smatch sessionId_match;
		if(std::regex_match(sessionId_cookie, sessionId_match, sessionId_regex)) {
			userlist_mutex.lock_shared();
			if(userlist.contains(sessionId_match[1].str())) {
				sessionId=sessionId_match[1].str();
			}
			userlist_mutex.unlock_shared();
		}
	}else if(req.has_param("secret")) {
		std::string const& secret_val=req.get_param_value("secret");
		userlist_mutex.lock_shared();
		if(userlist.contains(secret_val)) {
			sessionId=secret_val;
		}
		userlist_mutex.unlock_shared();
	}
	parsed_args["secret"]=sessionId;
	auto maybeSession=userlist.find(sessionId);
	try {
		if(!sessionId.length()) {
			//res.set_content("401 Unauthorized\n\n", "text/plain");
			//res.status=401;
			throw FBUC::UnauthorizedDemand{"Unauthorized"};
			return;
		}
		FBUC::Session currentSession=maybeSession->second;
		std::lock_guard<std::mutex> the_lock(currentSession->op_lock);
		if(!currentSession->user&&(administrative||action->mandatory_login())) {
			throw FBUC::InvalidRequestDemand{"Login Required"};
		}
		if(currentSession->user&&currentSession->phoenix_only) {
			std::regex phoenix_only_match("^phoenix\\/(.*?)$", std::regex_constants::ECMAScript);
			std::smatch sm;
			if(!std::regex_match(action->action_name, sm, phoenix_only_match)&&action->action_name!="api"&&action->action_name!="logout") {
				throw FBUC::AccessDeniedDemand{"Restricted to phoenix/"};
			}
		}
		if(administrative&&(!currentSession->user||!*currentSession->user->isAdministrator)) {
			throw FBUC::AccessDeniedDemand{"Access Denied"};
		}
		currentSession->last_alive=time(nullptr);
		Json::Value ret=action->_execute(parsed_args, currentSession);
		if(ret["code"].isInt()&&ret["code"].asInt()==-400) {
			throw FBUC::InvalidRequestDemand{ret["message"].asString()};
		}
		ret.removeMember("code");
		res.set_content(Utils::writeJSON(ret), "application/json");
		return;
	}catch(const FBUC::RedirectDemand& rdr) {
		res.status=302;
		res.set_header("Location", rdr.target);
	}catch(const FBUC::ErrorDemand& ird) {
		res.status=ird.status();
		res.set_content(ird.print_with_stack_dump(), "text/plain");
	}catch(const FBUC::DirectReturnDemand& drd) {
		if(drd.disposition.length()) {
			res.set_header("Content-Disposition", drd.disposition);
		}
		res.set_content(drd.content, drd.type);
	}
}


extern "C" void init_user_center() {
	dotcsClient.set_keep_alive(true);
	stripeClient.set_keep_alive(true);
	stripeClient.set_bearer_token_auth(Secrets::get_stripe_key());
	std::thread([](){
		while(1) {
			sleep(120);
			userlist_mutex.lock();
			time_t now=time(nullptr);
			for(auto it=userlist.begin();it!=userlist.end();) {
				std::shared_ptr<FBUC::UserSession> session=it->second;
				if(!session) {
					SPDLOG_CRITICAL("Empty UserSession ptr present! Check your code!");
					it=userlist.erase(it);
					continue;
				}
				time_t time_passed=now-session->last_alive;
				if(time_passed>2400) {
					if(it->second->user) {
						*it->second->user->keep_reference=false;
					}
					it=userlist.erase(it);
					continue;
				}
				if(!it->second->user&&time_passed>300) {
					it=userlist.erase(it);
					continue;
				}
				++it;
			}
			for(auto i=user_unique_map.begin();i!=user_unique_map.end();) {
				if(!userlist.contains(i->second)) {
					i=user_unique_map.erase(i);
					continue;
				}
				++i;
			}
			userlist_mutex.unlock();
			payments_mutex.lock();
			for(auto it=payment_intents.begin();it!=payment_intents.end();) {
				std::shared_ptr<FBUC::PaymentIntent> intent=it->second;
				if(!intent) {
					SPDLOG_CRITICAL("Empty PaymentIntent ptr present! Check your code!");
					it=payment_intents.erase(it);
					continue;
				}
				if(intent->session.expired()) {
					it=payment_intents.erase(it);
					continue;
				}else if(intent->approved) {
					intent->session.lock()->payment_intent=nullptr;
					it=payment_intents.erase(it);
					continue;
				}
				++it;
			}
			payments_mutex.unlock();
		}
	}).detach();
	std::thread([](){
		httplib::Server server;
		server.Options("/", [](const httplib::Request& req, httplib::Response& res) {
			res.status=204;
		});
		server.Get("/", [](const httplib::Request& req, httplib::Response& res) {
			res.set_content("Hello, world!", "text/plain");
		});
		server.Get("/api/stripe_recover", [](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_param("ssid")) {
				res.status=400;
				res.set_content("400 Illegal Request", "text/plain");
				return;
			}
			res.status=302;
			std::string mukaisaki=req.has_param("is_checkout")?"/cashier":"/pay";
			if(getenv("DEBUG")) {
				res.set_header("Location", fmt::format("http://127.0.0.1/fbuc/bin/#!/router/enter?to={}&secret={}",mukaisaki,req.get_param_value("ssid")));
				return;
			}
			res.set_header("Location", fmt::format("https://user.fastbuilder.pro/#!/router/enter?to={}&secret={}",mukaisaki,req.get_param_value("ssid")));
		});
		server.Options("/api/new", [](const httplib::Request& req, httplib::Response& res) {
			res.status=204;
		});
		server.Get("/api/new", [](const httplib::Request& req, httplib::Response& res) {
			std::string sessionId;
			userlist_mutex.lock();
			while(true) {
				sessionId=Utils::generateUUID();
				if(!userlist.contains(sessionId)) {
					//res.set_header("Set-Cookie", fmt::format("ssid={}", sessionId));
					auto new_ptr=std::make_shared<FBUC::UserSession>();
					new_ptr->session_id=sessionId;
					new_ptr->last_alive=time(nullptr);
					std::string ip_address="127.0.0.1";
					if(req.has_header("X-Forwarded-For")) {
						std::string const& ip_v=req.get_header_value("X-Forwarded-For");
						std::string::size_type n=ip_v.find(',');
						if(n==std::string::npos) {
							ip_address=ip_v;
						}else{
							ip_address=ip_v.substr(0, n);
						}
					}
					new_ptr->ip_address=std::move(ip_address);
					userlist[sessionId]=new_ptr;
					break;
				}
			}
			userlist_mutex.unlock();
			res.set_content(sessionId, "text/plain");
		});
		server.Get("/remote_auth", [&](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_header("X-Auth-HttpRequest-Query")) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			std::string query_val=req.get_header_value("X-Auth-HttpRequest-Query");
			std::regex secret_regex("(^|&)secret=(.*?)(&|$)", std::regex_constants::ECMAScript);
			std::smatch secret_match;
			if(!std::regex_search(query_val, secret_match, secret_regex)) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			std::string const& secret_val=secret_match[2].str();
			if(!userlist.contains(secret_val)) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			std::shared_ptr<FBUC::UserSession> session=userlist[secret_val];
			if(!session->user||(req.has_param("admin")&&!*session->user->isAdministrator)) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			res.set_header("Auth-Role", session->user->isAdministrator?"administrator":"user");
			res.set_header("Auth-User", session->user->username);
		});
		server.Get("/api/bot_ext_add_points", [](const httplib::Request& req, httplib::Response &res) {
			if(!req.has_param("token")||!req.has_param("target")||!req.has_param("value")) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			std::string const& token_content=req.get_param_value("token");
			if(token_content!=Secrets::add_external_bot_salt("ACCESS2")) {
				res.status=403;
				return;
			}
			std::string const& target=req.get_param_value("target");
			uint32_t pts_delta=atoi(req.get_param_value("value").c_str());
			auto userinfo=FBWhitelist::Whitelist::acquireUser(target);
			if(!userinfo) {
				res.set_content("USER_NOT_FOUND", "text/plain");
				return;
			}
			userinfo->points+=pts_delta;
			res.set_content("OK", "text/plain");
		});
		server.Post("/api/stripe/webhook", [&](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_header("Stripe-Signature")) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			time_t current_time=time(nullptr);
			std::string signature_content=req.get_header_value("Stripe-Signature");
			std::regex t_regex("t=([0-9]+)(,|$)", std::regex_constants::ECMAScript);
			std::regex v1_regex("v1=([a-z0-9]{64})(,|$)", std::regex_constants::ECMAScript);
			std::smatch t_match;
			std::smatch v1_match;
			if(!std::regex_search(signature_content, t_match, t_regex)||!std::regex_search(signature_content, v1_match, v1_regex)) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			time_t given_time=std::stol(t_match[1].str());
			if(current_time-given_time>120) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			std::string signed_payload=fmt::format("{}.{}", t_match[1].str(), req.body);
			std::string key=Secrets::get_stripe_webhook_secret();
			std::string out_md;
			out_md.resize(32);
			unsigned int out_md_len=32;
			HMAC(EVP_sha256(), key.c_str(), key.length(), (const unsigned char *)signed_payload.c_str(), signed_payload.size(), (unsigned char *)&out_md.front(), &out_md_len);
			std::string expected_signature=Utils::str2hex(out_md);
			if(expected_signature!=v1_match[1].str()) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			Json::Value event;
			Utils::parseJSON(req.body, &event, nullptr);
			std::string event_type=event["type"].asString();
			if(event_type!="checkout.session.completed"/*&&event_type!="charge.succeeded"&&event_type!="payment_intent.succeeded"*/) {
				res.set_content("200 but not expected", "text/plain");
				return;
			}
			Json::Value &session=event["data"]["object"];
			payments_mutex.lock_shared();
			if(!payment_intents.contains(session["id"].asString())) {
				payments_mutex.unlock_shared();
				return;
			}
			auto intent=payment_intents[session["id"].asString()];
			payments_mutex.unlock_shared();
			std::shared_ptr<FBUC::UserSession> user=intent->session.lock();
			if(!user) {
				// ???
				res.status=500;
				return;
			}
			if(intent->content.size()==0) {
				user->user->promocode_count+=intent->helper_price;
				return;
			}
			FBUC::finalizePaymentIntent(intent, user->user.get(), fmt::format("@Stripe+{}", session["id"].asString()));
		});
		server.Options(R"(/api/(administrative/)?(((phoenix/)|(dotcs/))?[0-9a-zA-Z_]+)$)", [](const httplib::Request& req, httplib::Response& res) {
			res.status=204;
		});
		server.Get(R"(/api/(administrative/)?(((phoenix/)|(dotcs/))?[0-9a-zA-Z_]+)$)", [](const httplib::Request& req, httplib::Response& res) {
			if(!req.matches[2].length()) {
				res.status=404;
				return;
			}
			FBUC::Action *action=nullptr;
			bool isAdministrative=req.matches[1].length()!=0;
			std::unordered_map<std::string, FBUC::Action *> &target_map=isAdministrative?fbuc_administrative_actions:fbuc_actions;
			if(!target_map.contains(req.matches[2].str())) {
				res.status=404;
				return;
			}else{
				action=target_map[req.matches[2].str()];
			}
			Json::Value parsed_args;
			for(const auto &i:req.params) {
				parsed_args[i.first]=i.second;
			}
			enter_action_clust(action, parsed_args, req, res, isAdministrative);
		});
		server.Post(R"(/api/(administrative/)?(((phoenix/)|(dotcs/))?[0-9a-zA-Z_]+)$)", [](const httplib::Request& req, httplib::Response& res) {
			if(!req.matches[2].length()) {
				res.status=404;
				return;
			}
			FBUC::Action *action=nullptr;
			bool isAdministrative=req.matches[1].length()!=0;
			std::unordered_map<std::string, FBUC::Action *> &target_map=isAdministrative?fbuc_administrative_actions:fbuc_actions;
			if(!target_map.contains(req.matches[2].str())) {
				res.status=404;
				return;
			}else{
				action=target_map[req.matches[2].str()];
			}
			Json::Value parsed_args;
			std::string error_message;
			bool isSucc=Utils::parseJSON(req.body, &parsed_args, &error_message);
			if(!isSucc) {
				res.status=400;
				res.set_content(fmt::format("400 Invalid Request\n\nExpected JSON data, where JSON parsing failed.\n\nError: {}", error_message), "text/plain");
				return;
			}
			enter_action_clust(action, parsed_args, req, res, isAdministrative);
		});
		server.set_post_routing_handler([](const auto& req, auto& res) {
			res.set_header("access-control-allow-credentials", "true");
			res.set_header("access-control-allow-headers", "Origin, Authorization, Accept, Content-Type, Cookie");
			res.set_header("access-control-allow-methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS");
			if(req.has_header("Origin")&&req.get_header_value("Origin")=="http://127.0.0.1") {
				res.set_header("access-control-allow-origin", "http://127.0.0.1");
			}else{
				res.set_header("access-control-allow-origin", "https://user.fastbuilder.pro");
			}
		});
		server.listen("0.0.0.0", 8687);
	}).detach();
}
