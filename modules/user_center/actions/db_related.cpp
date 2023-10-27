#include "../user_center.h"
#include "utils.h"
#include "secrets.h"
#include <fmt/format.h>
#include <thread>
#include <httplib.h>
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

namespace FBUC {
	LACTION2(VoteAnnouncementAction, "vote_announcement",
			std::string, vote_type, "vote_type",
			std::string, uniqueId, "unique_id") {
		if(vote_type!="up"&&vote_type!="down")
			throw InvalidRequestDemand{"无效投票类型"};
		FBWhitelist::User *user=session->user.get();
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto _target_announcement=fbdb["announcements"].find_one(document{}<<"uniqueId"<<*uniqueId<<finalize);
		if(!_target_announcement.has_value()) {
			return {false, "公告不存在"};
		}
		auto target_announcement=*_target_announcement;
		if(vote_type=="up") {
			if(target_announcement["downvoters"]) {
				auto downvoters_arr=target_announcement["downvoters"].get_array();
				for(auto i:downvoters_arr.value) {
					if(user->user_oid==(std::string)i.get_string()) {
						return {false, "你已经投过反对票了，不能投支持票。"};
					}
				}
			}
			size_t orig_upvoters=target_announcement["upvoters"]?std::distance(target_announcement["upvoters"].get_array().value.begin(),target_announcement["upvoters"].get_array().value.end()):0;
			auto pull_result=fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$pull"<<open_document<<"upvoters"<<user->user_oid<<close_document<<finalize);
			if(!pull_result->modified_count()) {
				orig_upvoters++;
				fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$push"<<open_document<<"upvoters"<<user->user_oid<<close_document<<finalize);
			}else{
				orig_upvoters--;
			}
			Json::Value update_val;
			update_val["upvotes"]=orig_upvoters;
			return {true, "ok", "update", update_val};
		}else if(vote_type=="down") {
			if(target_announcement["upvoters"]) {
				auto upvoters_arr=target_announcement["upvoters"].get_array();
				for(auto i:upvoters_arr.value) {
					if(user->user_oid==(std::string)i.get_string()) {
						return {false, "你已经投过支持票了，不能投反对票。"};
					}
				}
			}
			size_t orig_downvoters=target_announcement["downvoters"]?std::distance(target_announcement["downvoters"].get_array().value.begin(),target_announcement["downvoters"].get_array().value.end()):0;
			auto pull_result=fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$pull"<<open_document<<"downvoters"<<user->user_oid<<close_document<<finalize);
			if(!pull_result->modified_count()) {
				orig_downvoters++;
				fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$push"<<open_document<<"downvoters"<<user->user_oid<<close_document<<finalize);
			}else{
				orig_downvoters--;
			}
			Json::Value update_val;
			update_val["downvotes"]=orig_downvoters;
			return {true, "ok", "update", update_val};
		}
		throw ServerErrorDemand{"Fell"};
	}
	
	
	LACTION0(FetchAnnouncementsAction, "fetch_announcements") {
		Json::Value outvalues(Json::arrayValue);
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto cursor=fbdb["announcements"].find(document{}<<finalize, mongocxx::options::find{}.limit(10).sort(document{}<<"_id"<<-1<<finalize));
		for(auto &i:cursor) {
			Json::Value cur;
			cur["title"]=(std::string)i["title"].get_string();
			cur["content"]=(std::string)i["content"].get_string();
			cur["date"]=(std::string)i["date"].get_string();
			cur["author"]=(std::string)i["author"].get_string();
			cur["uniqueId"]=(std::string)i["uniqueId"].get_string();
			if(i["upvoters"]) {
				cur["upvotes"]=std::distance(i["upvoters"].get_array().value.begin(),i["upvoters"].get_array().value.end());
			}else{
				cur["upvotes"]=0;
			}
			if(i["downvoters"]) {
				cur["downvotes"]=std::distance(i["downvoters"].get_array().value.begin(),i["downvoters"].get_array().value.end());
			}else{
				cur["downvotes"]=0;
			}
			outvalues.append(cur);
		}
		throw DirectReturnDemand{Utils::writeJSON(outvalues), "application/json"};
	}
	
	LACTION1(GetUserContactsAction, "get_user_contacts",
			std::optional<int64_t>, identifier, "identifier") {
		std::shared_ptr<FBWhitelist::User> user=session->user;
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		if(!identifier->has_value()) {
			Json::Value ret(Json::ValueType::arrayValue);
			auto the_document=document{};
			if(!*(user->isAdministrator)) {
				the_document<<"username"<<*user->username;
			}else{
				the_document<<"closed"<<false;
			}
			auto user_contacts=fbdb["contacts"].find(the_document<<finalize);
			for(auto &i:user_contacts) {
				Json::Value current_value;
				current_value["title"]=(std::string)i["title"].get_string();
				current_value["identifier"]=(int64_t)i["identifier"].get_int64();
				if(i["closed"].get_bool()) {
					current_value["closed"]=true;
				}else{
					current_value["has_update"]=*user->isAdministrator^i["user_can_add_msg"].get_bool();
				}
				ret.insert(0, current_value);
			}
			return {true, "ok", "contacts", ret};
		}
		auto search_doc=document{};
		search_doc<<"identifier"<<**identifier;
		if(!*user->isAdministrator) {
			search_doc<<"username"<<*user->username;
		}
		auto _spec_contact=fbdb["contacts"].find_one(search_doc<<finalize);
		if(!_spec_contact.has_value()) {
			return {false, "未找到对应联络"};
		}
		auto spec_contact=*_spec_contact;
		Json::Value ret_val;
		ret_val["title"]=(std::string)spec_contact["title"].get_string();
		Json::Value thread_arr(Json::ValueType::arrayValue);
		bsoncxx::array::view thread_db_arr=(bsoncxx::array::view)spec_contact["thread"].get_array();
		for(auto &i:thread_db_arr) {
			Json::Value sub_val;
			sub_val["sender"]=(std::string)i["sender"].get_string();
			sub_val["content"]=(std::string)i["content"].get_string();
			sub_val["time"]=(int64_t)i["time"].get_int64();
			thread_arr.insert(0, sub_val);
		}
		ret_val["thread"]=thread_arr;
		ret_val["user_can_add_msg"]=*user->isAdministrator|spec_contact["user_can_add_msg"].get_bool();
		if(spec_contact["closed"].get_bool()) {
			ret_val["user_can_add_msg"]=false;
		}
		ret_val["identifier"]=(int64_t)spec_contact["identifier"].get_int64();
		return {true, "found", "item", ret_val};
	}
	
	LACTION2(CreateUserContactAction, "create_user_contact",
			std::string, title, "title",
			std::string, content, "content") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto old_contact=fbdb["contacts"].find_one(document{}<<"username"<<session->user->username<<"closed"<<false<<finalize);
		if(old_contact.has_value()) {
			return {false, "已有过去联络存在，请耐心等待，或删除对应联络。"};
		}
		if(content->length()>1000) {
			return {false, "联络内容太长"};
		}else if(title->length()>32) {
			return {false, "标题太长"};
		}
		int64_t con_id=(int64_t)time(nullptr);
		fbdb["contacts"].insert_one(document{}<<"username"<<*session->user->username<<"title"<<*title<<"thread"<<open_array<<open_document<<"sender"<<*session->user->username<<"content"<<*content<<"time"<<(int64_t)time(nullptr)<<close_document<<close_array<<"closed"<<false<<"user_can_add_msg"<<false<<"identifier"<<con_id<<finalize);
		std::string tg_notification=fmt::format("*New Contact*\nCONTACTID: {}\nUser: `{}`\nTitle: `{}`\n\n```\n{}\n```", con_id, *session->user->username, *title, *content);
		std::thread([tg_notification]() {
			httplib::Client tgClient("https://api.telegram.org");
			Json::Value postContent;
			postContent["chat_id"]=Secrets::get_telegram_chat_id();
			postContent["parse_mode"]="MarkdownV2";
			postContent["text"]=tg_notification;
			tgClient.Post(fmt::format("/{}/sendMessage", Secrets::get_telegram_bot_token()), Utils::writeJSON(postContent), "application/json");
		}).detach();
		return {true, "OK", "identifier", con_id};
	}
	
	LACTION4(UpdateUserContactAction, "update_user_contact",
			int64_t, identifier, "identifier",
			std::string, content, "content",
			std::optional<bool>, anonymous, "anonymous",
			std::optional<bool>, closing, "closing") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto contact_item=fbdb["contacts"].find_one(document{}<<"identifier"<<*identifier<<finalize);
		if(!contact_item.has_value()) {
			return {false, "不存在此联络"};
		}
		auto r_contact_item=*contact_item;
		if(r_contact_item["closed"].get_bool()) {
			return {false, "联络已经被关闭"};
		}
		std::string name="用户中心管理员";
		if(!session->user->isAdministrator) {
			if(((std::string)r_contact_item["username"].get_string())!=session->user->username) {
				return {false, "不存在此联络"};
			}
			if(!r_contact_item["user_can_add_msg"].get_bool()) {
				return {false, "请等待回复"};
			}
			fbdb["contacts"].update_one(document{}<<"identifier"<<*identifier<<finalize, document{}<<"$push"<<open_document<<"thread"<<open_document<<"content"<<*content<<"sender"<<*session->user->username<<"time"<<(int64_t)time(nullptr)<<close_document<<close_document<<"$set"<<open_document<<"user_can_add_msg"<<false<<close_document<<finalize);
			goto tg_notify;
			return {true, "OK"};
		}
		if(!anonymous->has_value()||!**anonymous) {
			name=session->user->username;
		}
		fbdb["contacts"].update_one(document{}<<"identifier"<<*identifier<<finalize, document{}<<"$push"<<open_document<<"thread"<<open_document<<"content"<<*content<<"sender"<<name<<"time"<<(int64_t)time(nullptr)<<close_document<<close_document<<"$set"<<open_document<<"user_can_add_msg"<<true<<close_document<<finalize);
		if(closing->has_value()&&**closing) {
			fbdb["contacts"].update_one(document{}<<"identifier"<<*identifier<<finalize, document{}<<"$set"<<open_document<<"closed"<<true<<close_document<<finalize);
		}
		{
			tg_notify:
			std::string tg_notification=fmt::format("*Update on Contact*\nCONTACTID: {}\nOperator: `{}`\n", *identifier, *session->user->username);
			if(*anonymous&&**anonymous) {
				tg_notification+="*ANONYMOUS MODE*\n";
			}
			if(*closing&&**closing) {
				tg_notification+="*CLOSING*\n";
			}
			tg_notification+="\n\n*Target Contact Thread*\n";
			// Get updated value
			auto spec_contact=*(fbdb["contacts"].find_one(document{}<<"identifier"<<*identifier<<finalize));
			tg_notification+=fmt::format("*Title*: `{}`\n", (std::string)spec_contact["title"].get_string());
			int no=1;
			bsoncxx::array::view thread_db_arr=(bsoncxx::array::view)spec_contact["thread"].get_array();
			for(auto &i:thread_db_arr) {
				tg_notification+=fmt::format("*\\#{}, {}*:\n```\n{}\n```\n", no, i["sender"].get_string(), i["content"].get_string());
				no++;
			}
			std::thread([tg_notification]() {
				httplib::Client tgClient("https://api.telegram.org");
				Json::Value postContent;
				postContent["chat_id"]=Secrets::get_telegram_chat_id();
				postContent["parse_mode"]="MarkdownV2";
				postContent["text"]=tg_notification;
				tgClient.Post(fmt::format("/{}/sendMessage", Secrets::get_telegram_bot_token()), Utils::writeJSON(postContent), "application/json");
			}).detach();
		}
		return {true, "OK"};
	}
	
	LACTION1(DeleteUserContactAction, "delete_user_contact",
			int64_t, identifier, "identifier") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		if(*session->user->isAdministrator) {
			fbdb["contacts"].delete_one(document{}<<"identifier"<<*identifier<<finalize);
			return {true};
		}
		fbdb["contacts"].delete_one(document{}<<"username"<<*session->user->username<<"identifier"<<*identifier<<finalize);
		return {true};
	}
	
	LACTION7(GetWhitelistAction, "get_whitelist",
			std::optional<std::string>, username, "username",
			std::optional<std::string>, _wquery, "whitelist_query",
			std::optional<uint32_t>, _wpage, "whitelist_page",
			std::optional<std::string>, pquery_username, "p_username",
			std::optional<std::string>, pquery_helper, "p_hname",
			std::optional<std::string>, pquery_description, "p_desc",
			std::optional<uint32_t>, _ppage, "payment_log_page") {
		if(username->has_value()) {
			auto client=mongodb_pool.acquire();
			auto user=(*client)["fastbuilder"]["whitelist"].find_one(document{}<<"username"<<**username<<finalize);
			std::string user_json_str=bsoncxx::to_json(*user);
			if(!user.has_value()) {
				throw DirectReturnDemand{"{}", "application/json"};
			}
			throw DirectReturnDemand{user_json_str, "application/json"};
		}
		if((*_wquery)->size()<4) {
			throw InvalidRequestDemand{"Invalid item `wquery`."};
		}
		std::string const& wquery=**_wquery;
		auto query=document{};
		if(wquery[0]=='1') {
			query<<"admin"<<true;
		}
		if(wquery[1]=='1') {
			query<<"allowed_to_use_phoenix"<<true;
		}
		if(wquery[2]=='1') {
			query<<"banned"<<true;
		}
		if(wquery[3]=='1') {
			query<<"promocodeCount"<<open_document<<"$ne"<<(int32_t)0<<"$exists"<<true<<close_document;
		}
		if(wquery.size()>4) {
			query<<"username"<<open_document<<"$regex"<<bsoncxx::types::b_regex{wquery.substr(4)}<<close_document;
		}
		unsigned int wpage=_wpage->has_value()?**_wpage-1:0;
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		mongocxx::options::find wlist_fo=mongocxx::options::find{}.skip(20*wpage).limit(20);
		auto wlist_o=fbdb["whitelist"].find(query<<finalize, wlist_fo);
		Json::Value wlist_jv(Json::ValueType::arrayValue);
		for(auto &i:wlist_o) {
			std::string i_str=bsoncxx::to_json(i);
			Json::Value item_jv;
			Utils::parseJSON(i_str, &item_jv);
			wlist_jv.append(item_jv);
		}
		auto plistquery=document{};
		if(pquery_username->has_value()) {
			plistquery<<"username"<<open_document<<"$regex"<<bsoncxx::types::b_regex{**pquery_username}<<close_document;
		}
		if(pquery_helper->has_value()) {
			plistquery<<"helper"<<open_document<<"$regex"<<bsoncxx::types::b_regex{**pquery_helper}<<close_document;
		}
		if(pquery_description->has_value()) {
			plistquery<<"description"<<open_document<<"$regex"<<bsoncxx::types::b_regex{**pquery_description}<<close_document;
		}
		unsigned int ppage=_ppage->has_value()?**_ppage-1:0;
		auto plist_fo=mongocxx::options::find{}.sort(document{}<<"_id"<<-1<<finalize).skip(20*ppage).limit(20);
		auto payments_o=fbdb["payments"].find(plistquery<<finalize, plist_fo);
		Json::Value plist_jv(Json::ValueType::arrayValue);
		for(auto &i:payments_o) {
			std::string i_str=bsoncxx::to_json(i);
			Json::Value item_jv;
			Utils::parseJSON(i_str, &item_jv);
			uint64_t date_v=item_jv["date"]["$date"].asUInt64();
			item_jv["date"]=date_v;
			plist_jv.append(item_jv);
		}
		unsigned int pn_wlist=(unsigned int)(fbdb["whitelist"].estimated_document_count()/20.0);
		if(fbdb["whitelist"].estimated_document_count()/20.0>pn_wlist)pn_wlist++;
		unsigned int pn_plist=(unsigned int)(fbdb["payments"].estimated_document_count()/20.0);
		if(fbdb["payments"].estimated_document_count()/20.0>pn_plist)pn_plist++;
		return {true, "ok", "wlist", wlist_jv, "payments", plist_jv, "pn_wlist", pn_wlist, "pn_plist", pn_plist};
	}
	
	LACTION2(PublishAnnouncementAction, "publish_announcement",
			std::string, title, "title",
			std::string, content, "content") {
		time_t m_time=time(nullptr);
		struct tm *ptr_time=gmtime(&m_time);
		time_t utc_time=mktime(ptr_time);
		time_t cn_time=utc_time+3600*8;
		std::string cn_time_str(ctime(&cn_time));
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		fbdb["announcements"].insert_one(document{}<<"title"<<*title<<"content"<<*content<<"date"<<cn_time_str<<"author"<<*session->user->username<<"uniqueId"<<Utils::generateUUID()<<finalize);
		return {true};
	}
	
	LACTION1(RemoveAnnouncementAction, "remove_announcement",
			std::string, uniqueId, "param") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		fbdb["announcements"].delete_one(document{}<<"uniqueId"<<*uniqueId<<finalize);
		return {true};
	}
	
	static FBUCActionCluster dbRelatedGeneralActions(0, {
		Action::enmap(new FetchAnnouncementsAction),
		Action::enmap(new VoteAnnouncementAction),
		Action::enmap(new GetUserContactsAction),
		Action::enmap(new CreateUserContactAction),
		Action::enmap(new UpdateUserContactAction),
		Action::enmap(new DeleteUserContactAction)
	});
	
	static FBUCActionCluster dbRelatedAdministrativeActions(1, {
		Action::enmap(new GetWhitelistAction),
		Action::enmap(new PublishAnnouncementAction),
		Action::enmap(new RemoveAnnouncementAction)
	});
};

