#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <json/json.h>
#include <string>
#include <fmt/format.h>
#include "action.h"

Json::Value FBUC::Action::_execute(Json::Value const& input, std::shared_ptr<FBUC::UserSession> &session) {
	Action *dup=copy();
	Json::Value ret;
	try {
		ret=dup->__execute(input, session);
	}catch(...){
		delete dup;
		throw;
	}
	delete dup;
	return ret;
}

Json::Value FBUC::Action::__execute(Json::Value const& input, std::shared_ptr<FBUC::UserSession> &session) {
	for(auto &i : arguments) {
		if(!(*i)->parse(input)) {
			Json::Value ret_err;
			ret_err["code"]=-400;
			ret_err["success"]=false;
			ret_err["message"]=fmt::format("Parse error for key: {}", (*i)->argument_name);
			return ret_err;
		}
	}
	Json::Value ret;
	ActionResult res=execute(session);
	ret["success"]=res.success;
	ret["message"]=res.message;
	for(auto &i:res.additional_items) {
		ret[i.first]=i.second;
	}
	return ret;
}
