#include "../user_center.h"
#include "utils.h"
#include "secrets.h"

namespace FBUC {
	LACTION0(UCCalculateMonthlyPlanDurationAction, "calculate_monthly_plan_duration") {
		if(!session->user->free) {
			return {true, "", "duration", -1};
		}else if(!session->user->expiration_date.stillAlive()) {
			return {true, "", "duration", 0};
		}
		return {true, "", "duration", round(((session->user->expiration_date-time(nullptr))/86400.00)*100.0)/100.0};
	}
	
	LACTION2(UCAddBalanceAction, "add_balance",
			FBWhitelist::User, user, "username",
			uint64_t, count, "value") {
		user->promocode_count+=count;
		return {true, "ok"};
	}
	
	LACTION0(ClearBalanceAction, "clear_balance") {
		session->user->promocode_count.unset();
		return {true, "ok"};
	}
	
	LACTION1(UCDropUserAction, "drop_user",
			FBWhitelist::User, target, "username") {
		FBWhitelist::Whitelist::dropUser(target->username);
		return {true, "Well done"};
	}
	
	LACTION2(UpdateUserPasswordAction, "update_user_password",
			FBWhitelist::User, user, "username",
			std::string, new_password, "new_password") {
		if(new_password->length()!=64||new_password=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
			throw InvalidRequestDemand{"Invalid password value"};
		}
		user->password=Utils::sha256(Secrets::addSalt(*new_password));
		return {true};
	}
	
	LACTION3(AddUserAction, "add_user",
			std::optional<FBWhitelist::User>, user_if_exist, "username",
			std::string, username, "username",
			std::string, password, "password") {
		if(user_if_exist->has_value()) {
			return {false, "Such user is already existed."};
		}
		auto newUser=FBWhitelist::Whitelist::createUser(username, Utils::sha256(Secrets::addSalt(password)));
		if(!newUser.has_value()) {
			return {false, "Failed to create user"};
		}
		Json::Value ret;
		ret["username"]=*username;
		ret["banned"]=false;
		ret["password"]=Utils::sha256(Secrets::addSalt(*password));
		ret["owns"]=Json::Value(Json::ValueType::arrayValue);
		ret["free"]=true;
		return {true,"","userwl",ret};
	}
	
	LACTION0(ExportUserDataAction, "export_user_data") {
		throw ServerErrorDemand{"Not implemented yet"};
	}
	
	ACTION2(ExternalBotGetUserInfoAction, "bot_ext_get_userinfo",
			std::string, username, "username",
			std::string, token, "token") {
		if(token!=Secrets::add_external_bot_salt("ACCESS"))
			throw AccessDeniedDemand{"Access denied"};
		auto userinfo=FBWhitelist::Whitelist::acquireUser(username);
		if(!userinfo) {
			return {true, "honored", "nouser", true};
		}
		float mp_duration;
		if(!userinfo->free) {
			mp_duration=-1;
		}else if(!userinfo->expiration_date.stillAlive()) {
			mp_duration=0;
		}else{
			mp_duration=round(((userinfo->expiration_date-time(nullptr))/86400.00)*100.0)/100.0;
		}
		return {true, "honored", "nouser", false, "slots", userinfo->rentalservers.toDescriptiveJSON(), "mp", mp_duration, "points", *userinfo->points};
	}
	
	LACTION1(GetUserWhitelistValueAction, "get_user_whitelist_value",
			FBWhitelist::User, user, "username") {
		Json::Value output(Json::ValueType::arrayValue);
		for(FBWhitelist::DBValue<bool> &val:*user) {
			output.append(val.toJSON());
		}
		return {true, "", "value", output};
	}
	
	LACTION6(SetUserWhitelistValueAction, "set_user_whitelist_value",
			FBWhitelist::User, user, "username",
			std::string, item_name, "item_name",
			std::optional<int64_t>, int_value, "value",
			std::optional<std::string>, string_value, "value",
			std::optional<bool>, bool_value, "value",
			std::optional<bool>, is_unset, "is_unset") {
		Json::Value val;
		FBWhitelist::DBValue<bool> *target=nullptr;
		const char *itm=item_name->c_str();
		for(FBWhitelist::DBValue<bool> &val:*user) {
			if(!strcmp(val.item_name, itm)) {
				if(is_unset->has_value()&&**is_unset) {
					val.unset();
					goto set_user_whitelist_value__early_return;
				}
				target=&val;
				break;
			}
		}
		if(!target) {
			throw InvalidRequestDemand{"Target database item not found"};
		}
		if(int_value->has_value()) {
			val=**int_value;
		}else if(string_value->has_value()) {
			val=**string_value;
		}else if(bool_value->has_value()) {
			val=**bool_value;
		}else{
			throw InvalidRequestDemand{"Invalid type"};
		}
		try {
			target->fromJSON(val);
		}catch(std::runtime_error const& err) {
			throw InvalidRequestDemand{"Operation failed: "+(std::string)err.what()};
		}
		set_user_whitelist_value__early_return: {}
		Json::Value output(Json::ValueType::arrayValue);
		for(FBWhitelist::DBValue<bool> &val:*user) {
			output.append(val.toJSON());
		}
		return {true, "", "value", output};
	}
	
	LACTION3(RentalServerOperationAction, "rental_server_operation",
			FBWhitelist::User, user, "username",
			std::optional<std::string>, slotid, "slotid",
			std::string, operation, "operation") {
		if(operation=="unlock") {
			if(!slotid->has_value()) {
				throw InvalidRequestDemand{"Missing required argument `slotid'."};
			}
			auto slot=user->rentalservers[**slotid];
			if(slot) {
				slot.locked.unset();
				slot.lastdate.unset();
			}
		}else if(operation=="remove") {
			if(!slotid->has_value()) {
				throw InvalidRequestDemand{"Missing required argument `slotid'."};
			}
			user->rentalservers.erase_slot(**slotid);
		}else if(operation=="add") {
			user->rentalservers.append_slot();
		}else if(operation=="lock") {
			if(!slotid->has_value()) {
				throw InvalidRequestDemand{"Missing required argument `slotid'."};
			}
			auto slot=user->rentalservers[**slotid];
			if(slot) {
				slot.locked=true;
			}
		}else{
			throw InvalidRequestDemand{"Invalid operation"};
		}
		return {true, "ok"};
	}
	
	LACTION1(ListUserRentalServersAction, "list_user_rental_servers",
			FBWhitelist::User, user, "user") {
		return {true, "", "rentalservers", user->rentalservers.toAdministrativeJSON()};
	}
	
	static FBUCActionCluster administrativeGeneralActions(0, {
		//Action::enmap(new UCCalculateMonthlyPlanDurationAction),
		Action::enmap(new ExternalBotGetUserInfoAction)
	});
	
	static FBUCActionCluster ucAdministrativeActions(1, {
		Action::enmap(new UCAddBalanceAction),
		Action::enmap(new ClearBalanceAction),
		Action::enmap(new UCDropUserAction),
		Action::enmap(new UpdateUserPasswordAction),
		Action::enmap(new AddUserAction),
		Action::enmap(new GetUserWhitelistValueAction),
		Action::enmap(new SetUserWhitelistValueAction),
		Action::enmap(new RentalServerOperationAction),
		Action::enmap(new ListUserRentalServersAction)
	});
};