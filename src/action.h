#pragma once

#ifndef ACTION_PRIVATE_INCLUDED

#include <string>
#include <vector>
#include <memory>
#include <variant>
#include <unordered_map>
#include <json/json.h>

namespace FBUC {
	struct UserSession;

	struct ActionArgumentInternal {
		std::string argument_name;
		bool is_fine_parsed;
		
		virtual bool argument_presented(Json::Value const& input) const {
			return input.isMember(argument_name);
		}
		virtual ~ActionArgumentInternal() = default;
		// bool indicates for whether it's successful
		virtual bool parse(Json::Value const& input) = 0;
		virtual ActionArgumentInternal *copy() const = 0;
	};
	
	template <typename T>
	struct ActionArgument : public ActionArgumentInternal {
		ActionArgument(void *ptr);
	
		virtual bool parse(Json::Value const& input);
		virtual ActionArgumentInternal *copy() const;
	};
	
	struct ActionResult {
		bool success;
		std::string message;
		std::unordered_map<std::string, Json::Value> additional_items;
		
		ActionResult() = default;
		ActionResult(ActionResult const&) = default;
	};

	struct Action {
		std::string action_name;
		std::vector<std::shared_ptr<ActionArgumentInternal>*> arguments;
		
		Action();
		virtual ~Action();
		
		virtual ActionResult execute(std::shared_ptr<UserSession> &connection) = 0;
		virtual Action *copy() const = 0;
		virtual bool mandatory_login() const = 0;
		Json::Value _execute(Json::Value const& input, std::shared_ptr<UserSession> &connection);
		Json::Value __execute(Json::Value const& input, std::shared_ptr<UserSession> &connection);
	};
	
	template <typename T>
	struct Argument {
		std::shared_ptr<ActionArgumentInternal> internal;
		Argument(std::string const& argname) : internal(ActionArgument<T>(argname).copy()) {}
		
		inline operator T() {
			return (T)(ActionArgument<T>&)*internal;
		}
		
		inline T operator *() {
			return (T)(ActionArgument<T>&)*internal;
		}
		
		inline T *operator->() {
			return &((ActionArgument<T>&)*internal).value;
		}
		
		inline bool operator==(T const& b) const {
			return ((ActionArgument<T>&)*internal).value==b;
		}
		
		inline auto operator<=>(T const& b) const {
			return ((ActionArgument<T>&)*internal).value<=>b;
		}
		
		inline operator std::shared_ptr<ActionArgumentInternal>() {
			return internal;
		}
	};
};

#endif