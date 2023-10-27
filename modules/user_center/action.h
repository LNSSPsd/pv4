#pragma once
#define ACTION_PRIVATE_INCLUDED
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
		bool is_fine_parsed=true;
		
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
		T value;
		
		ActionArgument(std::string const& argname) {
			this->argument_name=argname;
		}
		inline operator T() const { return value; }
		virtual bool parse(Json::Value const& input);
		virtual ActionArgumentInternal *copy() const;
	};
	
	struct ActionResult {
		bool success;
		std::string message;
		std::unordered_map<std::string, Json::Value> additional_items;
		
		ActionResult() = default;
		ActionResult(ActionResult const&) = default;
		
		ActionResult(bool stat) : success(stat) {}
		ActionResult(bool stat, std::string const& message) : success(stat), message(message) {}
		template<typename ...Args>
		ActionResult(bool stat, std::string const& message, Args&& ...args);
		
		template<typename ...Args>
		void parseAdditionalItems(std::string const& key, Json::Value val, Args&& ...args);
		inline void parseAdditionalItems() {}
	};

	struct Action {
		std::string action_name;
		std::vector<std::shared_ptr<ActionArgumentInternal>*> arguments;
		
		template <typename... Args>
		Action(std::string const& action_name, Args&&... args) {
			this->action_name=action_name;
			arguments={args...};
		}
		virtual ~Action() = default;
		
		Json::Value _execute(Json::Value const& input, std::shared_ptr<UserSession> &);
		virtual ActionResult execute(std::shared_ptr<UserSession> &connection) = 0;
		virtual Action *copy() const = 0;
		virtual bool mandatory_login() const { return false; }
		
		inline static std::pair<std::string, Action *> enmap(Action *target) {
			return std::make_pair(target->action_name, target);
		}
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
	
	class ActionCluster {
		int type;
		std::vector<std::string> actions;
	public:
		ActionCluster(int, std::unordered_map<std::string, Action *> const&);
		~ActionCluster();
	};
};

#define ARG(v) (std::shared_ptr<ActionArgumentInternal>*)&v

// Inside namespace FBUC:
#define __ACTION_ARG_P__T(...) __VA_OPT__(Argument<__VA_ARGS__>)
#define __ACTION_ARG_P__N(...) __VA_OPT__({__VA_ARGS__};)
#define __ACTION_B_ARG_A(...) __VA_OPT__(, ARG(__VA_ARGS__))
#define ACTION12(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10, T11, A11, N11, T12, A12, N12) \
	struct name : public Action { \
		__ACTION_ARG_P__T(T1) A1 __ACTION_ARG_P__N(N1) \
		__ACTION_ARG_P__T(T2) A2 __ACTION_ARG_P__N(N2) \
		__ACTION_ARG_P__T(T3) A3 __ACTION_ARG_P__N(N3) \
		__ACTION_ARG_P__T(T4) A4 __ACTION_ARG_P__N(N4) \
		__ACTION_ARG_P__T(T5) A5 __ACTION_ARG_P__N(N5) \
		__ACTION_ARG_P__T(T6) A6 __ACTION_ARG_P__N(N6) \
		__ACTION_ARG_P__T(T7) A7 __ACTION_ARG_P__N(N7) \
		__ACTION_ARG_P__T(T8) A8 __ACTION_ARG_P__N(N8) \
		__ACTION_ARG_P__T(T9) A9 __ACTION_ARG_P__N(N9) \
		__ACTION_ARG_P__T(T10) A10 __ACTION_ARG_P__N(N10) \
		__ACTION_ARG_P__T(T11) A11 __ACTION_ARG_P__N(N11) \
		__ACTION_ARG_P__T(T12) A12 __ACTION_ARG_P__N(N12) \
		name() : Action(network_name __ACTION_B_ARG_A(A1) \
					__ACTION_B_ARG_A(A2) \
					__ACTION_B_ARG_A(A3) \
					__ACTION_B_ARG_A(A4) \
					__ACTION_B_ARG_A(A5) \
					__ACTION_B_ARG_A(A6) \
					__ACTION_B_ARG_A(A7) \
					__ACTION_B_ARG_A(A8) \
					__ACTION_B_ARG_A(A9) \
					__ACTION_B_ARG_A(A10) \
					__ACTION_B_ARG_A(A11) \
					__ACTION_B_ARG_A(A12) ) {} \
		virtual Action *copy() const { return new name; } \
		\
		virtual ActionResult execute(std::shared_ptr<FBUC::UserSession> &session); \
		~name() = default; \
	}; \
	ActionResult FBUC::name::execute(std::shared_ptr<FBUC::UserSession> &session)
#define ACTION11(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10, T11, A11, N11) \
	ACTION12(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10, T11, A11, N11,,,)
#define ACTION10(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10) \
	ACTION11(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10,,,)
#define ACTION9(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9) \
	ACTION10(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9,,,)
#define ACTION8(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8) \
	ACTION9(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8,,,)
#define ACTION7(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7) \
	ACTION8(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7,,,)
#define ACTION6(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6) \
	ACTION7(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6,,,)
#define ACTION5(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5) \
	ACTION6(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5,,,)
#define ACTION4(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4) \
	ACTION5(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4,,,)
#define ACTION3(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3) \
	ACTION4(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3,,,)
#define ACTION2(name, network_name, T1, A1, N1, T2, A2, N2) \
	ACTION3(name, network_name, T1, A1, N1, T2, A2, N2,,,)
#define ACTION1(name, network_name, T1, A1, N1) \
	ACTION2(name, network_name, T1, A1, N1,,,)
#define ACTION0(name, network_name) \
	ACTION1(name, network_name,,,)

#define __LACTION_ARG_P__T(...) __VA_OPT__(Argument<__VA_ARGS__>)
#define __LACTION_ARG_P__N(...) __VA_OPT__({__VA_ARGS__};)
#define __LACTION_B_ARG_A(...) __VA_OPT__(, ARG(__VA_ARGS__))
#define LACTION12(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10, T11, A11, N11, T12, A12, N12) \
	struct name : public Action { \
		__ACTION_ARG_P__T(T1) A1 __ACTION_ARG_P__N(N1) \
		__ACTION_ARG_P__T(T2) A2 __ACTION_ARG_P__N(N2) \
		__ACTION_ARG_P__T(T3) A3 __ACTION_ARG_P__N(N3) \
		__ACTION_ARG_P__T(T4) A4 __ACTION_ARG_P__N(N4) \
		__ACTION_ARG_P__T(T5) A5 __ACTION_ARG_P__N(N5) \
		__ACTION_ARG_P__T(T6) A6 __ACTION_ARG_P__N(N6) \
		__ACTION_ARG_P__T(T7) A7 __ACTION_ARG_P__N(N7) \
		__ACTION_ARG_P__T(T8) A8 __ACTION_ARG_P__N(N8) \
		__ACTION_ARG_P__T(T9) A9 __ACTION_ARG_P__N(N9) \
		__ACTION_ARG_P__T(T10) A10 __ACTION_ARG_P__N(N10) \
		__ACTION_ARG_P__T(T11) A11 __ACTION_ARG_P__N(N11) \
		__ACTION_ARG_P__T(T12) A12 __ACTION_ARG_P__N(N12) \
		name() : Action(network_name __ACTION_B_ARG_A(A1) \
					__ACTION_B_ARG_A(A2) \
					__ACTION_B_ARG_A(A3) \
					__ACTION_B_ARG_A(A4) \
					__ACTION_B_ARG_A(A5) \
					__ACTION_B_ARG_A(A6) \
					__ACTION_B_ARG_A(A7) \
					__ACTION_B_ARG_A(A8) \
					__ACTION_B_ARG_A(A9) \
					__ACTION_B_ARG_A(A10) \
					__ACTION_B_ARG_A(A11) \
					__ACTION_B_ARG_A(A12) ) {} \
		virtual Action *copy() const { return new name; } \
		\
		virtual bool mandatory_login() const { return true; } \
		\
		virtual ActionResult execute(std::shared_ptr<FBUC::UserSession> &session); \
	}; \
	ActionResult FBUC::name::execute(std::shared_ptr<FBUC::UserSession> &session)
#define LACTION11(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10, T11, A11, N11) \
	LACTION12(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10, T11, A11, N11,,,)
#define LACTION10(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10) \
	LACTION11(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9, T10, A10, N10,,,)
#define LACTION9(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9) \
	LACTION10(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8, T9, A9, N9,,,)
#define LACTION8(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8) \
	LACTION9(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7, T8, A8, N8,,,)
#define LACTION7(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7) \
	LACTION8(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6, T7, A7, N7,,,)
#define LACTION6(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6) \
	LACTION7(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5, T6, A6, N6,,,)
#define LACTION5(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5) \
	LACTION6(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4, T5, A5, N5,,,)
#define LACTION4(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4) \
	LACTION5(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3, T4, A4, N4,,,)
#define LACTION3(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3) \
	LACTION4(name, network_name, T1, A1, N1, T2, A2, N2, T3, A3, N3,,,)
#define LACTION2(name, network_name, T1, A1, N1, T2, A2, N2) \
	LACTION3(name, network_name, T1, A1, N1, T2, A2, N2,,,)
#define LACTION1(name, network_name, T1, A1, N1) \
	LACTION2(name, network_name, T1, A1, N1,,,)
#define LACTION0(name, network_name) \
	LACTION1(name, network_name,,,)
