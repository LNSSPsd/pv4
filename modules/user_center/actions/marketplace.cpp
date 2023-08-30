#include "../user_center.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "cpp-httplib/httplib.h"
#include "utils.h"
#include "products.h"
#include <fmt/format.h>

extern httplib::Client stripeClient;

namespace FBUC
{
	LACTION0(GetProductListAction, "get_product_list")
	{
		FBWhitelist::User &user = *session->user;
		std::vector<Product *> const &products = all_products();
		Json::Value product_list(Json::arrayValue);
		for (Product *i : products)
		{
			if (i->forbid_cart() || !i->check_on(user))
				continue;
			product_list.append(i->toJSON());
		}
		return {true, "", "products", product_list};
	}

	LACTION1(AddProductToCartAction, "add_product_to_cart",
			 std::string, _product_id, "product_id")
	{

		unsigned int product_id = std::stoi(_product_id);
		Product *target = nullptr;
		std::vector<Product *> const &products = all_products();
		for (Product *i : products)
		{
			if (i->product_id() == product_id)
			{
				target = i;
				break;
			}
		}
		if (!target)
		{
			return {false, "未找到商品"};
		}
		if (!target->check_on(*session->user))
		{
			return {false, "你未满足购买此商品的所需条件"};
		}
		if (target->forbid_cart())
		{
			return {false, "商品禁止加入购物车。"};
		}
		if (target->no_multi_add())
		{
			for (Product *i : session->cart)
			{
				if (i == target)
				{
					return {false, "商品已在购物车"};
				}
			}
		}
		if (session->cart.size() > 8)
		{
			return {false, "购物车内商品过多"};
		}
		session->cart.push_back(target);
		return {true, ""};
	}

	LACTION0(GetShoppingCartAction, "get_shopping_cart")
	{
		Json::Value ret_val(Json::arrayValue);
		for (Product *i : session->cart)
		{
			ret_val.append(i->toJSON());
		}
		throw DirectReturnDemand{Utils::writeJSON(ret_val), "application/json"};
	}

	LACTION1(EraseFromShoppingCartAction, "erase_from_shopping_cart",
			 std::string, _product_id, "product_id")
	{
		uint32_t product_id = std::stoi(_product_id);
		for (std::vector<Product *>::iterator it = session->cart.begin(); it != session->cart.end();)
		{
			if ((*it)->product_id() == product_id)
			{
				it = session->cart.erase(it);
				// Erase only one
				break;
			}
			else
			{
				it++;
			}
		}
		return {true, ""};
	}

	LACTION0(GenerateBillAction, "generate_bill")
	{
		if (!session->user->isDotCS)
		{
			if (!session->cart.size())
			{
				return {false, "购物车里没有商品"};
			}
			FBUC::PaymentIntent *currentPaymentIntent = new FBUC::PaymentIntent;
			currentPaymentIntent->session = session;
			if (session->user->banned_from_payment)
			{
				currentPaymentIntent->banned_from_payment = true;
			}
			else
			{
				currentPaymentIntent->needs_verify = false;
				// currentPaymentIntent->needs_verify=!session->user->payment_verify_fingerprint.has_value();
			}
			for (Product *i : session->cart)
			{
				currentPaymentIntent->content.push_back(i);
				if (i->card_only())
				{
					currentPaymentIntent->card_only = true;
				}
				currentPaymentIntent->price += i->price();
				if ((unsigned int)i->price() * 0.8 == 0 && i->price() != 0)
				{
					currentPaymentIntent->helper_price += 1;
				}
				else
				{
					currentPaymentIntent->helper_price += i->price() * 0.8;
				}
			}
			currentPaymentIntent->points_delta = currentPaymentIntent->price * 7;
			if (currentPaymentIntent->price < 6)
			{
				currentPaymentIntent->stripe_price = 6;
			}
			else
			{
				currentPaymentIntent->stripe_price = currentPaymentIntent->price;
			}
			auto ptr = std::shared_ptr<FBUC::PaymentIntent>(currentPaymentIntent);
			payments_mutex.lock();
			payment_intents[session->user->username] = ptr;
			payments_mutex.unlock();
			session->payment_intent = ptr;
			return {true, "", "location", "/pay"};
		}
		else
		{
			return {false, "请前往 幻梦互联用户中心下单。您没有权限在FastBuilder用户中心下单。"};
		}
	}

	LACTION1(GetBillAction, "get_bill",
			 Session, session, "secret")
	{
		if (!session->payment_intent)
		{
			return {false, "", "show", "未找到交易或交易已完成"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent = session->payment_intent;
		std::string show;
		for (Product *sub : intent->content)
		{
			if (sub->card_only())
			{
				show += "[仅官方支付] ";
			}
			show += fmt::format("{}: ￥{}\n", sub->product_name(), sub->price());
		}
		show += fmt::format("\n<b>合计</b>: ￥{}\n", intent->price ? std::to_string(intent->price) : "免费");
		if (intent->stripe_price != intent->price && intent->price != 0)
		{
			show += fmt::format("官方支付最低价: ￥{}\n", intent->stripe_price);
		}
		if (intent->card_only)
		{
			show += "注意：含有仅官方支付商品。\n";
		}
		show += fmt::format("现有 Points: <b style=\"color:orange;\">{}</b>\n", *session->user->points);
		if (intent->points_delta >= 0)
		{
			show += fmt::format("获得 Points: <b style=\"color:blue;\">{}</b>\n", intent->points_delta);
		}
		else
		{
			show += fmt::format("消耗 Points: <b style=\"color:red;\">{}</b>\n", -intent->points_delta);
		}
		if (intent->banned_from_payment)
		{
			show += "<hr/><b style=\"color:red;\">由于您的支付信息与他人出现重合，此账户已被永久禁止支付，其他功能不受影响。</b>";
		}
		if (intent->needs_verify)
		{
			show += "<hr/><b style=\"color:blue;\">由于我们需要验证您的账户唯一性，本次支付只能使用本页面上的支付方式完成。</b>\n";
		}
		bool can_use_point = true;
		if (intent->points_delta < 0 || intent->banned_from_payment || (session->user->free && !session->user->expiration_date.stillAlive()))
		{
			can_use_point = false;
		}
		if (getenv("DEBUG"))
		{
			show += "\n\n<b style=\"color:red;\">调试模式</b>";
			return {true, "", "show", show, "codepwn_pay_available", false, "isfree", intent->helper_price == 0 && intent->price == 0, "can_use_point", can_use_point, "needs_verify", intent->needs_verify};
		}
		return {true, "", "show", show, "codepwn_pay_available", false, "isfree", intent->helper_price == 0 && intent->price == 0, "can_use_point", can_use_point, "needs_verify", intent->needs_verify};
	}

	LACTION0(CheckPaymentAction, "check_payment")
	{
		std::shared_ptr<FBUC::PaymentIntent> intent = session->payment_intent;
		if (!intent)
		{
			return {false, "会话已经过期", "expired", true};
		}
		if (!intent->paired || !intent->approved)
		{
			return {false, "尚未确认", "paired", intent->paired, "price", intent->price};
		}
		return {true, "Well done", "paired", true, "approved", true};
	}

	LACTION0(UCGetBalanceAction, "get_balance")
	{
		Json::Value ret;
		if (session->user->promocode_count.has_value())
		{
			ret.append(*session->user->promocode_count);
		}
		else
		{
			ret.append(0);
		}
		ret.append(0);
		ret.append(0);
		throw DirectReturnDemand{Utils::writeJSON(ret), "application/json"};
	}

	LACTION1(PairPaymentAction, "pair_payment",
			 std::string, identifier, "number")
	{
		payments_mutex.lock_shared();
		if (!payment_intents.contains(identifier))
		{
			payments_mutex.unlock_shared();
			return {false, "确认码或用户名无效"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent = payment_intents[identifier];
		payments_mutex.unlock_shared();
		if (intent->needs_verify)
		{
			return {false, "用户需要完成一次官方支付以满足唯一性验证需求"};
		}
		else if (intent->paired)
		{
			return {false, "指定确认码已然匹配，请让用户重新结算。"};
		}
		else if (intent->card_only)
		{
			return {false, "支付中存在仅官方支付商品，不能使用此方法结帐"};
		}
		if (*session->user->promocode_count <= 0)
		{
			return {false, "余额不足"};
		}
		std::string list;
		for (Product *i : intent->content)
		{
			list += fmt::format("{}: ￥{}<br/>", i->product_name(), i->price());
		}
		list += fmt::format("用户价格合计: ￥{}<br/>代理价合计: ￥{}<br/>", intent->price, intent->helper_price);
		if (*session->user->promocode_count < intent->helper_price)
		{
			return {false, "未确认。交易不能完成，因为余额不足。", "list", list};
		}
		intent->paired = true;
		intent->pairee = session->user->username;
		return {true, "", "list", list};
	}

	LACTION1(ApprovePaymentAction, "approve_payment",
			 std::string, identifier, "number")
	{
		payments_mutex.lock_shared();
		if (!payment_intents.contains(identifier))
		{
			payments_mutex.unlock_shared();
			return {false, "确认码无效"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent = payment_intents[identifier];
		payments_mutex.unlock_shared();
		if (intent->needs_verify)
		{
			return {false, "用户需要完成一次官方支付以满足唯一性验证需求"};
		}
		else if (intent->card_only)
		{
			return {false, "支付中存在仅官方支付商品，不能使用此方法结帐"};
		}
		else if (intent->banned_from_payment)
		{
			throw InvalidRequestDemand{"Payment-banned user"};
		}
		int64_t final = session->user->promocode_count - intent->helper_price;
		if (final < 0)
		{
			return {false, "余额不足"};
		}
		std::shared_ptr<FBUC::UserSession> targetSession = intent->session.lock();
		if (!targetSession || intent->approved)
		{
			return {false, "会话过期"};
		}
		session->user->promocode_count = final;
		finalizePaymentIntent(intent, targetSession->user.get(), session->user->username);
		return {true, "Well done"};
	}

	LACTION1(RedeemForFreeAction, "redeem_for_free",
			 std::string, captcha, "captcha")
	{
		if (!session->verifyCaptcha(captcha))
		{
			return {false, "验证码错误"};
		}
		if (!session->payment_intent)
		{
			return {false, "无商品"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent = session->payment_intent;
		if (intent->approved)
		{
			return {false, "无商品"};
		}
		if (intent->price > 0 || intent->helper_price > 0)
		{
			return {false, "商品需要付费，而非免费获取"};
		}
		finalizePaymentIntent(intent, session->user.get(), "@Free");
		return {true};
	}

	LACTION0(StripeCreateSessionAction, "stripe_create_session")
	{
		std::shared_ptr<FBUC::PaymentIntent> intent = session->payment_intent;
		if (!intent || intent->approved)
		{
			return {false, "没有有效的支付请求"};
		}
		if (!intent->content.size())
		{
			throw InvalidRequestDemand{"Invalid request"};
		}
		if (intent->banned_from_payment)
		{
			throw InvalidRequestDemand{"Payment request while being banned from payment"};
		}
		std::string return_url = "https://api.fastbuilder.pro/api/stripe_recover?ssid=";
		if (getenv("DEBUG"))
		{
			return_url = "http://127.0.0.1:8687/api/stripe_recover?ssid=";
		}
		return_url += session->session_id;
		httplib::Params params{
			//{"line_items[0][quantity]", "1"},
			//{"line_items[0][price_data][tax_behavior]", "exclusive"},
			//{"line_items[0][price_data][currency]", "cny"},
			//{"line_items[0][price_data][product_data][name]", "User Center Products"},
			//{"line_items[0][price_data][unit_amount]", std::to_string(intent->stripe_price*100)},
			{"mode", "payment"},
			{"allow_promotion_codes", "true"},
			{"payment_method_types[0]", "card"},
			{"payment_method_types[1]", "alipay"},
			{"success_url", return_url},
			{"cancel_url", return_url},
			{"automatic_tax[enabled]", "true"},
			{"consent_collection[terms_of_service]", "required"}};
		if (intent->points_delta < 0)
		{
			params.emplace("line_items[0][quantity]", "1");
			params.emplace("line_items[0][price_data][tax_behavior]", "exclusive");
			params.emplace("line_items[0][price_data][currency]", "cny");
			params.emplace("line_items[0][price_data][product_data][name]", "Discounted Products Set");
			params.emplace("line_items[0][price_data][unit_amount]", std::to_string(intent->stripe_price * 100));
		}
		else
		{
			for (unsigned int i = 0; i < intent->content.size(); i++)
			{
				Product *item = intent->content[i];
				params.emplace(fmt::format("line_items[{}][quantity]", i), "1");
				params.emplace(fmt::format("line_items[{}][price_data][tax_behavior]", i), "exclusive");
				params.emplace(fmt::format("line_items[{}][price_data][currency]", i), "cny");
				params.emplace(fmt::format("line_items[{}][price_data][product_data][name]", i), item->product_name_en());
				params.emplace(fmt::format("line_items[{}][price_data][unit_amount]", i), std::to_string(item->price() * 100));
			}
		}
	stripe_retry_01:
	{
	}
		auto stripe_res = stripeClient.Post("/v1/checkout/sessions", params);
		if (!stripe_res)
		{
			goto stripe_retry_01;
		}
		Json::Value stripe_parsed;
		if (!Utils::parseJSON(stripe_res->body, &stripe_parsed, nullptr))
		{
			throw ServerErrorDemand{"Failed to parse stripe response"};
		}
		payments_mutex.lock();
		payment_intents[stripe_parsed["id"].asString()] = payment_intents[session->user->username];
		payments_mutex.unlock();
		intent->stripe_pid = stripe_parsed["id"].asString();
		return {true, "", "url", stripe_parsed["url"]};
	}

	/*LACTION0(GetPaymentLogAction, "get_payment_log") {
		std::shared_ptr<FBWhitelist::User> user=session->user;
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto payments_o=fbdb["payments"].find(document{}<<"username"<<*(user->username)<<finalize);
		Json::Value ret_arr(Json::arrayValue);
		for(auto &i:payments_o) {
			std::string i_str=bsoncxx::to_json(i);
			Json::Value item_jv;
			Utils::parseJSON(i_str, &item_jv);
			uint64_t date_v=item_jv["date"]["$date"].asUInt64();
			item_jv["date"]=date_v;
			std::string description="";
			if(item_jv["refunded"].asBool()) {
				description+="<b style=\"color:red;\">[已退款]</b><br/>";
			}
			if(item_jv["helper"].isString()&&item_jv["helper"].asString()[0]=='@') {
				description+="官方支付<br/>";
			}else{
				description+=fmt::format("代理支付: {}<br/>", item_jv["helper"].asString());
			}
			Json::Value content_parsed;
			if(item_jv["content"].isString()) {
				Utils::parseJSON(item_jv["content"].asString(), &content_parsed);
			}else{
				content_parsed=item_jv["content"];
			}
			description+="<hr/><ol>";
			for(Json::Value const& sub:content_parsed) {
				description+=fmt::format("<li>{} - ￥{}</li>", sub["product_name"].asString(), sub["price"].asInt());
			}
			description+="</ol>";
			Json::Value current;
			current["identifier"]=item_jv["date"];
			current["description"]=description;
			ret_arr.insert(0, current);
		}
		return {true, "", "payments", ret_arr, "pages", 1};
	}*/

	LACTION1(HelperChargeAction, "helper_charge",
			 uint32_t, value, "value")
	{
		if (*value >= 800 || *value < 6)
			throw InvalidRequestDemand{"Invalid amount given"};
		if (*session->user->promocode_count == 0)
			throw InvalidRequestDemand{"User not permitted to charge"};
		std::string return_url = fmt::format("https://api.fastbuilder.pro/api/stripe_recover?is_checkout=1&ssid={}", session->session_id);
		if (getenv("DEBUG"))
		{
			return_url = fmt::format("http://127.0.0.1:8687/api/stripe_recover?is_checkout=1&ssid={}", session->session_id);
		}
		httplib::Params params{
			{"line_items[0][quantity]", "1"},
			{"line_items[0][price_data][tax_behavior]", "exclusive"},
			{"line_items[0][price_data][currency]", "cny"},
			{"line_items[0][price_data][product_data][name]", "FBUC Charge"},
			{"line_items[0][price_data][unit_amount]", std::to_string(value * 100)},
			{"mode", "payment"},
			{"allow_promotion_codes", "true"},
			{"payment_method_types[0]", "card"},
			{"payment_method_types[1]", "alipay"},
			{"success_url", return_url},
			{"cancel_url", return_url},
			{"automatic_tax[enabled]", "true"}};
	stripe_retry_02:
	{
	}
		auto stripe_res = stripeClient.Post("/v1/checkout/sessions", params);
		if (!stripe_res)
		{
			goto stripe_retry_02;
		}
		Json::Value stripe_parsed;
		if (!Utils::parseJSON(stripe_res->body, &stripe_parsed, nullptr))
		{
			throw ServerErrorDemand{"Failed to parse stripe response"};
		}
		PaymentIntent *chargeIntent = new PaymentIntent;
		chargeIntent->session = session;
		chargeIntent->price = 801;
		chargeIntent->stripe_price = 801;
		chargeIntent->helper_price = value;
		chargeIntent->card_only = true;
		auto shared_intent = std::shared_ptr<PaymentIntent>(chargeIntent);
		payments_mutex.lock();
		payment_intents[stripe_parsed["id"].asString()] = shared_intent;
		payments_mutex.unlock();
		session->payment_intent = shared_intent;
		return {true, "created", "url", stripe_parsed["url"]};
	}

	LACTION1(CheckoutUsePointsAction, "use_points_on_checkout",
			 uint32_t, value, "value")
	{
		std::shared_ptr<FBUC::PaymentIntent> intent = session->payment_intent;
		if (!intent || intent->paired || intent->approved)
		{
			return {false, "没有有效的支付请求"};
		}
		if (!*value || !intent->content.size())
		{
			throw InvalidRequestDemand{"Invalid request"};
		}
		if (intent->banned_from_payment)
		{
			throw InvalidRequestDemand{"Payment request while being banned from payment"};
		}
		if (session->user->free && !session->user->expiration_date.stillAlive())
		{
			throw InvalidRequestDemand{"Invalid request"};
		}
		if (intent->points_delta < 0)
		{
			return {false, "已经使用过 Points"};
		}
		if (*value > session->user->points)
			return {false, "Points 不足"};
		if (*value % 100)
			return {false, "Points 使用不符合规则"};
		intent->points_delta = -value;
		uint32_t price_delta = *value / 100;
		if (price_delta >= intent->price)
		{
			intent->points_delta = -(intent->price * 100);
			intent->price = 0;
			intent->helper_price = 0;
			intent->stripe_price = 0;
		}
		else
		{
			intent->price -= price_delta;
			intent->helper_price -= round((price_delta) * 0.4);
			intent->stripe_price -= price_delta;
			if (intent->stripe_price < 6)
				intent->stripe_price = 6;
		}
		return {true, "Perfect"};
	}

	static FBUCActionCluster marketplaceGeneralActions(0, {
															  Action::enmap(new GetProductListAction),
															  Action::enmap(new AddProductToCartAction),
															  Action::enmap(new GetShoppingCartAction),
															  Action::enmap(new EraseFromShoppingCartAction),
															  Action::enmap(new GenerateBillAction),
															  Action::enmap(new GetBillAction),
															  Action::enmap(new CheckPaymentAction),
															  Action::enmap(new UCGetBalanceAction),
															  Action::enmap(new PairPaymentAction),
															  Action::enmap(new ApprovePaymentAction),
															  Action::enmap(new HelperChargeAction),
															  Action::enmap(new CheckoutUsePointsAction),
															  Action::enmap(new RedeemForFreeAction),
															  Action::enmap(new StripeCreateSessionAction)
															  // Action::enmap(new GetPaymentLogAction) -> db_related.cpp
														  });
};
