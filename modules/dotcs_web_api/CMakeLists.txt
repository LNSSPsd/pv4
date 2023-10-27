cmake_minimum_required(VERSION 3.14)

project(pv4-dotcs-web-api)
add_library(pv4-dotcs-web-api SHARED
	dotcs_web_api.cpp
)
# 	user_center.cpp
# 	basic.cpp
# 	actions/account.cpp
# 	actions/marketplace.cpp
# 	actions/nemc.cpp
# 	actions/db_related.cpp
# 	actions/phoenix_client.cpp
# 	actions/administrative.cpp
# 	captcha_gen/Captcha.cxx
# 	cotp/cotp.c
# 	cotp/otpuri.c
# 	qrcode/qrcode.c
# )
target_include_directories(pv4-dotcs-web-api PRIVATE)
target_link_libraries(pv4-dotcs-web-api pv4-framework pv4-secrets)