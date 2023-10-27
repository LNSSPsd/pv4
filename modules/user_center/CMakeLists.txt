cmake_minimum_required(VERSION 3.14)

project(pv4-user-center CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-enum-enum-conversion")

add_library(pv4-user-center SHARED
	user_center.cpp
	basic.cpp
	actions/account.cpp
	actions/marketplace.cpp
	actions/nemc.cpp
	actions/db_related.cpp
	actions/phoenix_client.cpp
	actions/administrative.cpp
	captcha_gen/Captcha.cxx
	cotp/cotp.c
	cotp/otpuri.c
	qrcode/qrcode.c
)
target_include_directories(pv4-user-center PRIVATE captcha_gen)
target_link_libraries(pv4-user-center pv4-framework pv4-secrets pv4-products_private)