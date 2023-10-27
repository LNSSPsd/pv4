cmake_minimum_required(VERSION 3.14)

project(pv4-whitelist)

add_library(pv4-whitelist SHARED whitelist.cpp)
target_link_libraries(pv4-whitelist pv4-framework)