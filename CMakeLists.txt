cmake_minimum_required(VERSION 3.14)

project(pv4)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -pie")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -pie")
set(CMAKE_VISIBILITY_INLINES_HIDDEN OFF)
set(CMAKE_CXX_VISIBILITY_PRESET "default")


set(ENABLE_ICU OFF CACHE BOOL "")
set(ENABLE_SASL OFF CACHE BOOL "")
set(ENABLE_STATIC ON CACHE BOOL "")
set(ENABLE_TESTS OFF CACHE BOOL "")
set(ENABLE_EXAMPLES OFF CACHE BOOL "")
set(ENABLE_SRV OFF CACHE BOOL "")
set(ENABLE_SSL OFF CACHE BOOL "")
add_subdirectory(mongodb/mongo-c-driver)

include(cmake/pv4-framework.cmake)

add_subdirectory(modules/shutdown)
add_subdirectory(modules/whitelist)
add_subdirectory(modules/secrets)
add_subdirectory(modules/products)
if(EXISTS ${PROJECT_SOURCE_DIR}/modules/private/nemc_helper)
	set(PV4_USE_PRIVATE_NEMC_HELPER ON)
	add_subdirectory(${PROJECT_SOURCE_DIR}/modules/private/nemc_helper)
else()
	add_subdirectory(modules/nemc_helper)
endif()
add_subdirectory(modules/user_center)
if(EXISTS ${PROJECT_SOURCE_DIR}/modules/private/dotcs_web_api)
	add_subdirectory(${PROJECT_SOURCE_DIR}/modules/private/dotcs_web_api)
else()
	add_subdirectory(modules/dotcs_web_api)
endif()

find_package(OpenSSL REQUIRED)

add_executable(pv4 src/main.cpp src/action.cpp src/modules.cpp src/utils.cpp)
set_property(TARGET pv4 PROPERTY ENABLE_EXPORTS ON)
add_custom_command(TARGET pv4 POST_BUILD COMMAND cp ${PROJECT_SOURCE_DIR}/modules.json ${PROJECT_BINARY_DIR}/)
target_link_libraries(pv4 
	bson_static
	mongoc_static
	-Wl,--whole-archive
	fmt
	jsoncpp_static
	bsoncxx_static
	mongocxx_static
	spdlog
	httplib
	-Wl,--no-whole-archive
	${OpenSSL_LIBRARIES}
)
