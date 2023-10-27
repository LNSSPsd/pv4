#ifdef HAVE_CONFIG_H
#include <config.h>
#else
// Assume defines when unconfigured
#define HAVE_LINK_H
#endif

#ifdef HAVE_LINK_H
#include <link.h>
#endif
#include <dlfcn.h>
#include <mutex>
#include <vector>
#include <stdexcept>
#include <signal.h>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include "modules.h"
#include "utils.h"

struct Module {
	void *handle;
	std::string name;
	std::vector<std::string> pre_deinit_funcs;
	std::vector<std::string> deinit_funcs;
};

static std::vector<Module> modules;
std::vector<std::string> modules_suppress_loading;

static bool should_shutdown=false;
static std::mutex loadingMutex;

extern void _wait_until_server_idle();

void Modules::switchSuppressLoading(std::string const& name) {
	auto val=std::find(modules_suppress_loading.begin(), modules_suppress_loading.end(), name);
	if(val!=modules_suppress_loading.end()) {
		modules_suppress_loading.erase(val);
		return;
	}
	modules_suppress_loading.push_back(name);
}

std::string Modules::getModuleFromHandle(void *handle) {
	for(auto const &i:modules) {
		if(i.handle==handle) {
			return i.name;
		}
	}
	return "";
}

extern void register_general_sighandlers();

void Modules::scheduleReload() {
	SPDLOG_INFO("Modules reloading scheduled");
	std::thread([](){
		loadingMutex.lock();
		Modules::loadModules();
		loadingMutex.unlock();
	}).detach();
}

void Modules::scheduleTeardown() {
	should_shutdown=true;
	scheduleReload();
	//unloadModules();
	SPDLOG_INFO("Modules teardown scheduled");
}

void Modules::doImmediateUnload() {
	SPDLOG_INFO("Unloading modules");
	loadingMutex.lock();
	for(Module const& i:modules) {
		for(std::string const& func:i.pre_deinit_funcs) {
			void (*deinit_func)(void)=(void(*)())dlsym(i.handle, func.c_str());
			if((void*)deinit_func==nullptr) {
				SPDLOG_WARN("Failed to find the pre-deinit function {} of module [{}] !", func, i.name);
				continue;
			}
			deinit_func();
		}
	}
	Modules::unloadModules();
	loadingMutex.unlock();
}

void Modules::unloadModules() {
	for(int i=modules.size()-1;i>=0;i--) {
		for(std::string const& func_name:modules[i].deinit_funcs) {
			void (*deinit_func)(void)=(void(*)())dlsym(modules[i].handle, func_name.c_str());
			if((void*)deinit_func==nullptr) {
				SPDLOG_WARN("Failed to find the deinit function {} of module [{}] !", func_name, modules[i].name);
				continue;
			}
			deinit_func();
		}
		dlclose(modules[i].handle);
		SPDLOG_INFO("Module [{}] unloaded via dlclose", modules[i].name);
	}
	modules.clear();
	if(should_shutdown) {
		SPDLOG_INFO("Module unloading succeeded, shutdown flag ON");
		SPDLOG_INFO("Quit correctly");
		spdlog::shutdown();
		exit(0);
	}
}

Json::Value Modules::loadModulesDefinition() {
	FILE *modules_definition_sheet_file=fopen("modules.json", "r");
	if(!modules_definition_sheet_file) {
		throw std::runtime_error("Failed to open modules definition file: modules.json");
	}
	fseek(modules_definition_sheet_file, 0, SEEK_END);
	size_t file_size=ftell(modules_definition_sheet_file);
	fseek(modules_definition_sheet_file, 0, SEEK_SET);
	char *modules_def=(char*)malloc(file_size);
	fread(modules_def, 1, file_size, modules_definition_sheet_file);
	fclose(modules_definition_sheet_file);
	std::string modules_def_str(modules_def, file_size);
	// ^ file_size is necessary as we did not put a 0 after that string.
	free(modules_def);
	Json::Value mdl_def;
	std::string mdl_def_parse_error;
	if(!Utils::parseJSON(modules_def_str, &mdl_def, &mdl_def_parse_error)) {
		throw std::runtime_error(fmt::format("Failed to parse modules definition file modules.json: {}", mdl_def_parse_error));
	}
	if(!mdl_def.isArray()) {
		throw std::runtime_error("Modules definition should start w/ an array.");
	}
	return mdl_def;
}

void Modules::loadModules() {
	unloadModules();
	Json::Value mdl_def=loadModulesDefinition();
	for(Json::Value& i:mdl_def) {
		if(!i["name"].isString()) {
			i["name"]=i["path"];
		}
		if(!i["path"].isString()) {
			SPDLOG_CRITICAL("Module {} has no path definition", i["name"].asString());
			abort();
			continue;
		}
		Module cur;
		cur.name=i["name"].asString();
		void *handle=dlopen(i["path"].asString().c_str(), RTLD_NOW|RTLD_GLOBAL);
		if(!handle) {
			SPDLOG_CRITICAL("Failed to load {} module: {}", i["name"].asString(), dlerror());
			abort();
			throw std::runtime_error(fmt::format("Failed to load {} module: {}", i["name"].asString(), dlerror()));
		}
		cur.handle=handle;
		if(i["init_funcs"].isArray()) {
			for(Json::Value const& init_func_name:i["init_funcs"]) {
				if(!init_func_name.isString()) {
					SPDLOG_CRITICAL("Syntax error: init_funcs should contain only string, under module {}.", cur.name);
					abort();
				}
				void (*init_func)()=(void(*)())dlsym(handle, init_func_name.asString().c_str());
				if(!init_func) {
					SPDLOG_WARN("Failed to find init function {} of module {}.", init_func_name.asString(), cur.name);
					continue;
				}
				init_func();
			}
		}
		if(i["pre_deinit_funcs"].isArray()) {
			for(Json::Value const& deinit_func_name:i["pre_deinit_funcs"]) {
				if(!deinit_func_name.isString()) {
					SPDLOG_CRITICAL("Syntax error: pre_deinit_funcs should contain only string, under module {}.", cur.name);
					abort();
				}
				cur.pre_deinit_funcs.push_back(deinit_func_name.asString());
			}
		}
		if(i["deinit_funcs"].isArray()) {
			for(Json::Value const& deinit_func_name:i["deinit_funcs"]) {
				if(!deinit_func_name.isString()) {
					SPDLOG_CRITICAL("Syntax error: deinit_funcs should contain only string, under module {}.", cur.name);
					abort();
				}
				cur.deinit_funcs.push_back(deinit_func_name.asString());
			}
		}
		modules.insert(modules.begin(), cur);
		SPDLOG_INFO("Module [{}] loaded successfully", cur.name);
	}
}
