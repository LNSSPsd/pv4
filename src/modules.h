#pragma once
#include "action.h"

namespace Modules {
	std::string getModuleFromHandle(void *handle);
	void doImmediateUnload();
	void unloadModules();
	void switchSuppressLoading(std::string const& name);
	Json::Value loadModulesDefinition();
	void loadModules();
	void scheduleReload();
	void scheduleTeardown();
};