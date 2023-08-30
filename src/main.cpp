#ifdef HAVE_CONFIG_H
#include <config.h>
#else
// Assume defines when unconfigured
#define HAVE_DLADDR1
#define HAVE_UNISTD_H
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <pthread.h>
#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>
#include <execinfo.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <signal.h>
#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/daily_file_sink.h"
#include "modules.h"

#ifdef __APPLE__
typedef sig_t sighandler_t;
#endif

mongocxx::instance mongodb_instance;
mongocxx::pool mongodb_pool{mongocxx::uri{"mongodb://127.0.0.1:27017"}};

//bool rescue_mode=false;
//std::string rescue_mode_cause;
//std::string rescue_mode_stack_dump;

std::mutex stackTraceMutex;
void stackTrace(int signal) {
	stackTraceMutex.lock();
	SPDLOG_CRITICAL("Program fatal error, showing stack trace");
	if(signal==11) {
		SPDLOG_CRITICAL("SIGSEGV");
	}else if(signal==13){
		SPDLOG_CRITICAL("SIGPIPE");
	}else{
		SPDLOG_CRITICAL("SIGABRT");
	}
	void *addrlist[64];
	int addrlen=backtrace(addrlist, 64);
	if(!addrlen) {
		SPDLOG_CRITICAL("SHOOT, STACK IS RUINED!");
		printf("STACK IS RUINED\n");
		exit(10);
	}
	std::string final_cause;
	Dl_info c_dl_info;
	for(int i=0;i<addrlen;i++) {
		void *dl_handle;
#ifdef HAVE_DLADDR1
		if(dladdr1(addrlist[i], &c_dl_info, &dl_handle, RTLD_DL_LINKMAP)==0)
#else
		if(dladdr(addrlist[i], &c_dl_info)==0)
#endif
		{
			SPDLOG_CRITICAL("#{}: [{:#x}:dladdr() failed]\n", i, (uint64_t)addrlist[i]);
			continue;
		}

		if(!c_dl_info.dli_sname) {
			c_dl_info.dli_sname="0";
		}
		if(!c_dl_info.dli_fname) {
			c_dl_info.dli_fname="???";
		}
		int demangling_status;
		char *symbol_name=abi::__cxa_demangle(c_dl_info.dli_sname, 0, 0, &demangling_status);
		if(demangling_status!=0) {
			symbol_name=(char *)c_dl_info.dli_sname;
		}
#ifdef HAVE_DLADDR1
		std::string module_name=Modules::getModuleFromHandle(dl_handle);
#else
		std::string module_name="";
#endif
		if(module_name.length()!=0) {
			SPDLOG_CRITICAL("#{}: {}+{:#x} ([{}]:{}+{:#x})\n", i, symbol_name, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_saddr, module_name, c_dl_info.dli_fname, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_fbase);
		}else{
			SPDLOG_CRITICAL("#{}: {}+{:#x} ({}+{:#x})\n", i, symbol_name, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_saddr, c_dl_info.dli_fname, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_fbase);
		}
		if(final_cause.length()==0&&module_name.length()) {
			final_cause=module_name;
		}
		if(demangling_status==0)
			free(symbol_name);
	}
	if(final_cause.length()) {
		SPDLOG_WARN("Final cause might be: [{}]", final_cause);
		/*SPDLOG_WARN("Module-liked cause, entering rescue mode");
		rescue_mode_stack_dump=stack_dump_str;
		rescue_mode_cause=final_cause;
		rescue_mode=true;
		Modules::doImmediateUnload();
		SPDLOG_INFO("Program is now in rescue mode!");
		SPDLOG_WARN("Exiting thread, this may cause a memory leak");
		::signal(SIGINT, SIG_DFL);
		::signal(61, SIG_IGN);
		pthread_exit(nullptr);*/
	}
	spdlog::flush_on(spdlog::level::critical);
	_exit(10);
}

void register_general_sighandlers() {
	signal(SIGSEGV, (sighandler_t)stackTrace);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGABRT, (sighandler_t)stackTrace);
	signal(61, (sighandler_t)pthread_exit);
}

int main() {
	spdlog::flush_on(spdlog::level::trace);
	auto logger=spdlog::daily_logger_mt<spdlog::async_factory>("main", "logs/pv4.log", 0, 0);
	logger->sinks().push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	spdlog::set_default_logger(logger);
	//spdlog::enable_backtrace(16);
	spdlog::set_pattern("[%C%m%d %H:%M:%S:%e] [%^%l%$] %v << %!");
	spdlog::set_level(spdlog::level::info);
	SPDLOG_INFO("pv4: FBAuthenicator Started Up");
	register_general_sighandlers();
	SPDLOG_DEBUG("signal handlers registered");
	Modules::loadModules();
	while(1) {
		sleep(3600);
	}
	//pthread_exit(0);
	return 0;
}
