#include <psp2/net/net.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/sysmodule.h>

#include <kuio.h>
#include <taihen.h>

#include <libk/stdio.h>
#include <libk/stdarg.h>
#include <libk/string.h>


char* rules[][2] = {{"psm-runtime.np.dl.playstation.net", "23.67.253.169"},
		   {"psm-pkg.np.dl.playstation.net", "23.67.253.169"}};

#define LOG_FILE "ux0:/data/psmredir.log"

static tai_hook_ref_t ref_sceNetResolverStartNtoa;
static tai_hook_ref_t ref_load_hook;
static tai_hook_ref_t ref_unload_hook;
static SceUID g_hook;
static SceUID g_load;
static SceUID g_unload;



// void kuLOG(char* format, ...){
// 	char str[512] = { 0 };
// 	va_list va;

// 	va_start(va, format);
// 	vsnprintf(str, 512, format, va);
// 	va_end(va);
	
// 	SceUID fd;
// 	kuIoOpen(LOG_FILE, SCE_O_WRONLY | SCE_O_APPEND | SCE_O_CREAT, &fd);
// 	kuIoWrite(fd, str, strlen(str));
// 	kuIoWrite(fd, "\n", 1);
// 	kuIoClose(fd);
// }

void LOG(char* format, ...){
	char str[512] = { 0 };
	va_list va;

	va_start(va, format);
	vsnprintf(str, 512, format, va);
	va_end(va);
	
	SceUID fd;
	fd = sceIoOpen(LOG_FILE, SCE_O_WRONLY | SCE_O_APPEND | SCE_O_CREAT, 0777);
	sceIoWrite(fd, str, strlen(str));
	sceIoWrite(fd, "\n", 1);
	sceIoClose(fd);
}

int find_dns_rule(const char *hostname) {
	int nEntries = sizeof(rules)/sizeof(rules[0]);
	for (int i=0; i<nEntries; i++) {
		if (strstr(hostname, rules[i][0]) != NULL)
			return i;
	}
	return -1;
}

int hook_sceNetResolverStartNtoa(int rid, const char *hostname, SceNetInAddr *addr, int timeout, int retry, int flags) {
	LOG("--> sceNetResolverStartNtoa()");

	int result = TAI_CONTINUE(int, ref_sceNetResolverStartNtoa, rid, hostname, addr, timeout, retry, flags);
	if(addr != NULL && hostname != NULL) {
		int rule = find_dns_rule(hostname);
		if (rule >= 0) {
			int res = sceNetInetPton(SCE_NET_AF_INET, rules[1][rule], &(addr->s_addr));
			if (res == 0) {
				LOG("<-- sceNetResolverStartNtoa()");
				return 0;
			}
		}
	}
	LOG("<-- sceNetResolverStartNtoa()");
	return result;
}

// SceNet is loaded on demand
// Need to hook it when it's loaded
int hook_sysmodule_load(uint16_t id) {
	int ret;
	ret = TAI_CONTINUE(int, ref_load_hook, id);
	if (ret < 0) return ret;

	switch (id) {
	case SCE_SYSMODULE_HTTP:
		if (g_hook == -1) {
			g_hook = taiHookFunctionExport(&ref_sceNetResolverStartNtoa, "SceNet", TAI_ANY_LIBRARY /*0x6BF8B2A2*/, 0x424AE26, hook_sceNetResolverStartNtoa); 
			LOG("hook module_resolverNtoa: 0x%08X", g_hook);
		}    
		break;
	default:
		break;
	}

	return ret;
}

int hook_sysmodule_unload(uint16_t id) {
	int ret;
	ret = TAI_CONTINUE(int, ref_unload_hook, id);
	if (ret < 0) return ret;

	switch (id) {
	case SCE_SYSMODULE_HTTP:
		if (g_hook >= 0) {
			taiHookRelease(g_hook, ref_sceNetResolverStartNtoa);
			LOG("unhook module_resolverNtoa");
			g_hook = -1;
		}
		break;
	default:
		break;
	}
	return ret;
}

int hooks_setup() {
	LOG("--> module_start()");
	g_load = taiHookFunctionExport(&ref_load_hook, "SceNet", 0x03FCF19D, 0x79A0160A, hook_sysmodule_load);
	LOG("hook module_load: 0x%08X", g_load);
	g_unload = taiHookFunctionExport(&ref_unload_hook, "SceNet", 0x03FCF19D, 0x31D87805, hook_sysmodule_unload);
	LOG("hook module_unload: 0x%08X", g_unload);
	LOG("<-- module_start()");
	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start() {
	g_hook = -1;
	SceUID thid;
	thid = sceKernelCreateThread("psmredir", hooks_setup, 0x10000100, 0x10000, 0, 0, NULL);
	sceKernelStartThread(thid, 0, NULL);
	return 0;
}

int module_stop() {
	if (g_hook >= 0) taiHookRelease(g_hook, ref_sceNetResolverStartNtoa);
	if (g_load >= 0) taiHookRelease(g_load, ref_load_hook);
	if (g_unload >= 0) taiHookRelease(g_unload, ref_unload_hook);
	return 0;
}
