#include <taihen.h>
#include <psp2/net/net.h>
#include <kuio.h>
#include <psp2/io/fcntl.h>
#include <libk/stdio.h>
#include <libk/stdarg.h>
#include <libk/string.h>


char* rules[][2] = {{"psm-runtime.np.dl.playstation.net", "23.67.253.169"},
		   {"psm-pkg.np.dl.playstation.net", "23.67.253.169"}};

#define LOG_FILE "ux0:/data/psmredir.log"

static tai_hook_ref_t ref_sceNetResolverStartNtoa;
static SceUID g_hook;

void LOG(char* format, ...){
	char str[512] = { 0 };
	va_list va;

	va_start(va, format);
	vsnprintf(str, 512, format, va);
	va_end(va);
	
	SceUID fd;
	kuIoOpen(LOG_FILE, SCE_O_WRONLY | SCE_O_APPEND | SCE_O_CREAT, &fd);
	kuIoWrite(fd, str, strlen(str));
	kuIoWrite(fd, "\n", 1);
	kuIoClose(fd);
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

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start() {
	LOG("--> module_start()");
	g_hook = taiHookFunctionImport(&ref_sceNetResolverStartNtoa, TAI_MAIN_MODULE/*"SceNet*/, 0x6BF8B2A2, 0x424AE26, hook_sceNetResolverStartNtoa);
	LOG("hook sceNetResolverStartNtoa: 0x%08X", g_hook);
	LOG("<-- module_start()");
	return 0;
}

int module_stop() {
	if (g_hook >= 0) taiHookRelease(g_hook, ref_sceNetResolverStartNtoa);
	return 0;
}
