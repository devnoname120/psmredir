#include <taihen.h>
#include <psp2/net/net.h>

const char *sceClibStrstr(const char *str1, const char *str2);

static tai_hook_ref_t ref_sceNetResolverStartNtoa;

char* rules[][2] = {{"psm-runtime.np.dl.playstation.net", "23.67.253.169"},
		   {"psm-pkg.np.dl.playstation.net", "23.67.253.169"}};

int find_dns_rule(const char *hostname) {
	int nEntries = sizeof(rules)/sizeof(rules[0]);
	for (int i=0; i<nEntries; i++) {
		if (sceClibStrstr(hostname, rules[i][0]) != NULL)
			return i;
	}
	return -1;
}

int hook_sceNetResolverStartNtoa(int rid, const char *hostname, SceNetInAddr *addr, int timeout, int retry, int flags) {
	int result = TAI_CONTINUE(int, ref_sceNetResolverStartNtoa, rid, hostname, addr, timeout, retry, flags);
	if(addr != NULL && hostname != NULL) {
		int rule = find_dns_rule(hostname);
		if (rule >= 0) {
			int res = sceNetInetPton(SCE_NET_AF_INET, rules[1][rule], &(addr->s_addr));
			if (res == 0) {
				return 0;
			}
		}
	}
	return result;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start() {
	taiHookFunctionExport(&ref_sceNetResolverStartNtoa, "SceNet", TAI_ANY_LIBRARY, 0xD5EEB048, hook_sceNetResolverStartNtoa);
	return 0;
}

int module_stop() {
	return 0;
}