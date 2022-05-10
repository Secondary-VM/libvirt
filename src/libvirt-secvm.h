#include "virlog.h"
#include "datatypes.h"

#define VIRT_PRIMARYVM_CID_BASE	3
#define VIRT_SECVM_MAXNO	16
#define virshPath		"/home/ang/usr/bin/virsh" /* XXX Temp */

void virSecvmVsockOpen(virDomainPtr primaryDomain);
void virSecvmVsockClose(virDomainPtr dom);
int cgrpSetup(const char *primaryName, const int primaryId, pid_t pid);


struct secVM {
	int id;
	virDomainPtr parent;
	virDomainPtr domain;
	char image[64];
};
