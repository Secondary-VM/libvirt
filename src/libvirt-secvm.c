#include <sys/socket.h>
#include <sys/mount.h>
#include <linux/vm_sockets.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <config.h>
#include <stdio.h>
#include <math.h>
#include <mntent.h>
#include <libgen.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "internal.h"
#include "vircommand.h"
#include "libvirt-secvm.h"
#include "domain_conf.h"
#include "domain_addr.h"
#include "virxml.h"
#include "virfile.h"
#include "virutil.h"

VIR_LOG_INIT("secvm");

#define BSIZE 128
#define virCgrMntPt	"/var/lib/libvirt/cgroup"
#define virPrimaryNS	"/var/lib/libvirt/images"

/** CGROUP */
static bool isCgrpMounted(void)
{
	bool mounted = false;
	struct mntent *ent;
	FILE *mounts = setmntent("/etc/mtab", "r");
	while ((ent = getmntent(mounts)) != NULL ){
		if (strcmp(ent->mnt_dir, virCgrMntPt) == 0) {
			mounted = true;
			break;
		}
	}
	endmntent(mounts);
	return mounted;
}

static int cgrpMount(void)
{
	int mntFlags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
	int ret = 0;

	VIR_INFO("Mounting...\n");
	mkdir(virCgrMntPt, S_IRWXU);
	if (!isCgrpMounted()) {
		ret = mount("cgroup2", virCgrMntPt, "cgroup2", mntFlags, NULL);
		if (ret) {
			VIR_ERROR("%s\n", strerror(errno));
			return -1;
		}
		VIR_INFO("Mounted...\n");
	} else {
		VIR_INFO("Is already mounted...\n");
	}

	return ret;
}

/* TODO set limits in virSystemdCreateMachine/virDomainCgroupInitCgroup instead of here!
 * 	This should only used to move the daemonPID in the priVM group
 */
int cgrpSetup(const char *parentName, const int parentId, pid_t pid)
{
	char buf[BSIZE];
	int ret;
	FILE *VirCgrpFile;

	ret = cgrpMount();
	if (ret)
		return ret;

	/* Move */
	snprintf(buf, BSIZE, "%s/machine.slice/machine-qemu\\x2d%d\\x2d%s.scope/libvirt/cgroup.procs",
			virCgrMntPt, parentId, parentName);
	VirCgrpFile = fopen(buf, "a");
	if (VirCgrpFile == NULL) {
		VIR_ERROR("NO FILE");
		return -1;
	}
	snprintf(buf, BSIZE, "%d", pid);
	fputs(buf, VirCgrpFile);
	fclose(VirCgrpFile);

#if 0
	/* Mem limit */
	/* XXX Unnecessary, we unplug memory from primaryVM */
	snprintf(buf, BSIZE, "%s/machine.slice/machine-qemu\\x2d%d\\x2d%s.scope/memory.max",
			virCgrMntPt, parentId, parentName);
	VirCgrpFile = fopen(buf, "a");
	if (VirCgrpFile == NULL)
		return -1;
	snprintf(buf, BSIZE, "%luK", virDomainGetMaxMemory(dom));
	fputs(buf, VirCgrpFile);
	fclose(VirCgrpFile);
#endif

	/* Cpuset limit */
	snprintf(buf, BSIZE, "%s/machine.slice/machine-qemu\\x2d%d\\x2d%s.scope/cpuset.cpus",
			virCgrMntPt, parentId, parentName);
	VirCgrpFile = fopen(buf, "a");
	if (VirCgrpFile == NULL)
		return -1;

	/* TODO Hardcoded mess: get cpus from virDomainGetVcpus */
	snprintf(buf, BSIZE, "4,5,6,7");
	fputs(buf, VirCgrpFile);
	fclose(VirCgrpFile);

	/* TODO CPUSET Root/isolated partition */

	return 0;
}


/** DISK carveout */
static inline int detachSecDisk(virDomainPtr dom) /* TODO copy cmdDetachDisk */
{
	char buf[BSIZE];

	snprintf(buf, BSIZE,
		 "%s detach-disk --domain %d --target vdb",
		 virshPath, virDomainGetID(dom));
	return system(buf);
}

static inline int attachSecDisk(virDomainPtr dom) /* TODO copy cmdAttachDisk */
{
	char buf[BSIZE];

	snprintf(buf, BSIZE,
		 "%s attach-disk --domain %d --source %s/%d/sib.ext4 --target vdb",
		 virshPath, virDomainGetID(dom), virPrimaryNS, dom->id);
	return system(buf);
}

static inline int updateRamSize(virDomainPtr dom, int size, bool add)
{
	char buf[BSIZE];
	//int oldsize = virDomainGetMaxMemory(dom);
	int oldsize = 8388608;

	int newsize = add ? oldsize + size :
		oldsize - size;

	/* VIR_DOMAIN_AFFECT_CURRENT is default, no need to change it */

	VIR_INFO("UNPLUGGING memory from priVM, %d %d %d", size, oldsize, newsize);
	if (newsize <= 0)
		return -1;

	snprintf(buf, BSIZE,
		 "%s setmem %d %dKiB --current",
		 virshPath, virDomainGetID(dom), newsize);
	VIR_INFO("%s", buf);

	return system(buf);

	//TODO should use virDomainSetMemory(dom, newsize);
}


static int getImage(struct secVM *vm, char *buf, const char *type)
{
	int ret;
	char cmd[512];
	struct stat sb;
	size_t imgsize;

	ret = detachSecDisk(vm->parent);

	/* Mount disk */
	sprintf(cmd, "mount -t ext4 %s/%d/sib.ext4 %s/%d/mnt",
			virPrimaryNS, vm->parent->id, virPrimaryNS, vm->parent->id);

	VIR_INFO("%s", cmd);
	ret = system(cmd);

	/* Get file */
	sprintf(cmd, "mv %s/%d/mnt/%s %s/%d/%d/image.%s",
		virPrimaryNS, vm->parent->id, basename(vm->image), virPrimaryNS, vm->parent->id, vm->id, type);
	ret = system(cmd);


	/* secVM host path is the return value (in buf) */
	sprintf(buf, "%s/%d/%d/image.qcow2", virPrimaryNS, vm->parent->id, vm->id);

	/* Calculate new size of disk */
	sprintf(cmd, "%s/%d/sib.ext4", virPrimaryNS, vm->parent->id);
	stat(cmd, &sb);
	imgsize = sb.st_size;

	stat(buf, &sb);
	imgsize -= sb.st_size;

	/* Unmount */
	sprintf(cmd, "%s/%d/mnt", virPrimaryNS, vm->parent->id);
	umount(cmd);

	/* resize disk */
	sprintf(cmd, "e2fsck -f %s/%d/sib.ext4", virPrimaryNS, vm->parent->id);
	ret = system(cmd);
	sprintf(cmd, "resize2fs %s/%d/sib.ext4 %luK", virPrimaryNS, vm->parent->id, imgsize / 1024);
	ret = system(cmd);

	ret = attachSecDisk(vm->parent);

	return ret;
}

static int releaseImage(struct secVM *vm, const char *type)
{
	int ret;
	char cmd[BSIZE];
	struct stat sb;
	size_t imgsize;

	ret = detachSecDisk(vm->parent);

	/* Calculate new size of disk */
	sprintf(cmd, "%s/%d/sib.ext4", virPrimaryNS, vm->parent->id);
	stat(cmd, &sb);
	imgsize = sb.st_size;

	sprintf(cmd, "%s/%d/%d/image", virPrimaryNS, vm->parent->id, vm->id);
	stat(cmd, &sb);
	imgsize += sb.st_size;

	/* resize disk */
	sprintf(cmd, "e2fsck -f %s/%d/sib.ext4", virPrimaryNS, vm->parent->id);
	ret = system(cmd);
	sprintf(cmd, "resize2fs %s/%d/sib.ext4 %luK", virPrimaryNS, vm->parent->id, imgsize / 1024);
	ret = system(cmd);

	/* Mount disk */
	sprintf(cmd, "mount -t ext4 %s/%d/sib.ext4 %s/%d/mnt",
		virPrimaryNS, vm->parent->id, virPrimaryNS, vm->parent->id);
	ret = system(cmd);

	/* Copy file */
	sprintf(cmd, "mv %s/%d/%d/image.%s %s/%d/mnt/%s",
		virPrimaryNS, vm->parent->id, vm->id, type, virPrimaryNS, vm->parent->id, basename(vm->image));
	ret = system(cmd);

	/* Unmount */
	sprintf(cmd, "%s/%d/mnt", virPrimaryNS, vm->parent->id);
	umount2(cmd, MNT_FORCE);

	/* Remove virPrimaryNS for secVM */
	sprintf(cmd, "%s/%d/%d", virPrimaryNS, vm->parent->id, vm->id);
	ret = rmdir(cmd);

	ret = attachSecDisk(vm->parent);

	return ret;
}


/* buf holds the return value */
static inline void get_secondary_vmid(char* buf, struct secVM* secVM) // TODO
{
	sprintf(buf, "%d", secVM->id);
}

/* buf holds the return value */
static inline void get_secondary_vmmemory(char* buf, int sec_mem)
{
	sec_mem *= 976562; // convert from GB to kib
	sprintf(buf, "%d", sec_mem);
}

static inline int check_available_vcpus(int sec_vcpus) // TODO
{
	int status = !!sec_vcpus;
	return status;
}

/* buf holds the return value */
static inline void get_secondary_vmvcpus(char *buf, int sec_vcpus, int encryption)
{
	if (encryption && !check_available_vcpus(sec_vcpus))
		return;

	sprintf(buf, "%d", sec_vcpus);
}

static int virSecvmSpawn(virDomainPtr primaryDomain,
		int sec_vcpus, int sec_mem, bool encryption, const char* disk_type,
		struct secVM *vm)
{
	int ret;
	int priID = virDomainGetID(primaryDomain);
	int secID = vm->id;
	char buf[BSIZE];
	char spawn_cmd[256] = "", param_values[5][256];

	/* TODO Hardcoded should get parent id in secondary VM xml template */
	char xml_params[5][20] = {"VMNAME", "SECMEM", "SECVCPUS", "DISKTYPE", "DISKNAME"};
	//virDomainPtr secondaryDomain = NULL;
	g_autofree char *buffer = NULL;
	VIR_INFO("Starting SecVM\n");


	// TODO: get secondaryVM ID
	get_secondary_vmmemory(param_values[1], sec_mem);
	get_secondary_vmvcpus(param_values[2], sec_vcpus, encryption);
	strcpy(param_values[3], disk_type);
	strcpy(param_values[4], vm->image);
	snprintf(buf, BSIZE, "/var/lib/libvirt/images/%d/%d", priID, secID);
	umask(0);
	mkdir(buf, 0755);

	snprintf(buf, BSIZE, "cp /var/lib/libvirt/secVmTemplate.xml /var/lib/libvirt/images/%d/%d/desc.xml",
			priID, secID);
	ret = system(buf);
	if (ret)
		VIR_ERROR("Couldn't copy xml template");

	if (getImage(vm, param_values[4], param_values[3]))
		VIR_ERROR("Couldn't get image\n");

	for (int i = 0; i < sizeof(xml_params)/sizeof(xml_params[0]); i++) {
		strcpy(spawn_cmd, "sed -i \'s#");
		strcat(spawn_cmd, xml_params[i]);
		strcat(spawn_cmd, "#");
		strcat(spawn_cmd, param_values[i]);
		snprintf(buf, BSIZE, "#g\' /var/lib/libvirt/images/%d/%d/desc.xml", priID, secID);
		strcat(spawn_cmd, buf);
		ret = system(spawn_cmd);
		if (ret)
			VIR_ERROR("Parsing error");
	}
	if (encryption) {
		char encparam_values[2][256] = {
			"<memoryBacking> \\n    <locked/> \\n  </memoryBacking>",
			"<launchSecurity type=\'\"\'\"\'sev\'\"\'\"\'> \\n    <cbitpos>47</cbitpos> \\n    <reducedPhysBits>1</reducedPhysBits> \\n    <policy>0x0000</policy> \\n  </launchSecurity>"
		};
		char xml_encparams[2][20] = {"<!--MEMLOCK-->", "<!--ENCRYPT-->"};
		for (int i = 0; i < sizeof(xml_encparams)/sizeof(xml_encparams[0]); i++) {
			strcpy(spawn_cmd, "sed -i \'s#");
			strcat(spawn_cmd, xml_encparams[i]);
			strcat(spawn_cmd, "#");
			strcat(spawn_cmd, encparam_values[i]);
			snprintf(buf, BSIZE, "#g\' /var/lib/libvirt/images/%d/%d/desc.xml", priID, secID);
			strcat(spawn_cmd, buf);
			ret = system(spawn_cmd);
			if (ret)
				VIR_ERROR("Encryption parsing error");
		}
	}

	//	snprintf(buf, BSIZE, "/var/lib/libvirt/images/%d/%d/desc.xml", priID, secID);
//	if (virFileReadAll(buf, (12*1024*1024), &buffer) < 0)
//		VIR_ERROR("Couldn't read XML template\n");
//
//	secondaryDomain = virDomainCreateXML(primaryDomain->conn, buffer, 0);
//	snprintf(buf, 16, "%d", primaryDomain->id);
//	if (secondaryDomain)
//		virDomainSetMetadata(secondaryDomain, VIR_DOMAIN_METADATA_HIERARCHY, "secondary",
//				buf, NULL, 0);

	/* unplug memory from priVM */
	ret = updateRamSize(primaryDomain, sec_mem * 976562, false);
	if (ret)
		VIR_ERROR("Could not carve out memory"); /*TODO Cleanup */

	/* TODO: use virDomainCreateXML only works outside of the daemon for some reasons... */

	snprintf(buf, BSIZE, "%s create /var/lib/libvirt/images/%d/%d/desc.xml",
		 virshPath, priID, secID);
	ret = system(buf);
	if (ret)
		VIR_ERROR("Couldn't spawn secVM"); /*TODO Cleanup */

	return ret;
}

/* TODO */
static int virSecvmDestroy(struct secVM *vm)
{
	VIR_INFO("Destroying secVM %d\n", vm->id);
	/*
	 * Unplug secVM drive from primaryVM
	 *
	 * cmdDetachDisk()
	 *
	 * Inflate secVM drive
	 * Move secVM image on drive
	 * Replug secVM image on primaryVM
	 *
	 * cmdAttachDisk()
	 *
	 * Replug memory into primaryVM
	 *
	 * cmdattatchDevice()
	 *
	 *
	 * Destroy secVM
	 */
	if(releaseImage(vm, "qcow2"))
		VIR_ERROR("Couldn't reattach disk to host");
	virDomainDestroy(vm->domain);
	return 0;
}

void virSecvmVsockOpen(virDomainPtr primaryDomain)
{
	int ret;
	int id = virDomainGetID(primaryDomain);
	char pid[16];
	pid_t daemonPID = 0;
	g_autofree char *buffer = NULL;

	daemonPID = virFork();
	if(daemonPID == 0) {
		struct sockaddr_vm addr;
		struct sockaddr_vm peer_addr;
		socklen_t peer_addr_size = sizeof(struct sockaddr_vm);
		int s = socket(AF_VSOCK, SOCK_STREAM, 0);
		char buf[BSIZE];
		size_t msg_len;
		int peer_fd;
		struct secVM *secVMs[VIRT_SECVM_MAXNO] = {NULL};

		snprintf(buf, BSIZE, "%s/%d", virPrimaryNS, id);
		umask(0);
		mkdir(buf, 0755);
		sprintf(buf, "%s/%d/mnt", virPrimaryNS, id);
		ret = mkdir(buf, 0755);

		/* TODO have dynamic size parsed from XML */
		/* TODO Use cmdVolCreate */
		//snprintf(buf, BSIZE, "truncate -s 50G %s/%d/sib.ext4", virPrimaryNS, id);
		//ret = system(buf);
		snprintf(buf, BSIZE, "mkfs.ext4 %s/%d/sib.ext4", virPrimaryNS, id);
		ret = system(buf);

		attachSecDisk(primaryDomain);

		memset(&addr, 0, sizeof(struct sockaddr_vm));
		addr.svm_family = AF_VSOCK;
		addr.svm_port = 42424;
		addr.svm_cid = VMADDR_CID_HOST;

		bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_vm));
		listen(s, 0);

		//TODO CID is temporary
		peer_addr.svm_cid = 3;
		//peer_addr.svm_cid = VIRT_PRIMARYVM_CID_BASE + id;
		while(true) {
			VIR_INFO("Secondary VM Daemon listening...");
			peer_fd = accept(s, (struct sockaddr *)&peer_addr, &peer_addr_size);

			while ((msg_len = recv(peer_fd, &buf, 64, 0)) > 0) {
				char* uarg;
				char operation[64];
				//1 sec_vmid; 2 sec_vcpus; 3 sec_mem; 4 sec_disk; 5 disk type; 6 encryption;
				int input_flag = 0;

				int vcpus = 1;
				int mem = 1;
				int sec_id = -1;
				char disk[64];
				char dtype[8];
				bool encryption = false;

				buf[msg_len] = '\0';
				VIR_INFO("Received %lu bytes: %s\n", msg_len, buf);
				uarg = strtok (buf," ");

				while (uarg != NULL) { // parse arguments from the user input
					if (!strcmp(uarg, "-i")) {
						input_flag = 1;
					} else if (!strcmp(uarg, "-c")) {
						input_flag = 2;
					} else if (!strcmp(uarg, "-m")) {
						input_flag = 3;
					} else if (!strcmp(uarg, "-d")) {
						input_flag = 4;
					} else if (!strcmp(uarg, "-t")) {
						input_flag = 5;
					} else if (!strcmp(uarg, "-e")) {
						input_flag = 6;
					} else if (!strcmp(uarg, "create") ||
							!strcmp(uarg, "destroy") ||
							!strcmp(uarg, "list")) {
						strcpy(operation, uarg);
						input_flag = 0;
					} else if (input_flag == 1) {
						sec_id = atoi(uarg);
					} else if (input_flag == 2) {
						vcpus = atoi(uarg);
					} else if (input_flag == 3) {
						mem = atoi(uarg);
					} else if (input_flag == 4) {
						strcpy(disk, uarg);
					} else if (input_flag == 5) {
						strcpy(dtype, uarg);
					} else if (input_flag == 6) {
						encryption = atoi(uarg);
					}
					uarg = strtok (NULL, " ");
				}
				memset(&buf, 0, sizeof(buf));

				if (!strcmp(operation, "create")) {
					int i;
					struct secVM *vm;

					for (i = 0; i < VIRT_SECVM_MAXNO; i++)
						if (secVMs[i] == NULL)
							break;

					if (i >= VIRT_SECVM_MAXNO)
						VIR_ERROR("No more space for secVMs available");

					vm = malloc(sizeof(struct secVM));
					vm->id = i;
					vm->parent = primaryDomain;
					strcpy(vm->image, disk);
					secVMs[i] = vm;

					VIR_INFO("%d %d %d %s", vcpus, mem, encryption, vm->image);
					virSecvmSpawn(primaryDomain,
							vcpus, mem, encryption, dtype, vm);

					/* TODO Check if successful */
					send(peer_fd, "create", 6, 0);

				}
				if (!strcmp(operation, "destroy")) {
					struct secVM *vm = secVMs[sec_id];
					VIR_INFO("destroy VM %d", sec_id);
					ret = virSecvmDestroy(vm);

					if (ret)
						VIR_ERROR("Couldn't destroy secVM");

					send(peer_fd, "destroy", 7, 0);
					free(vm);
					secVMs[sec_id] = NULL;
				}
			}
			sleep(1);

		}
	} else if (daemonPID < 0) {
		VIR_ERROR("SecVM daemon for %d not created due to PID %d error", id, daemonPID);
		return;
	}
	snprintf(pid, 16, "%d", daemonPID);

	/* XXX Better for the daemon to move itself in the cgroup to avoid race condition */
	ret = cgrpSetup(primaryDomain->name, primaryDomain->id, daemonPID);
	if (ret) {
		VIR_ERROR("Couldn't move daemon into Cgroup");
		VIR_ERROR("Booting VM as Standard VM");
		virSecvmVsockClose(primaryDomain);
		virDomainSetMetadata(primaryDomain, VIR_DOMAIN_METADATA_HIERARCHY, "standard",
				NULL, NULL, 0);
		return;
	}

	/* --- */
	VIR_INFO("Started secVM listener for primary VM %d with PID %d\n", id, daemonPID);
}

void virSecvmVsockClose(virDomainPtr dom)
{
	/* TODO, kill daemon, kill secVMs */
	char buf[BSIZE];
	int ret;

	ret = detachSecDisk(dom);
	if (ret)
		VIR_ERROR("Could not detach and remove disk");

	snprintf(buf, BSIZE, "%s/%d", virPrimaryNS, virDomainGetID(dom));
	remove(buf);
}
