#include <jni.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>
#include <linux/limits.h>
#include <dlfcn.h>
#include <dirent.h>

#include "debug.h"

#define TIME_USING_CLOCK

typedef EGLBoolean (*EglSwapBuffers)(EGLDisplay dpy, EGLSurface surf);

//EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = -1;
EglSwapBuffers old_eglSwapBuffers = NULL;

int ct = 0;

#ifdef TIME_USING_CLOCK
clock_t sck = 0;
#else
long long startTime;
long long current_timestamp() {
	struct timeval te;
	gettimeofday(&te, NULL); // get current time
	long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;// caculate milliseconds
	// printf("milliseconds: %lld\n", milliseconds);
	return milliseconds;
}
#endif

char* fpsPath;
//FILE *fp;

void savaFps(int fps) {

//	if (fp == NULL) {
//		fp = fopen(fpsPath, "wb");
//	}
	FILE *fp = fopen(fpsPath, "wb");
	if (fp != NULL) {
//		LOGD("[+] file point : %p ,fps: %d \n", fp, fps);
		int size = fwrite(&fps, sizeof(fps), 1, fp);
		if (size <= 0) {
			LOGD("[+] write fps faild : error = %d (%s) \n", errno,
					strerror(errno));
		}
//		LOGD(">open fps file is ok : %s, error = %d \n", fpsPath, errno);
		fclose(fp);
	} else {
		LOGD("[+] open fps file faild : %s, error = %d (%s)\n", fpsPath, errno,
				strerror(errno));
	}
}

//void closeFp() {
//	if (fp != NULL) {
//		fclose(fp);
//		fp = NULL;
//	}
//}

EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface) {
//	LOGD("[+] New eglSwapBuffers\n");

#ifdef TIME_USING_CLOCK
	clock_t ck = clock();
	clock_t time = ck - sck;
	if (time > CLOCKS_PER_SEC) {
		sck = ck;
		int fps = ct * CLOCKS_PER_SEC / time;
		LOGD("[+]>FPS : %d\n", fps);
		savaFps(fps);
		ct = 0;
	}
#else
	long long curtime = current_timestamp();
	long long ltime = curtime - startTime;
	if (ltime > 1000) {
		startTime = curtime;
		int fps = ct * 1000 / ltime;
		LOGD("[+]>FPS : %d\n", fps);
		savaFps(fps);
		ct = 0;
	}
#endif

	ct++;

	if (old_eglSwapBuffers == (EglSwapBuffers) -1) {
		LOGD("[+] error\n");
	}

	return old_eglSwapBuffers(dpy, surface);
}

void* get_module_base(pid_t pid, const char* module_name) {
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);

				if (addr == 0x8000)
					addr = 0;

				break;
			}
		}

		fclose(fp);
	}

	return (void *) addr;
}

int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0) {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

char* findStartStringFile(const char *path, const char *startName)
{
	char* findPath = NULL;
	DIR* dir = opendir(path);
	if (dir == NULL) {
		return NULL;
	}

	struct dirent * entry;
	int pathLen = strlen(path);
	while((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, startName, strlen(startName)) == 0) {
			findPath = entry->d_name;
			break;
		}
	}

	closedir(dir);
	return findPath;
}

int findStartStringFilePath(const char *path, const char *startName, char* out) {
	char findPath[256];
	memset(findPath, 0, sizeof(findPath));

	char* file = findStartStringFile(path, "hwcomposer.");
	if (file != NULL) {
		strcpy(findPath, path);
		findPath[strlen(path)] = '/';
		strcat(findPath, file);
		LOGD("[+] find hwcomposer so : %s\n", findPath);
	} else {
		LOGD("[+] Not fond hwcomposer so\n");
	}

	strcpy(out, findPath);
	int len = strlen(findPath);
	out[len] = '\0';
	return len;
}

int replaceGotSymbolAddr(char* libFile, uint32_t symbolAddr, uint32_t replaceAddr) {
	void * base_addr = get_module_base(getpid(), libFile);
	LOGD("[+] get_module_base address %s = %p\n", libFile, base_addr);

	int fd = open(libFile, O_RDONLY);
	if (-1 == fd) {
		LOGD("[+] open %s faild ! \n", libFile);
		return -1;
	}

	Elf32_Ehdr ehdr;
	read(fd, &ehdr, sizeof(Elf32_Ehdr));

	unsigned long shdr_addr = ehdr.e_shoff;
	int shnum = ehdr.e_shnum;
	int shent_size = ehdr.e_shentsize;
	unsigned long stridx = ehdr.e_shstrndx;

	Elf32_Shdr shdr;
	lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
	read(fd, &shdr, shent_size);

	char * string_table = (char *) malloc(shdr.sh_size);
	lseek(fd, shdr.sh_offset, SEEK_SET);
	read(fd, string_table, shdr.sh_size);
	lseek(fd, shdr_addr, SEEK_SET);

	int i;
	uint32_t out_addr = 0;
	uint32_t out_size = 0;
	uint32_t got_item = 0;
	int32_t got_found = 0;

	for (i = 0; i < shnum; i++) {
		read(fd, &shdr, shent_size);
		if (shdr.sh_type == SHT_PROGBITS) {
			int name_idx = shdr.sh_name;
			if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
					|| strcmp(&(string_table[name_idx]), ".got") == 0) {
				out_addr = (uint32_t) base_addr + shdr.sh_addr;
				out_size = shdr.sh_size;
				LOGD("[+] out_addr = %x, out_size = %x\n", out_addr, out_size);

				for (i = 0; i < out_size; i += 4) {
					got_item = *(uint32_t *) (out_addr + i);

					if (got_item == (uint32_t) symbolAddr) {
						got_found = 1;
						LOGD("[+] got_item addr = %x \n", got_item);

						uint32_t page_size = getpagesize();
						uint32_t entry_page_start = (out_addr + i)
								& (~(page_size - 1));
						mprotect((uint32_t *) entry_page_start, page_size,
								PROT_READ | PROT_WRITE);
						*(uint32_t *) (out_addr + i) = replaceAddr;

						got_item = *(uint32_t *) (out_addr + i);
						LOGD("[+] replace got_item addr = %x \n", got_item);

						break;
					} else if (got_item == replaceAddr) {
						got_found = 1;
						LOGD("[+] Already got_item addr = %x \n", got_item);
						break;
					}

				}
				if (got_found == 1) {
					break;
				}
			}
		}
	}

	free(string_table);
	close(fd);

	if (got_found != 1) {
		LOGD("[+] No found symbolAddr %d on got table\n", symbolAddr);
		return -2;
	}

	return 0;
}

#define LIBSF_PATH  "/system/lib/libsurfaceflinger.so"
#define HOOK_ACTION_INJECT				0	//注入
#define HOOK_ACTION_REMOVE_INJECT		1	//移除注入
#define HWCOMPOSER	"hwcomposer."
int hook_eglSwapBuffers(int hook_action) {
//    void* handle = dlopen(LIBSF_PATH, RTLD_NOW | RTLD_GLOBAL);
//	void* handle = dlopen(LIBSF_PATH, RTLD_LAZY);
//	old_eglSwapBuffers = dlsym(handle, "eglSwapBuffers");
//	LOGD("[+] old_eglSwapBuffers : %p\n", old_eglSwapBuffers);
//	dlclose(handle);

	if (old_eglSwapBuffers == NULL) {
		LOGD("[+] init eglSwapBuffers %p \n", eglSwapBuffers);
		old_eglSwapBuffers = eglSwapBuffers;

//		void* eglSwapBuffers_dlsym = dlsym ((void *) -1l, "eglSwapBuffers");
//		LOGD("[+] init eglSwapBuffers_dlsym %p \n", eglSwapBuffers_dlsym);
		LOGD("[+] new_eglSwapBuffers = %p\n", new_eglSwapBuffers);
	}

	uint32_t find = (uint32_t)old_eglSwapBuffers;
	uint32_t replace = (uint32_t)new_eglSwapBuffers;
	if (hook_action != HOOK_ACTION_INJECT) {
		find = (uint32_t)new_eglSwapBuffers;
		replace = (uint32_t)old_eglSwapBuffers;
	}

	char file[256];
	int len = findStartStringFilePath("/system/lib/hw", HWCOMPOSER, file);
	int ret = -3;
	if (len > 0) {
		LOGD("[+] find hwcomposer so : %s\n", file);
		ret = replaceGotSymbolAddr(file, find, replace);
		LOGD("[+] replaceGotSymbolAddr hwcomposer : %d\n", ret);
	}
	len = findStartStringFilePath("/system/vendor/lib/hw", HWCOMPOSER, file);
	if (len > 0) {
		LOGD("[+] find hwcomposer so : %s\n", file);
		ret = replaceGotSymbolAddr(file, find, replace);
		LOGD("[+] replaceGotSymbolAddr hwcomposer : %d\n", ret);
	}

	ret = replaceGotSymbolAddr(LIBSF_PATH, find, replace);
	LOGD("[+] replaceGotSymbolAddr libsurfaceflinger : %d\n", ret);
	return ret;
}

//int hook_eglSwapBuffers(int hook_action) {
//	old_eglSwapBuffers = eglSwapBuffers;
//	LOGD("Orig eglSwapBuffers = %p\n", old_eglSwapBuffers);
//	void * base_addr = get_module_base(getpid(), LIBSF_PATH);
//	LOGD("[+] libsurfaceflinger.so address = %p\n", base_addr);
//
////    void* handle = dlopen("/system/lib/libEGL.so", RTLD_NOW | RTLD_GLOBAL);
////    void* dlopen_eglSwapBuffers = dlsym(handle, "eglSwapBuffers");
////    dlclose(handle);
////    LOGD("[+] dlopen_eglSwapBuffers = %p\n", dlopen_eglSwapBuffers);
//
//	int fd = open(LIBSF_PATH, O_RDONLY);
//	if (-1 == fd) {
//		LOGD("[+] error\n");
//		return -1;
//	}
//
//	Elf32_Ehdr ehdr;
//	read(fd, &ehdr, sizeof(Elf32_Ehdr));
//
//	unsigned long shdr_addr = ehdr.e_shoff;
//	int shnum = ehdr.e_shnum;
//	int shent_size = ehdr.e_shentsize;
//	unsigned long stridx = ehdr.e_shstrndx;
//
//	Elf32_Shdr shdr;
//	lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
//	read(fd, &shdr, shent_size);
//
//	char * string_table = (char *) malloc(shdr.sh_size);
//	lseek(fd, shdr.sh_offset, SEEK_SET);
//	read(fd, string_table, shdr.sh_size);
//	lseek(fd, shdr_addr, SEEK_SET);
//
//	int i;
//	uint32_t out_addr = 0;
//	uint32_t out_size = 0;
//	uint32_t got_item = 0;
//	int32_t got_found = 0;
//
//	char* action = "HOOK_ACTION_REMOVE_INJECT";
//	EglSwapBuffers find = new_eglSwapBuffers;
//	EglSwapBuffers replace = old_eglSwapBuffers;
//	if (hook_action == HOOK_ACTION_INJECT) {
//		action = "HOOK_ACTION_INJECT";
//		replace = new_eglSwapBuffers;
//		find = old_eglSwapBuffers;
//	}
//
//	LOGD("[+] find addr = %p \n", find);
//	LOGD("[+] replace addr = %p \n", replace);
//
//	for (i = 0; i < shnum; i++) {
//		read(fd, &shdr, shent_size);
//		if (shdr.sh_type == SHT_PROGBITS) {
//			int name_idx = shdr.sh_name;
//			if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
//					|| strcmp(&(string_table[name_idx]), ".got") == 0) {
//				out_addr = (uint32_t) base_addr + shdr.sh_addr;
//				out_size = shdr.sh_size;
//				LOGD("[+] out_addr = %x, out_size = %x\n", out_addr, out_size);
//
//				for (i = 0; i < out_size; i += 4) {
//					got_item = *(uint32_t *) (out_addr + i);
//
//					if (got_item == (uint32_t) find) {
//						got_found = 1;
//						LOGD("[+] %s : Found eglSwapBuffers in got\n", action);
//						LOGD("[+] got_item addr = %x \n", got_item);
//
//						uint32_t page_size = getpagesize();
//						uint32_t entry_page_start = (out_addr + i)
//								& (~(page_size - 1));
//						mprotect((uint32_t *) entry_page_start, page_size,
//								PROT_READ | PROT_WRITE);
//						*(uint32_t *) (out_addr + i) = (uint32_t) replace;
//
//						got_item = *(uint32_t *) (out_addr + i);
//						LOGD("[+] replace got_item addr = %x \n", got_item);
//
//						break;
//					} else if (got_item == (uint32_t) replace) {
//						got_found = 1;
//						LOGD("[+] %s : Already ....\n", action);
//						LOGD("[+] Already got_item addr = %x \n", got_item);
//						break;
//					}
//
//				}
//				if (got_found == 1) {
//					break;
//				}
//			}
//		}
//	}
//
//	free(string_table);
//	close(fd);
//
//	if (got_found != 1) {
//		return -2;
//	}
//
//	return 0;
//}

int fpsShow_action(char * path, int hook_action) {
#if ENABLE_DEBUG
	char* action = "HOOK_ACTION_REMOVE_INJECT";

	if (hook_action == HOOK_ACTION_INJECT) {
		action = "HOOK_ACTION_INJECT";
	}

	LOGD("[+] %s : Hook success\n", action);
	LOGD("[+] %s : Start hooking\n", action);
#endif

//    LOGD("fpsShow file : %s\n", file);
//    fpsPath = strdup(path);
	fpsPath = path;

#ifdef TIME_USING_CLOCK
	sck = clock();
#else
	startTime = current_timestamp();
#endif

//	fp = NULL;

	return hook_eglSwapBuffers(hook_action);
}

int infps(char * path) {
	return fpsShow_action(path, HOOK_ACTION_INJECT);
}

/**
 * 移除fps注入
 * path : 不重要,随便写
 */
int rmfps(char * path) {
	int ret = fpsShow_action(path, HOOK_ACTION_REMOVE_INJECT);
//	closeFp();
	return ret;
}
