#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>

#include "debug.h"

#if defined(__i386__)
#define pt_regs         user_regs_struct
#endif

#define CPSR_T_MASK     ( 1u << 5 )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";

int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for (i = 0; i < j; i ++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = data;

    for (i = 0; i < j; i ++) {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, (void *)d.val);

        dest  += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, (void *)d.val);
    }

    return 0;
}

#if defined(__arm__)
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)
{
    uint32_t i;
    for (i = 0; i < num_params && i < 4; i ++) {
        regs->uregs[i] = params[i];
    }

    //
    // push remained params onto stack
    //
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}

#elif defined(__i386__)
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
    regs->esp -= (num_params) * sizeof(long) ;
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid, (uint8_t *)regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

    regs->eip = addr;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue( pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#else
#error "Not supported"
#endif

int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
    	LOGE("[+] ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
    	LOGE("[+] ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
    	LOGE("[+] ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
    	LOGE("[+] 1.ptrace_attach");
        return -1;
    }

    waitpid(pid, NULL, WUNTRACED);

    /*
	 * Restarts  the stopped child as for PTRACE_CONT, but arranges for
	 * the child to be stopped at the next entry to or exit from a sys‐
	 * tem  call,  or  after execution of a single instruction, respec‐
	 * tively.
	 */
	if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) {
		LOGE("[+] 2.ptrace_syscall");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL ) < 0) {
		LOGE("[+] 3.ptrace_syscall");
		return -1;
	}

	waitpid(pid, NULL, WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
    	LOGE("[+] ptrace_detach");
        return -1;
    }

    return 0;
}

uint32_t get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

//    if (pid < 0) {
//        /* self process */
//    	pid = getpid();
//    }
//    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    //DEBUG_PRINT("[+] maps filename : %s \n", filename);

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return addr;
}

uint32_t get_remote_addr(pid_t target_pid, const char* module_name, uint32_t local_addr)
{
	uint32_t local_handle, remote_handle;

    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(target_pid, module_name);

    DEBUG_PRINT("[+] get_remote_addr:local_addr[%x], local[%x], remote[%x]\n", local_addr, local_handle, remote_handle);

    uint32_t ret_addr = local_addr + remote_handle - local_handle;

#if defined(__i386__)
    if (!strcmp(module_name, libc_path)) {
        ret_addr += 2;
    }
#endif
    return ret_addr;
}

/**********************************************************************/
int find_module_info_by_address(pid_t pid, void* addr, char *module, void** start, void** end) {
	char statline[1024];
	FILE *fp;
	char *address, *proms, *ptr, *p;

	if ( pid < 0 ) {
		/* self process */
		snprintf( statline, sizeof(statline), "/proc/self/maps");
	} else {
		snprintf( statline, sizeof(statline), "/proc/%d/maps", pid );
	}

	fp = fopen( statline, "r" );

	if ( fp != NULL ) {
		while ( fgets( statline, sizeof(statline), fp ) ) {
			ptr = statline;
			address = (char*)nexttok(&ptr); // skip address
			proms = (char*)nexttok(&ptr); // skip proms
			nexttok(&ptr); // skip offset
			nexttok(&ptr); // skip dev
			nexttok(&ptr); // skip inode

			while(*ptr != '\0') {
				if(*ptr == ' ')
					ptr++;
				else
					break;
			}

			p = ptr;
			while(*p != '\0') {
				if(*p == '\n')
					*p = '\0';
				p++;
			}

			// 4016a000-4016b000
			if(strlen(address) == 17) {
				address[8] = '\0';

				*start = (void*)strtoul(address, NULL, 16);
				*end   = (void*)strtoul(address+9, NULL, 16);

				// printf("[%p-%p] %s | %p\n", *start, *end, ptr, addr);

				if(addr > *start && addr < *end) {
					strcpy(module, ptr);

					fclose( fp ) ;
					return 0;
				}
			}
		}

		fclose( fp ) ;
	}

	return -1;
}

int find_module_info_by_name(pid_t pid, const char *module, void** start, void** end) {
	char statline[1024];
	FILE *fp;
	char *address, *proms, *ptr, *p;

	if ( pid < 0 ) {
		/* self process */
		snprintf( statline, sizeof(statline), "/proc/self/maps");
	} else {
		snprintf( statline, sizeof(statline), "/proc/%d/maps", pid );
	}

	fp = fopen( statline, "r" );

	if ( fp != NULL ) {
		while ( fgets( statline, sizeof(statline), fp ) ) {
			ptr = statline;
			address = (char*)nexttok(&ptr); // skip address
			proms = (char*)nexttok(&ptr); // skip proms
			nexttok(&ptr); // skip offset
			nexttok(&ptr); // skip dev
			nexttok(&ptr); // skip inode

			while(*ptr != '\0') {
				if(*ptr == ' ')
					ptr++;
				else
					break;
			}

			p = ptr;
			while(*p != '\0') {
				if(*p == '\n')
					*p = '\0';
				p++;
			}

			// 4016a000-4016b000
			if(strlen(address) == 17) {
				address[8] = '\0';

				*start = (void*)strtoul(address, NULL, 16);
				*end   = (void*)strtoul(address+9, NULL, 16);

				// printf("[%p-%p] %s | %p\n", *start, *end, ptr, addr);

				if(strncmp(module, ptr, strlen(module)) == 0) {
					fclose( fp ) ;
					return 0;
				}
			}
		}

		fclose( fp ) ;
	}

	return -1;
}

void* get_remote_address(pid_t pid, void *local_addr) {
	char buf[256];
	void* local_start = 0;
	void* local_end = 0;
	void* remote_start = 0;
	void* remote_end = 0;

	if(find_module_info_by_address(-1, local_addr, buf, &local_start, &local_end) < 0) {
		LOGI("[-] find_module_info_by_address FAIL");
		return NULL;
	}

	LOGI("[+] the local module is %s", buf);

	if(find_module_info_by_name(pid, buf, &remote_start, &remote_end) < 0) {
		LOGI("[-] find_module_info_by_name FAIL");
		return NULL;
	}

	return (void *)( (uint32_t)local_addr + (uint32_t)remote_start - (uint32_t)local_start );
}
/**********************************************************************/

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

long ptrace_retval(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_r0;
#elif defined(__i386__)
    return regs->eax;
#else
#error "Not supported"
#endif
}

long ptrace_ip(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_pc;
#elif defined(__i386__)
    return regs->eip;
#else
#error "Not supported"
#endif
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, uint32_t func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
    if (ptrace_call(target_pid, func_addr, parameters, param_num, regs) == -1) {
        return -1;
    }

    if (ptrace_getregs(target_pid, regs) == -1) {
        return -1;
    }
    DEBUG_PRINT("[+] Target process returned from %s, return value=%lx, pc=%lx \n",
            func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

/**
 * 注入远程进程
 * 这里用到了内存映射空间,原因是,远程进程不能直接使用本进程的内存数据
 *
 * target_pid : 目标进程id
 * library_path : 注入的so路径
 * function_name : 注入后执行的so里的函数名
 * param : 函数的函数参数,只能有一个字符串参数,如需修改,请修改对应部分代码
 */
int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param)
{
    int ret = -1;
    uint32_t mmap_addr, munmap_addr, dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr;
//    uint32_t local_handle, remote_handle, dlhandle;
    uint32_t map_base = 0;
//    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
//    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
//        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
//        _saved_cpsr_s, _saved_r0_pc_s;

//    uint32_t code_length;
    long parameters[10];

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));

    //小米2 刷的color Os上,在Android里执行命令,直接使用mmap地址是错误的.使用新方法
    void* handle = dlopen(libc_path, RTLD_LAZY);
	void* local_mmap = dlsym(handle, "mmap");
	void* local_munmap = dlsym(handle, "munmap");
	dlclose(handle);

    mmap_addr = get_remote_addr(target_pid, libc_path, (uint32_t)local_mmap);

    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

//	munmap_addr = get_remote_addr(target_pid, libc_path, (uint32_t)local_munmap);
//	DEBUG_PRINT("[+] Remote munmap address: %x\n", munmap_addr);

//	return -3;

    /**
     * call mmap function
     * mmap, munmap - map or unmap files or devices into memory
     * void *mmap(void *start, size_t length, int prot, int flags,
     * 		  int fd, off_t offset);
     */

    /* call mmap 映射一块内存空间 */
    parameters[0] = 0;  // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset
    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    //get funtion "mmap" retrun value
    map_base = ptrace_retval(&regs);

    DEBUG_PRINT("[+] mmap addr map_base : 0x%x \n", map_base);

    /**
     * end call mmap
     */

    dlopen_addr  = get_remote_addr( target_pid, linker_path, (uint32_t)dlopen );
    dlsym_addr 	 = get_remote_addr( target_pid, linker_path, (uint32_t)dlsym );
    dlclose_addr = get_remote_addr( target_pid, linker_path, (uint32_t)dlclose );
    dlerror_addr = get_remote_addr( target_pid, linker_path, (uint32_t)dlerror );

    DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    //把so的文件路径写入到映射出来的内存空间
    DEBUG_PRINT("library path = %s\n", library_path);
    ptrace_writedata(target_pid, (uint8_t *)map_base, (uint8_t *)library_path, strlen(library_path) + 1);

    /**
     * call dlopen function
     * void *dlopen(const char *filename, int flag);
     */
    parameters[0] = map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;
    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;
    //get dlopen return value
    long sohandle = ptrace_retval(&regs);

#define FUNCTION_NAME_ADDR_OFFSET       0x100
    /**
     * 把函数名些到映射出来的内存空间中,偏移是0x100,这也间接的限制了上面写入的so文件路径的最大长度为0x100-1(ANSI String)
     */
    ptrace_writedata(target_pid, (uint8_t *)map_base + FUNCTION_NAME_ADDR_OFFSET, (uint8_t *)function_name, strlen(function_name) + 1);


    /**
     * 获取function_name在so中的地址
     */
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    long hook_entry_addr = ptrace_retval(&regs);
    DEBUG_PRINT("hook_entry_addr function(%s) = %lx\n", function_name, hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x200
    /**
     * 写入一个字符串参数到映射出来的内存空间中,间接的说明这个函数只能有一个字符串参数,如果需要修改,就的修改此处
     */
    ptrace_writedata(target_pid, (uint8_t *)map_base + FUNCTION_PARAM_ADDR_OFFSET, (uint8_t *)param, strlen(param) + 1);

    /**
     * 调用注入so中的函数
     */
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;
    if (ptrace_call_wrapper(target_pid, function_name, (uint32_t)hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    long hook_entry_return = ptrace_retval(&regs);
    DEBUG_PRINT("[+] hook_entry_return: %ld\n", hook_entry_return);

    if (hook_entry_return != 0) {
    	DEBUG_PRINT("[+] call hook entry faild.");
		ret = -2;
	} else {
		ret = 0;
	}


//    printf("Press enter to dlclose and detach\n");
//    getchar();


    /**
     * 关闭打开的so文件句柄
     */
//    parameters[0] = sohandle;
//    if (ptrace_call_wrapper(target_pid, "dlclose", (uint32_t)dlclose, parameters, 1, &regs) == -1)
//        goto exit;
//    ptrace_call_wrapper(target_pid, "dlclose", (uint32_t)dlclose, parameters, 1, &regs);

    /**
     * 关闭映射内存空间
     * 关闭就异常,不能关闭
     * int munmap(void *start, size_t length);
     * 经测试,这个一个很小的消耗,可以不考虑关闭
     * 测试mmap使用同一个地址,每次返回的也是新地址
     */
//    munmap_addr = get_remote_addr(target_pid, libc_path, (uint32_t)local_munmap);
//    DEBUG_PRINT("[+] Remote munmap address: %x\n", munmap_addr);
//    parameters[0] = map_base;  	// addr
//    parameters[1] = 0x4000; 	// size
//    ptrace_call_wrapper(target_pid, "munmap", munmap_addr, parameters, 2, &regs);

    /**
     * 恢复ptrace
     */
    DEBUG_PRINT("[+] ptrace_setregs\n");
    /* restore */
    ptrace_setregs(target_pid, &original_regs);
    DEBUG_PRINT("[+] ptrace_detach\n");
    ptrace_detach(target_pid);

exit:
	DEBUG_PRINT("[+] ret. over.\n");
    return ret;
}

#if ENABLE_DEBUG
uint32_t echoMaps(pid_t pid)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
    	pid = getpid();
    }

    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    fp = fopen(filename, "r");

    DEBUG_PRINT("[+] maps filename : %s \n", filename);

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
        	DEBUG_PRINT("[+] %s \n", line);
        }

        fclose(fp) ;
    }

    return addr;
}
#endif

int main(int argc, char** argv) {

	if (argc != 4) {
		printf("USAGE : soPath functionName strArg \n");
		return -1;
	}

	char* libPath 	= argv[1];
	char* function 	= argv[2];
	char* fnArg 	= argv[3];

    DEBUG_PRINT("[+] inject uid : %d, gid: %d\n", getuid(), getgid());
    DEBUG_PRINT("[+] inject pid : %d, gid: %d\n", getpid(), getppid());

    pid_t target_pid = find_pid_of("/system/bin/surfaceflinger");
    if (-1 == target_pid) {
    	printf("[+] faild : Can't find the process\n");
        return -1;
    }

    int ret = inject_remote_process(target_pid, libPath, function,  fnArg);

    /**
     * surfaceflinger有可能被重启,一样失败
     * 所以需要再次查找PID,查看是否改变
     */
    if (find_pid_of("/system/bin/surfaceflinger") != target_pid) {
    	ret = -2;
    }

    if (ret != 0) {
    	printf("[+] %s : FAILD.(%d)\n", function, ret);
	} else {
		printf("[+] %s : SUCCESS.\n", function);
	}
    return ret;
}
