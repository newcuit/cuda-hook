#include <stdio.h>
#include <stdlib.h>
#include <cassert>
#include <errno.h>
#include <cstring>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <ucontext.h>
#include <iostream>

#define NV_LINUX
#include "kernel-open/nvidia-uvm/uvm_linux_ioctl.h"
#include "kernel-open/nvidia-uvm/uvm_ioctl.h"
#include "kernel-open/common/inc/nv-ioctl.h"
#include "kernel-open/common/inc/nv-ioctl-numbers.h"
#define NV_ESC_NUMA_INFO         (NV_IOCTL_BASE + 15)
#include "src/nvidia/arch/nvalloc/unix/include/nv_escape.h"
#include "src/nvidia/arch/nvalloc/unix/include/nv-unix-nvos-params-wrappers.h"
#include "src/common/sdk/nvidia/inc/nvos.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl503c.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000system.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000client.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000gpu.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000syncgpuboost.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl0080.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl2080.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl83de/ctrl83dedebug.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrl906f.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrlcb33.h"
#include "src/common/sdk/nvidia/inc/class/clb0b5sw.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrlc36f.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrla06c.h"
#include "src/common/sdk/nvidia/inc/ctrl/ctrla06f/ctrla06fgpfifo.h"
#include "src/common/sdk/nvidia/inc/class/cl0080.h"
#include "src/common/sdk/nvidia/inc/class/cl2080.h"
#include "src/common/sdk/nvidia/inc/class/cl503b.h"
#include "src/nvidia/generated/g_allclasses.h"

#include <vector>
#include <map>
std::map<int, std::string> files;

#define GPU_ACQUIRE_COMPUTE_MODE_RESERVATION 0x20800145u
extern "C" {

std::map<void*, void*> fakepages;
std::map<uint64_t, uint64_t> workTokens;      // map work tokens to AMPERE_CHANNEL_GPFIFO_A objects
std::map<uint64_t, uint32_t*> gpFifoOffsets;  // map AMPERE_CHANNEL_GPFIFO_A objects to addresses

static void handler(int sig, siginfo_t *si, void *unused) {
        ucontext_t *u = (ucontext_t *)unused;
        uint8_t *rip = (uint8_t*)u->uc_mcontext.gregs[REG_RIP];

        uint32_t *fake = NULL, *real = NULL;
        for (auto tp : fakepages) {
                if (si->si_addr >= tp.first && (uint64_t)si->si_addr < ((uint64_t)tp.first)+0x10000) {
                        fake = (uint32_t *)tp.first;
                        real = (uint32_t *)tp.second;
                }
        }

        if (fake == NULL) {
                // this is not our hacked page, segfault
                printf("segfault at %p\n", si->si_addr);
                exit(-1);
        }

        // it's rcx on some CUDA drivers
        uint64_t rdx;
        int start;

        // TODO: where does start come from
        // rdx is the offset into the command buffer GPU mapping
        // TODO: decompile all stores
        // https://defuse.ca/online-x86-assembler.htm#disassembly2
        int addr_reg = REG_RAX;
        bool is_load = false;
        if (rip[0] == 0x89 && rip[1] == 0x10) {
                // mov    DWORD PTR [eax],edx
                rdx = u->uc_mcontext.gregs[REG_RDX];
        } else if (rip[0] == 0x89 && rip[1] == 0x08) {
                // mov    DWORD PTR [eax],ecx
                rdx = u->uc_mcontext.gregs[REG_RCX];
        } else if (rip[0] == 0x89 && rip[1] == 0x0a) {
                // mov    DWORD PTR [edx],ecx
                rdx = u->uc_mcontext.gregs[REG_RCX];
                addr_reg = REG_RDX;
        } else if (rip[0] == 0x89 && rip[1] == 0x01) {
                // mov    DWORD PTR [ecx],eax
                rdx = u->uc_mcontext.gregs[REG_RAX];
                addr_reg = REG_RCX;
        } else if (rip[0] == 0x8b && rip[1] == 0x02) {
                // mov    eax,DWORD PTR [edx]
                is_load = true;
                addr_reg = REG_RDX;
        } else if (rip[0] == 0x8b && rip[1] == 0x3e) {
                // mov    edi,DWORD PTR [esi]
                is_load = true;
                addr_reg = REG_RSI;
        } else {
                printf("UNKNOWN CALL ASM addr:%lx\n", (uint64_t)si->si_addr-(uint64_t)fake);
                printf("intercept %02X %02X %02X %02X rip %p\n", rip[0], rip[1], rip[2], rip[3], rip);
                exit(-1);
        }

        // NOTE: OpenCL reads from 0x80 and 0x84
        uint64_t addr = (uint64_t)si->si_addr-(uint64_t)fake+(uint64_t)real;
        printf("write addr:%lx\n", addr);
        u->uc_mcontext.gregs[addr_reg] = addr;
}

__attribute__((constructor)) void foo(void) {
        struct sigaction sa;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = handler;
        sigaction(SIGSEGV, &sa, NULL);
}

int (*my_close)(int fd);
#undef close
int close(int fd) {
        if (my_close == NULL) my_close = reinterpret_cast<decltype(my_close)>(dlsym(RTLD_NEXT, "close"));
        int ret = my_close(fd);
        printf("close(%s:%d) = %d\n\n", files[fd].c_str(), fd, ret);
        files[ret] = "";
        return ret;
}


int (*my_close64)(int fd);
#undef close
int close64(int fd) {
        if (my_close64 == NULL) my_close64 = reinterpret_cast<decltype(my_close64)>(dlsym(RTLD_NEXT, "close64"));
        int ret = my_close64(fd);
        printf("close64(%s:%d) = %d\n\n", files[fd].c_str(), fd, ret);
        files[ret] = "";
        return ret;
}


int (*my_open)(const char *pathname, int flags, mode_t mode);
#undef open
int open(const char *pathname, int flags, mode_t mode) {
        if (my_open == NULL) my_open = reinterpret_cast<decltype(my_open)>(dlsym(RTLD_NEXT, "open"));
        int ret = my_open(pathname, flags, mode);
        printf("open(%s, flags=%0x, mode=%0x) = %d\n\n", pathname, flags, mode, ret);
        files[ret] = pathname;
        return ret;
}


int (*my_open64)(const char *pathname, int flags, mode_t mode);
#undef open
int open64(const char *pathname, int flags, mode_t mode) {
        if (my_open64 == NULL) my_open64 = reinterpret_cast<decltype(my_open64)>(dlsym(RTLD_NEXT, "open64"));
        int ret = my_open64(pathname, flags, mode);
        printf("open64(%s, flags=%0x, mode=%0x) = %d\n\n", pathname, flags, mode, ret);
        files[ret] = pathname;
        return ret;
}

bool usermode_map_pending = false;
void *(*my_mmap64)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
#undef mmap64
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
        if (my_mmap64 == NULL) my_mmap64 = reinterpret_cast<decltype(my_mmap64)>(dlsym(RTLD_NEXT, "mmap"));
        void *ret = my_mmap64(addr, length, prot, flags, fd, offset);

        if (usermode_map_pending && flags == 0x1 && length == 0x10000) {
                usermode_map_pending = false;
                void *fake = (uint32_t *)mmap(NULL, length, PROT_NONE, MAP_SHARED | MAP_ANON, -1, 0);
                fakepages[fake] = ret;
                ret = fake;
        }

        if (fd > 0)
                printf("mmap64(addr=%p, length=0x%zx, prot=%d, flags=0x%x, fd=%s, offset=%ld) = %p\n", addr, length, prot, flags, files[fd].c_str(), offset, ret);
        else
                printf("mmap64(addr=%p, length=0x%zx, prot=%d, flags=0x%x, fd=%d, offset=%ld) = %p\n", addr, length, prot, flags, fd, offset, ret);
        printf("\n");
        return ret;
}


void *(*my_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
#undef mmap
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
        if (my_mmap == NULL) my_mmap = reinterpret_cast<decltype(my_mmap)>(dlsym(RTLD_NEXT, "mmap"));
        void *ret = my_mmap(addr, length, prot, flags, fd, offset);

        if (fd > 0)
                printf("mmap(addr=%p, length=0x%zx, prot=%d, flags=0x%x, fd=%s, offset=%ld) = %p\n", addr, length, prot, flags, files[fd].c_str(), offset, ret);
        else
                printf("mmap(addr=%p, length=0x%zx, prot=%d, flags=0x%x, fd=%d, offset=%ld) = %p\n", addr, length, prot, flags, fd, offset, ret);
        printf("\n");
        return ret;
}

int (*my_ioctl)(int filedes, unsigned long request, void *argp) = NULL;
#undef ioctl
int ioctl(int filedes, unsigned long request, void *argp) {
        if (my_ioctl == NULL) my_ioctl = reinterpret_cast<decltype(my_ioctl)>(dlsym(RTLD_NEXT, "ioctl"));
        int ret = 0;

        uint8_t type = (request >> 8) & 0xFF;
        uint8_t nr = (request >> 0) & 0xFF;
        uint16_t size = (request >> 16) & 0xFFF;

        if (type == NV_IOCTL_MAGIC) {
                ret = my_ioctl(filedes, request, argp);

                switch (nr) {
                case NV_ESC_CARD_INFO:
                        printf("ioctl(nvidiactl, NV_ESC_CARD_INFO, params) = %d\n", ret);
                        break;
                case NV_ESC_REGISTER_FD: {
                        nv_ioctl_register_fd_t *params = (nv_ioctl_register_fd_t *)argp;
                        printf("ioctl(nvidiactl, NV_ESC_REGISTER_FD, params) = %d\n", ret);
                        printf("\tfd:%d\n", params->ctl_fd);
                } break;
                case NV_ESC_ALLOC_OS_EVENT:
                        printf("ioctl(nvidiactl, NV_ESC_ALLOC_OS_EVENT, params) = %d\n", ret);
                        break;
                case NV_ESC_SYS_PARAMS:
                        printf("ioctl(nvidiactl, NV_ESC_SYS_PARAMS, params) = %d\n", ret);
                        break;
                case NV_ESC_CHECK_VERSION_STR:
                        printf("ioctl(nvidiactl, NV_ESC_CHECK_VERSION_STR, params) = %d\n", ret);
                        break;
                case NV_ESC_NUMA_INFO:
                        printf("ioctl(nvidiactl, NV_ESC_NUMA_INFO, params) = %d\n", ret);
                        break;
                case NV_ESC_RM_MAP_MEMORY_DMA: {
                        NVOS46_PARAMETERS *p = (NVOS46_PARAMETERS *)argp;
                        printf("ioctl(nvidiactl, NV_ESC_RM_MAP_MEMORY_DMA, params) = %d\n", ret);
                        printf("\thClient: %x hDevice: %x hDma: %x hMemory: %x offset: %llx length %llx status %x flags %x\n",
                                p->hClient, p->hDevice, p->hDma, p->hMemory, p->offset, p->length, p->status, p->flags);
                } break;
                case NV_ESC_RM_UNMAP_MEMORY_DMA:
                        printf("ioctl(nvidiactl, NV_ESC_RM_UNMAP_MEMORY_DMA, params) = %d\n", ret);
                        break;
                case NV_ESC_RM_UNMAP_MEMORY:
                        printf("ioctl(nvidiactl, NV_ESC_RM_UNMAP_MEMORY, params) = %d\n", ret);
                        break;
                case NV_ESC_RM_DUP_OBJECT:
                        printf("ioctl(nvidiactl, NV_ESC_RM_DUP_OBJECT, params) = %d\n", ret);
                        break;
                case NV_ESC_RM_ALLOC_MEMORY: {
                        NVOS02_PARAMETERS *p = (NVOS02_PARAMETERS *)argp;
                        printf("ioctl(nvidiactl, NV_ESC_RM_ALLOC_MEMORY, params) = %d\n", ret);
                        printf("\thRoot: %x pMemory: %p limit: %llx\n", p->hRoot, p->pMemory, p->limit);
                } break;
                case NV_ESC_RM_FREE:
                        printf("ioctl(nvidiactl, NV_ESC_RM_FREE, params) = %d\n", ret);
                        break;
                case NV_ESC_RM_CONTROL: {
                        const char *cmd_string = "";
                        NVOS54_PARAMETERS *p = (NVOS54_PARAMETERS *)argp;

                        printf("ioctl(nvidiactl, NV_ESC_RM_CONTROL, params) = %d\n", ret);
                        printf("\tclient: %x object: %x cmd: %08x params: %p 0x%x flags: %x status 0x%x\n", p->hClient, p->hObject, p->cmd,
                                        p->params, p->paramsSize, p->flags, p->status);
                        #define cmd(name) case name: cmd_string = #name; printf("\t\t%s\n", cmd_string);break
                        switch (p->cmd) {
                        cmd(NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION);
                        cmd(NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS);
                        cmd(NV0080_CTRL_CMD_DMA_SET_PAGE_DIRECTORY);
                        cmd(NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS);
                        cmd(NV0000_CTRL_CMD_GPU_GET_ID_INFO);
                        cmd(NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE);
                        cmd(NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO);
                        cmd(NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX);
                        cmd(NV0000_CTRL_CMD_GPU_DETACH_IDS);
                        cmd(NV2080_CTRL_CMD_GPU_GET_NAME_STRING);
                        cmd(NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING);
                        cmd(NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS);
                        cmd(NV2080_CTRL_CMD_GPU_GET_ENGINES);
                        cmd(NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES);
                        cmd(NV2080_CTRL_CMD_GPU_GET_ENGINES_V2);
                        cmd(NV2080_CTRL_CMD_GPU_GET_INFO_V2);
                        cmd(NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS);
                        cmd(NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO);
                        cmd(NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO);
                        cmd(NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS);
                        cmd(NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG);
                        cmd(NV2080_CTRL_CMD_FB_GET_INFO);
                        cmd(NV2080_CTRL_CMD_GR_GET_INFO);
                        cmd(NV2080_CTRL_CMD_GR_GET_GPC_MASK);
                        cmd(NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE);
                        cmd(NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE);
                        cmd(NV2080_CTRL_CMD_GR_GET_TPC_MASK);
                        cmd(NV2080_CTRL_CMD_GR_GET_CAPS_V2);
                        cmd(NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER);
                        cmd(NV2080_CTRL_CMD_BUS_GET_PCI_INFO);
                        cmd(NV2080_CTRL_CMD_BUS_GET_INFO);
                        cmd(NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO);
                        cmd(NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS);
                        cmd(NV2080_CTRL_CMD_GSP_GET_FEATURES);
                        cmd(NV2080_CTRL_CMD_MC_GET_ARCH_INFO);
                        cmd(NV2080_CTRL_CMD_PERF_BOOST);
                        cmd(NV2080_CTRL_CMD_CE_GET_CAPS);
                        cmd(NVA06C_CTRL_CMD_SET_TIMESLICE);
                        cmd(NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK);
                        cmd(NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY);
                        cmd(NV0080_CTRL_CMD_GPU_GET_CLASSLIST);
                        cmd(NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE);
                        cmd(NV0080_CTRL_CMD_HOST_GET_CAPS);
                        cmd(NV0080_CTRL_CMD_FIFO_GET_CAPS);
                        cmd(NV0080_CTRL_CMD_FB_GET_CAPS);
                        cmd(NV0080_CTRL_CMD_GR_GET_CAPS);
                        cmd(NV0080_CTRL_CMD_BSP_GET_CAPS);
                        cmd(NV0080_CTRL_CMD_MSENC_GET_CAPS);
                        cmd(NV0080_CTRL_CMD_FIFO_GET_CAPS_V2);
                        cmd(NV2080_CTRL_CMD_GPU_GET_INFO);
                        cmd(NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO);
                        cmd(NV503C_CTRL_CMD_REGISTER_VIDMEM);
                        cmd(NV503C_CTRL_CMD_UNREGISTER_VIDMEM);
                        cmd(NV0000_CTRL_CMD_SYSTEM_GET_FEATURES);
                        cmd(NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES);
                        cmd(NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2);
                        cmd(NV0080_CTRL_CMD_HOST_GET_CAPS_V2);
                        cmd(NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2);
                        cmd(NV2080_CTRL_CMD_FB_GET_INFO_V2);
                        cmd(NV2080_CTRL_CMD_BUS_GET_INFO_V2);
                        cmd(NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG);
                        cmd(NV2080_CTRL_CMD_CE_GET_ALL_CAPS);
                        cmd(NV2080_CTRL_CMD_BUS_GET_C2C_INFO);
                        cmd(GPU_ACQUIRE_COMPUTE_MODE_RESERVATION);
                        cmd(NV503C_CTRL_CMD_REGISTER_VA_SPACE);
                        cmd(NV0080_CTRL_CMD_FB_GET_CAPS_V2);
                        cmd(NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS);
                        //cmd(NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL);
                        cmd(NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS);
                        case NV0000_CTRL_CMD_GPU_ATTACH_IDS: {
                                int i;
                                NV0000_CTRL_GPU_ATTACH_IDS_PARAMS *subParams = (NV0000_CTRL_GPU_ATTACH_IDS_PARAMS *)p->params;
                                printf("\t\tNV0000_CTRL_CMD_GPU_ATTACH_IDS: \n");
                                for (i = 0; i < NV0000_CTRL_GPU_MAX_PROBED_GPUS; i++)
                                        if (subParams->gpuIds[i] != 0)
                                                printf("\t\t\tattached[%d] %x\n", i, subParams->gpuIds[i]);
                                break;
                        }
                        case NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES: {
                                NV0080_CTRL_GPU_GET_NUM_SUBDEVICES_PARAMS *subParams = (NV0080_CTRL_GPU_GET_NUM_SUBDEVICES_PARAMS*)p->params;
                                printf("\t\tNV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES: ");
                                printf("numSubDevices %x\n", subParams->numSubDevices);
                                break;
                        }
                        case NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:{
                                int i;
                                NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *subParams = (NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS*)p->params;
                                printf("\t\tNV0000_CTRL_CMD_GPU_GET_PROBED_IDS: \n");
                                for (i = 0; i < NV0000_CTRL_GPU_MAX_PROBED_GPUS; i++)
                                        if (0xffffffff != subParams->gpuIds[i])
                                                printf("\t\t\tgpuIds[%d] %x\n", i, subParams->gpuIds[i]);
                                break;
                        }
                        case NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST: {
                                int i;
                                uint32_t *channel_handle_list, *channel_list;
                                NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS *subParams = (NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS *)p->params;

                                printf("\t\tNV0080_CTRL_CMD_FIFO_GET_CHANNELLIST(%d): \n", subParams->numChannels);
                                for (i = 0; i < subParams->numChannels; i++) {
                                        channel_list = (uint32_t *)subParams->pChannelList;
                                        channel_handle_list = (uint32_t *)subParams->pChannelHandleList;
                                        printf("\t\t\t[%d]: ChannelHandleList %x ChannelList %x\n", i, channel_handle_list[i], channel_list[i]);
                                }
                                break;
                        }
                        case NVC36F_CTRL_GET_CLASS_ENGINEID:
                        case NV906F_CTRL_GET_CLASS_ENGINEID: {
                                NV906F_CTRL_GET_CLASS_ENGINEID_PARAMS *subParams = (NV906F_CTRL_GET_CLASS_ENGINEID_PARAMS*)p->params;
                                printf("\t\tNV906F_CTRL_GET_CLASS_ENGINEID: ");
                                printf("hObject %x classEngineID %x classID %x engineID %x\n", subParams->hObject,
                                                subParams->classEngineID, subParams->classID, subParams->engineID);
                                break;
                        }
                        case NVA06C_CTRL_CMD_PREEMPT: {
                                NVA06C_CTRL_PREEMPT_PARAMS *subParams = (NVA06C_CTRL_PREEMPT_PARAMS *)p->params;
                                printf("\t\tNVA06C_CTRL_CMD_PREEMPT: ");
                                printf("bWait %x bManualTimeout %x timeoutUs %x\n", subParams->bWait, subParams->bManualTimeout, subParams->timeoutUs);
                                break;
                        }
                        case NVA06F_CTRL_CMD_BIND: {
                                NVA06F_CTRL_BIND_PARAMS  *subParams = (NVA06F_CTRL_BIND_PARAMS *)p->params;
                                printf("\t\tNVA06F_CTRL_CMD_BIND: ");
                                printf("binding engineType %x\n", subParams->engineType);
                                break;
                        }
                        case NVC36F_CTRL_CMD_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX: {
                                NVC36F_CTRL_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX_PARAMS *subParams = (NVC36F_CTRL_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX_PARAMS*)p->params;
                                printf("\t\tNVC36F_CTRL_CMD_GPFIFO_SET_WORK_SUBMIT_TOKEN_NOTIF_INDEX: ");
                                printf("index %x\n", subParams->index);
                                break;
                        }
                        case NVA06F_CTRL_CMD_GPFIFO_SCHEDULE:
                        case NVA06C_CTRL_CMD_GPFIFO_SCHEDULE: {
                                NVA06F_CTRL_GPFIFO_SCHEDULE_PARAMS *subParams = (NVA06F_CTRL_GPFIFO_SCHEDULE_PARAMS*)p->params;
                                printf("\t\tNVA06C_CTRL_CMD_GPFIFO_SCHEDULE: ");
                                printf("schedule %x skipSubmit %x\n", subParams->bEnable, subParams->bSkipSubmit);
                                break;
                        }
                        case NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE: {
                                NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_PARAMS *subParams = (NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_PARAMS *)p->params;
                                printf("\t\tNV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE: ");
                                printf("hObject=%x  mapFlags=%x   out: addrSpaceType:%x\n", subParams->hObject, subParams->mapFlags, subParams->addrSpaceType);
                                break;
                        }
                        case NV2080_CTRL_CMD_GPU_GET_GID_INFO: {
                                NV2080_CTRL_GPU_GET_GID_INFO_PARAMS *subParams = (NV2080_CTRL_GPU_GET_GID_INFO_PARAMS *)p->params;
                                printf("\t\tNV2080_CTRL_CMD_GPU_GET_GID_INFO: ");
                                printf("index %d flags %d length %d\n", subParams->index, subParams->flags, subParams->length);
                                break;
                        }
                        case NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN: {
                                NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS *subParams = (NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS *)p->params;
                                printf("\t\tNVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN: ");
                                printf("work submit token 0x%x\n", subParams->workSubmitToken);
                                workTokens[subParams->workSubmitToken] = p->hObject;
                                break;
                        }
                        default: printf("\t\tUNKNOWN\n"); break;
                        }
                        #undef cmd
                } break;
                case NV_ESC_RM_ALLOC: {
                        const char *cls_string = "";
                        NVOS21_PARAMETERS *p = (NVOS21_PARAMETERS *)argp;

                        #define cls(name) case name: cls_string = #name; break
                        switch (p->hClass){
                        cls(NV01_ROOT_CLIENT);
                        cls(NV01_DEVICE_0);
                        cls(NV01_EVENT_OS_EVENT);
                        cls(NV20_SUBDEVICE_0);
                        cls(TURING_USERMODE_A);
                        cls(FERMI_VASPACE_A);
                        cls(KEPLER_CHANNEL_GROUP_A);
                        cls(FERMI_CONTEXT_SHARE_A);
                        cls(AMPERE_CHANNEL_GPFIFO_A);
                        cls(GT200_DEBUGGER);
                        cls(NV50_P2P);
                        cls(VOLTA_USERMODE_A);
                        cls(NV50_MEMORY_VIRTUAL);
                        cls(NV01_MEMORY_LOCAL_USER);
                        cls(NV01_MEMORY_SYSTEM);
                        cls(NV50_THIRD_PARTY_P2P);
                        cls(NV_CONFIDENTIAL_COMPUTE);
                        cls(NV2081_BINAPI);
                        cls(PASCAL_DMA_COPY_A);
                        cls(TURING_DMA_COPY_A);
                        cls(AMPERE_DMA_COPY_A);
                        cls(AMPERE_DMA_COPY_B);
                        cls(HOPPER_DMA_COPY_A);
                        cls(MAXWELL_DMA_COPY_A);
                        cls(ADA_COMPUTE_A);
                        cls(AMPERE_COMPUTE_B);
                        cls(NVC4B7_VIDEO_ENCODER);
                        cls(NVB4B7_VIDEO_ENCODER);
                        cls(NVC7B7_VIDEO_ENCODER);
                        cls(NVC9B7_VIDEO_ENCODER);
                        cls(NVB8B0_VIDEO_DECODER);
                        cls(NVC4B0_VIDEO_DECODER);
                        cls(NVC6B0_VIDEO_DECODER);
                        cls(NVC7B0_VIDEO_DECODER);
                        cls(NVC9B0_VIDEO_DECODER);
                        }
                        printf("ioctl(nvidiactl, NV_ESC_RM_ALLOC, params) = %d\n", ret);
                        printf("\thRoot: %x hObjectParent: %x hObjectNew: %x hClass: %x pAllocParms: %p status: 0x%x\n", p->hRoot, p->hObjectParent, p->hObjectNew,
                                p->hClass, p->pAllocParms, p->status);
                        printf("\t\t%s: ", cls_string);

                        if (p->hClass == TURING_USERMODE_A) usermode_map_pending = true;

                        if (p->hClass == NV01_ROOT_CLIENT) {
                                NV_BSP_ALLOCATION_PARAMETERS *pAllocParams = (NV_BSP_ALLOCATION_PARAMETERS *)p->pAllocParms;

                                printf("NvHandle: %x\n", p->hObjectNew);
                        } else if (p->pAllocParms != NULL) {
                                if (p->hClass == NV20_SUBDEVICE_0){
                                        NV2080_ALLOC_PARAMETERS *pAllocParams = (NV2080_ALLOC_PARAMETERS*)p->pAllocParms;

                                        printf("subDeviceId %x\n", pAllocParams->subDeviceId);
                                } else if (p->hClass == AMPERE_DMA_COPY_B || p->hClass == PASCAL_DMA_COPY_A || p->hClass == TURING_DMA_COPY_A ||
                                        p->hClass == AMPERE_DMA_COPY_A || p->hClass == HOPPER_DMA_COPY_A || p->hClass == MAXWELL_DMA_COPY_A){
                                        NVB0B5_ALLOCATION_PARAMETERS *pAllocParams = (NVB0B5_ALLOCATION_PARAMETERS *)p->pAllocParms;

                                        printf("version %x engineType %x\n", pAllocParams->version, pAllocParams->engineType);
                                } else if (p->hClass == ADA_COMPUTE_A || p->hClass == AMPERE_COMPUTE_B) {
                                        NV_GR_ALLOCATION_PARAMETERS *pAllocParams = (NV_GR_ALLOCATION_PARAMETERS*)p->pAllocParms;

                                        printf("version %x flags %x size %x caps %x\n", pAllocParams->version, pAllocParams->flags,
                                                pAllocParams->size, pAllocParams->caps);
                                } else if (p->hClass ==NVB8B0_VIDEO_DECODER || p->hClass == NVC4B0_VIDEO_DECODER || p->hClass == NVC6B0_VIDEO_DECODER ||
                                        p->hClass == NVC7B0_VIDEO_DECODER || p->hClass == NVC9B0_VIDEO_DECODER){
                                        NV_BSP_ALLOCATION_PARAMETERS *pAllocParams = (NV_BSP_ALLOCATION_PARAMETERS *)p->pAllocParms;

                                        printf("size: %x prohibitMultipleInstances %x engineInstance %x\n", pAllocParams->size, pAllocParams->prohibitMultipleInstances,
                                                pAllocParams->engineInstance);
                                } else if (p->hClass ==NVC4B7_VIDEO_ENCODER || p->hClass == NVB4B7_VIDEO_ENCODER || p->hClass == NVC7B7_VIDEO_ENCODER ||
                                        p->hClass == NVC9B7_VIDEO_ENCODER){
                                        NV_MSENC_ALLOCATION_PARAMETERS *pAllocParams = (NV_MSENC_ALLOCATION_PARAMETERS*)p->pAllocParms;

                                        printf("size: %x prohibitMultipleInstances %x engineInstance %x\n", pAllocParams->size, pAllocParams->prohibitMultipleInstances,
                                                pAllocParams->engineInstance);
                                } else if (p->hClass == KEPLER_CHANNEL_GROUP_A) {
                                        NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *pAllocParams = (NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *)p->pAllocParms;
                                        printf("hObjectError: %x ", pAllocParams->hObjectError);
                                        printf("hObjectEccError: %x ", pAllocParams->hObjectEccError);
                                        printf("hVASpace: %x ", pAllocParams->hVASpace);
                                        /* engineType defined: src/common/sdk/nvidia/inc/class/cl2080_notification.h */
                                        printf("engineType: %x ", pAllocParams->engineType);
                                        printf("bIsCallingContextVgpuPlugin: %d\n", pAllocParams->bIsCallingContextVgpuPlugin);
                                } else if (p->hClass == NV50_P2P) {
                                        NV503B_ALLOC_PARAMETERS *pAllocParams = (NV503B_ALLOC_PARAMETERS*)p->pAllocParms;

                                        printf("mailboxBar1Addr %llx ~ %x ", pAllocParams->mailboxBar1Addr, pAllocParams->mailboxTotalSize);
                                        printf("l2pBar1P2PDmaInfo %llx  ~ %llx ", pAllocParams->l2pBar1P2PDmaInfo.dma_address,  pAllocParams->l2pBar1P2PDmaInfo.dma_size);
                                        printf("p2lBar1P2PDmaInfo %llx  ~ %llx\n", pAllocParams->p2lBar1P2PDmaInfo.dma_address,  pAllocParams->p2lBar1P2PDmaInfo.dma_size);
                                } else if (p->hClass == FERMI_CONTEXT_SHARE_A) {
                                        NV_CTXSHARE_ALLOCATION_PARAMETERS *pAllocParams = (NV_CTXSHARE_ALLOCATION_PARAMETERS *)p->pAllocParms;
                                        printf("hVASpace: %x ", pAllocParams->hVASpace);
                                        printf("flags: %x ", pAllocParams->flags);
                                        printf("subctxId: %x\n", pAllocParams->subctxId);
                                } else if (p->hClass == FERMI_VASPACE_A) {
                                        NV_VASPACE_ALLOCATION_PARAMETERS *pAllocParams = (NV_VASPACE_ALLOCATION_PARAMETERS *)p->pAllocParms;
                                        printf("index: %x ", pAllocParams->index);
                                        printf("flags: %x ", pAllocParams->flags);
                                        printf("vaSize: %llx ", pAllocParams->vaSize);
                                        printf("vaStartInternal: %llx ", pAllocParams->vaStartInternal);
                                        printf("vaLimitInternal: %llx ", pAllocParams->vaLimitInternal);
                                        printf("bigPageSize: %x ", pAllocParams->bigPageSize);
                                        printf("vaBase: %llx\n", pAllocParams->vaBase);
                                } else if (p->hClass == NV20_SUBDEVICE_0) {
                                        //pprint((NV2080_ALLOC_PARAMETERS *)p->pAllocParms);
                                } else if (p->hClass == NV01_DEVICE_0) {
                                        NV0080_ALLOC_PARAMETERS *pAllocParams = (NV0080_ALLOC_PARAMETERS *)p->pAllocParms;
                                        printf("deviceId: %x", pAllocParams->deviceId);
                                        printf("hClientShare: %x ", pAllocParams->hClientShare);
                                        printf("hTargetClient: %x ", pAllocParams->hTargetClient);
                                        printf("hTargetDevice: %x ", pAllocParams->hTargetDevice);
                                        printf("flags: %x ", pAllocParams->flags);
                                        printf("vaSpaceSize: %lx ", (unsigned long)pAllocParams->vaSpaceSize);
                                        printf("vaStartInternal: %llx ", pAllocParams->vaStartInternal);
                                        printf("vaLimitInternal: %llx ", pAllocParams->vaLimitInternal);
                                        printf("vaMode: %x\n", pAllocParams->vaMode);
                                } else if (p->hClass == NV50_MEMORY_VIRTUAL) {
                                        NV_MEMORY_ALLOCATION_PARAMS *pAllocParams = (NV_MEMORY_ALLOCATION_PARAMS *)p->pAllocParms;
                                        printf("size: %lx ", (unsigned long)pAllocParams->size);
                                        printf("offset: %llx\n", pAllocParams->offset);
                                } else if (p->hClass == AMPERE_CHANNEL_GPFIFO_A) {
                                        NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS *pAllocParams = (NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS *)p->pAllocParms;

                                        printf("gpFifoOffset: %llx (num %ld) ", pAllocParams->gpFifoOffset, gpFifoOffsets.size());
                                        gpFifoOffsets[p->hObjectNew] = (uint32_t*)pAllocParams->gpFifoOffset;
                                        printf("hObjectError: %x\n", pAllocParams->hObjectError);
                                        printf("\t\t\thObjectBuffer: %x\n", pAllocParams->hObjectBuffer);
                                        printf("\t\t\tgpFifoOffset: %llx\n", pAllocParams->gpFifoOffset);
                                        printf("\t\t\tgpFifoEntries: %x\n", pAllocParams->gpFifoEntries);
                                        printf("\t\t\thContextShare: %x\n", pAllocParams->hContextShare);
                                        printf("\t\t\tflags: %x\n", pAllocParams->flags);
                                        printf("\t\t\thVASpace: %x\n", pAllocParams->hVASpace);
                                        for (int i = 0; i < NVOS_MAX_SUBDEVICES; i++) {
                                                if (pAllocParams->hUserdMemory[i] > 0) {
                                                        printf("\t\t\t\thUserdMemory[%d]: %x\n", i, pAllocParams->hUserdMemory[i]);
                                                        printf("\t\t\t\tuserdOffset[%d]: %llx\n", i, pAllocParams->userdOffset[i]);
                                                }
                                        }
                                        printf("\t\t\tengineType: %x\n", pAllocParams->engineType);
                                        printf("\t\t\tcid: %x\n", pAllocParams->cid);
                                        printf("\t\t\tsubDeviceId: %x\n", pAllocParams->subDeviceId);
                                        printf("\t\t\thObjectEccError: %x\n", pAllocParams->hObjectEccError);
                                        printf("\t\t\thPhysChannelGroup: %x\n", pAllocParams->hPhysChannelGroup);
                                        printf("\t\t\tinternalFlags: %x\n", pAllocParams->internalFlags);
                                        printf("\t\t\tProcessID: %x\n", pAllocParams->ProcessID);
                                        printf("\t\t\tSubProcessID: %x\n", pAllocParams->SubProcessID);

                                        #define DMP(x) printf("\t\t\t" #x "%llx %llx %d %d\n", x.base, x.size, x.addressSpace, x.cacheAttrib);
                                        DMP(pAllocParams->instanceMem);
                                        DMP(pAllocParams->userdMem);
                                        DMP(pAllocParams->ramfcMem);
                                        DMP(pAllocParams->mthdbufMem);
                                        DMP(pAllocParams->errorNotifierMem);
                                        DMP(pAllocParams->eccErrorNotifierMem);
                                } else if (p->hClass == NV01_MEMORY_LOCAL_USER) {
                                        NVOS32_PARAMETERS *pAllocParms  = (NVOS32_PARAMETERS *)(p->pAllocParms);

                                        printf("function: %x ", pAllocParms->function);
                                        printf("hRoot: %x ", pAllocParms->hRoot);
                                        printf("hObjectParent: %x ", pAllocParms->hObjectParent);
                                        printf("hVASpace: %x\n", pAllocParms->hVASpace);
                                        auto asz = pAllocParms->data.AllocSize;
                                        if (pAllocParms->function == NVOS32_FUNCTION_ALLOC_SIZE) {
                                                printf("\t\t\t\towner: %x ", asz.owner);
                                                printf("hMemory: %x ", asz.hMemory);
                                                printf("type: %d ", asz.type);
                                                printf("flags: %x ", asz.flags);
                                                if (asz.height != 0 || asz.width != 0) {
                                                        printf("height: %d ", asz.height);
                                                        printf("width: %d ", asz.width);
                                                }
                                                printf("size: %llx (%.2f MB) ", asz.size, asz.size/1e6);
                                                printf("offset: %llx ", asz.offset);
                                                printf("address: %p\n", asz.address);
                                        }
                                } else {
                                        printf("\n");
                                }
                        } else {
                                printf("\n");
                        }
                } break;
                case NV_ESC_RM_MAP_MEMORY: {
                        nv_ioctl_nvos33_parameters_with_fd *pfd = (nv_ioctl_nvos33_parameters_with_fd *)argp;
                        NVOS33_PARAMETERS *p = (NVOS33_PARAMETERS *)argp;
                        printf("ioctl(nvidiactl, NV_ESC_RM_MAP_MEMORY, params) = %d\n", ret);
                        printf("\thClient: %x hDevice: %x hMemory: %x pLinearAddress: %p offset: %llx length %llx status %x flags %x fd %d\n",
                                p->hClient, p->hDevice, p->hMemory, p->pLinearAddress, p->offset, p->length, p->status, p->flags, pfd->fd);
                } break;
                case NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO:
                        printf("ioctl(nvidiactl, NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO, params) = %d\n", ret);
                        break;
                case NV_ESC_RM_VID_HEAP_CONTROL: {
                        NVOS32_PARAMETERS *p = (NVOS32_PARAMETERS *)argp;

                        printf("ioctl(nvidiactl, NV_ESC_RM_VID_HEAP_CONTROL, params) = %d\n", ret);
                        printf("\tfunction: %x ", p->function);
                        printf("hRoot: %x ", p->hRoot);
                        printf("hObjectParent: %x ", p->hObjectParent);
                        printf("hVASpace: %x\n", p->hVASpace);
                        auto asz = p->data.AllocSize;
                        if (p->function == NVOS32_FUNCTION_ALLOC_SIZE) {
                                printf("\t\towner: %x ", asz.owner);
                                printf("hMemory: %x ", asz.hMemory);
                                printf("type: %d ", asz.type);
                                printf("flags: %x ", asz.flags);
                                if (asz.height != 0 || asz.width != 0) {
                                        printf("height: %d ", asz.height);
                                        printf("width: %d ", asz.width);
                                }
                                printf("size: %llx (%.2f MB) ", asz.size, asz.size/1e6);
                                printf("offset: %llx ", asz.offset);
                                printf("address: %p\n", asz.address);
                        }
                } break;
                default:
                        printf("ioctl(nvidiactl, %lx, params) = %d\n", request, ret);
                        break;
                }
        } else if (files.count(filedes)) {
                if (strcmp(files[filedes].c_str(), "/dev/nvidia-uvm") == 0) {
                        ret = my_ioctl(filedes, request, argp);
                        switch (request) {
                        case UVM_INITIALIZE: {
                                UVM_INITIALIZE_PARAMS *p = (UVM_INITIALIZE_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_INITIALIZE, params) = %d\n", ret);
                                printf("\tflags:%lx rmStatus:%x\n", (unsigned long)p->flags, p->rmStatus);
                                break;
                        }
                        case UVM_PAGEABLE_MEM_ACCESS: {
                                UVM_PAGEABLE_MEM_ACCESS_PARAMS *p = (UVM_PAGEABLE_MEM_ACCESS_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_PAGEABLE_MEM_ACCESS_PARAMS, params) = %d\n", ret);
                                printf("\tpageableMemAccess:%x rmStatus:%x\n", p->pageableMemAccess, p->rmStatus);
                                break;
                        }
                        case UVM_REGISTER_GPU: {
                                UVM_REGISTER_GPU_PARAMS *p = (UVM_REGISTER_GPU_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_REGISTER_GPU, params) = %d\n", ret);
                                printf("\tgpu_uuid:%x %x %x %x %x %x %x %x rmCtrlFd:%x hClient:%x hSmcPartRef:%x rmStatus:%x\n",
                                        p->gpu_uuid.uuid[0], p->gpu_uuid.uuid[1], p->gpu_uuid.uuid[2], p->gpu_uuid.uuid[3],
                                        p->gpu_uuid.uuid[4], p->gpu_uuid.uuid[5], p->gpu_uuid.uuid[6], p->gpu_uuid.uuid[7],
                                        p->rmCtrlFd, p->hClient, p->hSmcPartRef, p->rmStatus);
                                break;
                        }
                        case UVM_CREATE_RANGE_GROUP: {
                                UVM_CREATE_RANGE_GROUP_PARAMS *p = (UVM_CREATE_RANGE_GROUP_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_CREATE_RANGE_GROUP, params) = %d\n", ret);
                                printf("\trangeGroupId: %llx rmStatus: %x\n", p->rangeGroupId, p->rmStatus);
                                break;
                        }
                        case UVM_MAP_EXTERNAL_ALLOCATION: {
                                UVM_MAP_EXTERNAL_ALLOCATION_PARAMS *p = (UVM_MAP_EXTERNAL_ALLOCATION_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_MAP_EXTERNAL_ALLOCATION, params) = %d\n", ret);
                                printf("\tbase:%llx length:%llx offset:%llx gpuAttributesCount: %ld rmCtrlFd: %x hClient: %x hMemory: %x rmStatus:%x\n",
                                                p->base, p->length, p->offset,
                                                (unsigned long)p->gpuAttributesCount,
                                                p->rmCtrlFd,
                                                p->hClient, p->hMemory,
                                                p->rmStatus);
                                for (int i =0; i < p->gpuAttributesCount; i++) {
                                        printf("\t\tUVM(%d) gpuMappingType:%x gpuCachingType:%x gpuFormatType: %x gpuElementBits: %x gpuCompressionType: %x\n", i,
                                                p->perGpuAttributes[i].gpuMappingType,
                                                p->perGpuAttributes[i].gpuCachingType,
                                                p->perGpuAttributes[i].gpuFormatType,
                                                p->perGpuAttributes[i].gpuElementBits,
                                                p->perGpuAttributes[i].gpuCompressionType
                                                );
                                }
                                break;
                        }
                        case UVM_REGISTER_CHANNEL: {
                                UVM_REGISTER_CHANNEL_PARAMS *p = (UVM_REGISTER_CHANNEL_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_REGISTER_CHANNEL_PARAMS, params) = %d\n", ret);
                                printf("\trmCtrlFd:%x hClient:%x hChannel:%x base: %llx length: %lx rmStatus:%x\n",
                                        p->rmCtrlFd, p->hClient, p->hChannel,
                                        p->base, (unsigned long)p->length,
                                        p->rmStatus);
                                break;
                        }
                        case UVM_REGISTER_GPU_VASPACE: {
                                UVM_REGISTER_GPU_VASPACE_PARAMS *p = (UVM_REGISTER_GPU_VASPACE_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_REGISTER_GPU_VASPACE_PARAMS, params) = %d\n", ret);
                                printf("\tgpu_uuid: rmCtrlFd:%x hClient:%x hVaSpace:%x rmStatus:%x\n", p->rmCtrlFd, p->hClient, p->hVaSpace, p->rmStatus);
                                break;
                        }
                        case UVM_CREATE_EXTERNAL_RANGE: {
                                UVM_CREATE_EXTERNAL_RANGE_PARAMS *p = (UVM_CREATE_EXTERNAL_RANGE_PARAMS *)argp;

                                printf("ioctl(nvidia-uvm, UVM_CREATE_EXTERNAL_RANGE, params) = %d\n", ret);
                                printf("\tbase:%llx length:%llx\n", p->base, p->length);
                                break;
                        }
                        case UVM_ENABLE_PEER_ACCESS: {
                                printf("ioctl(nvidia-uvm, UVM_ENABLE_PEER_ACCESS, params) = %d\n", ret);
                                break;
                        }
                        case UVM_FREE: {
                                printf("ioctl(nvidia-uvm, UVM_FREE, params) = %d\n", ret);
                                break;
                        }
                        case UVM_MM_INITIALIZE:
                                printf("ioctl(nvidia-uvm, UVM_MM_INITIALIZE, params) = %d\n", ret);
                                break;
                        case UVM_SET_RANGE_GROUP:
                                printf("ioctl(nvidia-uvm, UVM_SET_RANGE_GROUP, params) = %d\n", ret);
                                break;
                        case UVM_VALIDATE_VA_RANGE:
                                printf("ioctl(nvidia-uvm, UVM_VALIDATE_VA_RANGE, params) = %d\n", ret);
                                break;
                        case UVM_DISABLE_READ_DUPLICATION: {
                                UVM_DISABLE_READ_DUPLICATION_PARAMS *p = (UVM_DISABLE_READ_DUPLICATION_PARAMS *)argp;
                                printf("ioctl(nvidia-uvm, UVM_DISABLE_READ_DUPLICATION, params) = %d\n", ret);
                                printf("\tparams: base 0x%llx length 0x%llx\n", p->requestedBase, p->length);
                                break;
                        }
                        case UVM_UNSET_ACCESSED_BY: {
                                UVM_UNSET_ACCESSED_BY_PARAMS *p = (UVM_UNSET_ACCESSED_BY_PARAMS *)argp;
                                printf("ioctl(nvidia-uvm, UVM_UNSET_ACCESSED_BY, params) = %d\n", ret);
                                printf("\tparams: base 0x%llx length 0x%llx\n", p->requestedBase, p->length);
                                break;
                        }
                        case UVM_SET_ACCESSED_BY: {
                                UVM_SET_ACCESSED_BY_PARAMS *p = (UVM_SET_ACCESSED_BY_PARAMS *)argp;
                                printf("ioctl(nvidia-uvm, UVM_SET_ACCESSED_BY, params) = %d\n", ret);
                                printf("\tparams: base 0x%llx length 0x%llx\n", p->requestedBase, p->length);
                                break;
                        }
                        case UVM_SET_PREFERRED_LOCATION: {
                                UVM_SET_PREFERRED_LOCATION_PARAMS *p = (UVM_SET_PREFERRED_LOCATION_PARAMS *)argp;
                                printf("ioctl(nvidia-uvm, UVM_SET_PREFERRED_LOCATION, params) = %d\n", ret);
                                printf("\tparams: base 0x%llx length 0x%llx\n", p->requestedBase, p->length);
                                break;
                        }
                        case UVM_UNSET_PREFERRED_LOCATION: {
                                UVM_UNSET_PREFERRED_LOCATION_PARAMS *p = (UVM_UNSET_PREFERRED_LOCATION_PARAMS *)argp;
                                printf("ioctl(nvidia-uvm, UVM_UNSET_PREFERRED_LOCATION, params) = %d\n", ret);
                                printf("\tparams: base 0x%llx length 0x%llx\n", p->requestedBase, p->length);
                                break;
                        }
                        case UVM_ENABLE_READ_DUPLICATION: {
                                UVM_ENABLE_READ_DUPLICATION_PARAMS *p = (UVM_ENABLE_READ_DUPLICATION_PARAMS *)argp;
                                printf("ioctl(nvidia-uvm, UVM_ENABLE_READ_DUPLICATION, params) = %d\n", ret);
                                printf("\tparams: base 0x%llx length 0x%llx\n", p->requestedBase, p->length);
                                break;
                        }
                        case UVM_ALLOW_MIGRATION_RANGE_GROUPS:
                                printf("ioctl(nvidia-uvm, UVM_ALLOW_MIGRATION_RANGE_GROUPS, params) = %d\n", ret);
                                break;
                        default: {
                                printf("ioctl(nvidia-uvm, 0x%lx %ld, params) = %d\n", request, request, ret);
                                break;
                        }
                        }
                } else {
                        //printf("0x%x %p\n", request, argp);
                        ret = my_ioctl(filedes, request, argp);
                }
        }
        printf("\n");

        return ret;
}
}