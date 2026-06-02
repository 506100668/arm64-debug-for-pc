#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <android/log.h>

#include <linux/elf.h>
#include <asm/ptrace.h>

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_FPREGS
#define NT_ARM_FPREGS 0x403
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif
#ifndef TRAP_TRACE
#define TRAP_TRACE 2
#endif

#define HW_BP_MAX 16
#define HW_WP_MAX 16
#define SW_BP_MAX 64
#define MEM_BP_MAX 128
#define MEM_PAGE_MAX 256
#define MEM_PAGE_BP_LINK_MAX 512
#define MEM_HIT_PAGE_MAX 64
#define MEM_PAGE_RANGE_MAX 16
#define STACK_DUMP_WORDS 8
#define DISASM_CONTEXT 8
#define VIEW_LEFT_WIDTH 84
#define VIEW_RIGHT_WIDTH 84
#define VIEW_MAX_LINES 32

#define DBGBCR_ENABLE      (1UL << 0)
#define DBGBCR_PMC_EL0     (2UL << 1)
#define DBGBCR_BAS         (0xful << 5)
#define DBGBCR_BT_INST     (0UL << 14)

typedef struct {
    unsigned long addr;
    uint32_t ctrl;
    int in_use;
} my_breakpoint_t;

typedef struct {
    unsigned long addr;
    unsigned long addr_raw;
    uint32_t ctrl;
    int in_use;
    int mode;
} my_watchpoint_t;

typedef struct {
    unsigned long addr;
    uint32_t orig_insn;
    int in_use;
    int mode;
    int backend_wp_idx;
} my_soft_breakpoint_t;

typedef struct {
    unsigned long addr;
    int mode;
    int in_use;
} my_mem_breakpoint_t;

typedef struct {
    unsigned long page;
    unsigned long map_start;
    unsigned long map_end;
    int range_count;
    unsigned long range_start[MEM_PAGE_RANGE_MAX];
    unsigned long range_end[MEM_PAGE_RANGE_MAX];
    int orig_prot;
    int nx_active;
    int in_use;
} my_mem_page_t;

typedef struct {
    int bp_idx;
    int page_idx;
    int in_use;
} my_mem_page_bp_link_t;

typedef struct {
    int page_idx;
    unsigned long fault_pc;
    int in_use;
} my_mem_hit_page_t;

static my_breakpoint_t my_breakpoints[HW_BP_MAX] = {0};
static my_watchpoint_t my_watchpoints[HW_WP_MAX] = {0};
static my_soft_breakpoint_t my_soft_breakpoints[SW_BP_MAX] = {0};
static my_mem_breakpoint_t my_mem_breakpoints[MEM_BP_MAX] = {0}; // 断点表
static my_mem_page_t my_mem_pages[MEM_PAGE_MAX] = {0};
static my_mem_page_bp_link_t my_mem_page_bp_links[MEM_PAGE_BP_LINK_MAX] = {0}; // 页和断点关联表
static my_mem_hit_page_t my_mem_hit_pages[MEM_HIT_PAGE_MAX] = {0}; // 命中的页表
static pid_t traced_tids[1024] = {0};
static int traced_tid_count = 0;
static pid_t interactive_tid = 0;
static int interaction_threads_paused = 0;
static pid_t target_pid = 0;
static int hw_bp_slots = -1;
static int hw_wp_slots = -1;
static char disasm_tool[32] = {0};
static int capstone_ready = -1;
static void *capstone_lib = NULL;
static size_t capstone_handle = 0;

typedef int cs_err_t;
typedef int cs_arch_t;
typedef size_t cs_mode_t;
typedef size_t csh_t;
typedef struct cs_insn_t {
    unsigned int id;
    uint64_t address;
    uint16_t size;
    uint8_t bytes[24];
    char mnemonic[32];
    char op_str[160];
    void *detail;
} cs_insn_t;

static cs_err_t (*p_cs_open)(cs_arch_t arch, cs_mode_t mode, csh_t *handle) = NULL;
static size_t (*p_cs_disasm)(csh_t handle, const uint8_t *code, size_t code_size, uint64_t address, size_t count, cs_insn_t **insn) = NULL;
static void (*p_cs_free)(cs_insn_t *insn, size_t count) = NULL;
static cs_err_t (*p_cs_close)(csh_t *handle) = NULL;
static cs_err_t (*p_cs_option)(csh_t handle, size_t type, size_t value) = NULL;
static int keystone_ready = -1;
static void *keystone_lib = NULL;
static size_t keystone_handle = 0;
typedef int ks_err_t;
typedef size_t ks_arch_t;
typedef size_t ks_mode_t;
typedef size_t ks_engine_t;
static ks_err_t (*p_ks_open)(ks_arch_t arch, ks_mode_t mode, ks_engine_t **ks) = NULL;
static int (*p_ks_asm)(ks_engine_t *ks, const char *assembly, uint64_t address, unsigned char **encode, size_t *size, size_t *count) = NULL;
static void (*p_ks_free)(unsigned char *p) = NULL;
static ks_err_t (*p_ks_close)(ks_engine_t *ks) = NULL;

static int stepping_bp_active = 0;
static int stepping_bp_idx = -1;
static unsigned long stepping_bp_addr = 0;
static int stepping_bp_resume = 0;
static int stepping_soft_active = 0;
static int stepping_soft_idx = -1;
static unsigned long stepping_soft_addr = 0;
static int stepping_soft_resume = 0;
static int stepping_soft_step_over = 0;
static pid_t stepping_soft_tid = 0;
static int current_soft_hit_idx = -1;
static unsigned long current_soft_hit_addr = 0;
static int stepping_watch_active = 0;
static int stepping_watch_idx = -1;
static int stepping_watch_mode = 0;
static unsigned long stepping_watch_addr = 0;
static int stepping_watch_resume = 0;
static pid_t stepping_watch_tid = 0;
static int current_watch_hit_idx = -1;
static unsigned long current_watch_hit_addr = 0;
static int stepping_mem_active = 0;
static pid_t stepping_mem_tid = 0;

static int step_over_active = 0;
static int step_over_temp_bp_idx = -1;
static int step_over_source_bp_idx = -1;
static int step_over_source_soft_bp_idx = -1;
static unsigned long step_over_source_bp_addr = 0;
static unsigned long step_over_return_addr = 0;

static int attach_process(pid_t pid);
static int detach_process(pid_t pid);
static unsigned long get_pc(pid_t pid);
static int set_pc(pid_t pid, unsigned long pc);
static int continue_execution(pid_t pid, int signo);
static int single_step(pid_t pid);
static int set_hardware_breakpoint(pid_t pid, unsigned long addr, int force_idx);
static int clear_breakpoint(pid_t pid, int idx);
static int clear_all_breakpoints(pid_t pid);
static int refresh_hw_bp_slots(pid_t pid);
static int sync_hw_breakpoints(pid_t pid);
static int refresh_hw_wp_slots(pid_t pid);
static int sync_hw_watchpoints(pid_t pid);
static int sync_hw_watchpoints_for_thread(pid_t pid, int disable_idx);
static int sync_hw_breakpoints_all_threads(pid_t pid);
static int sync_hw_watchpoints_all_threads(pid_t pid);
static int ensure_all_threads_attached_for_debug(pid_t pid);
static int load_thread_ids(pid_t pid, pid_t *tids, int max_tids);
static int find_traced_tid(pid_t tid);
static void add_traced_tid(pid_t tid);
static void remove_traced_tid(pid_t tid);
static int set_ptrace_options(pid_t tid);
static int ensure_thread_attached_for_debug(pid_t tid, int auto_continue);
static int stop_thread_for_sync(pid_t tid);
static void pause_other_traced_threads(pid_t current_tid);
static void resume_other_traced_threads(pid_t current_tid);
static void detach_all_traced_threads(void);
static unsigned long peek_data(pid_t pid, unsigned long addr);
static int peek_data_quiet(pid_t pid, unsigned long addr, unsigned long *out);
static uint8_t read_u8(pid_t pid, unsigned long addr);
static uint32_t read_u32(pid_t pid, unsigned long addr);
static int write_u8(pid_t pid, unsigned long addr, uint8_t val);
static int write_u32(pid_t pid, unsigned long addr, uint32_t val);
static int write_value_le(pid_t pid, unsigned long addr, unsigned long value, int size);
static int get_regs(pid_t pid, struct user_pt_regs *regs);
static int set_regs(pid_t pid, const struct user_pt_regs *regs);
static void print_registers(pid_t pid);
static long sign_extend(unsigned long val, int bits);
static int parse_u64(const char *s, unsigned long *v);
static int parse_addr_expr(pid_t pid, const char *s, unsigned long *v);
static int set_register_by_name(pid_t pid, const char *name, unsigned long value);
static int find_breakpoint_by_addr(unsigned long addr);
static int find_watchpoint_by_addr(unsigned long addr);
static int find_soft_breakpoint_by_addr(unsigned long addr);
static int step_past_breakpoint(pid_t pid, int bp_idx, unsigned long bp_addr, int resume_after_step);
static int step_past_soft_breakpoint(pid_t pid, int bp_idx, unsigned long bp_addr, int resume_after_step, int step_over_mode);
static int step_past_watchpoint(pid_t pid, int wp_idx, int resume_after_step);
static void list_breakpoints(void);
static void list_watchpoints(void);
static void list_soft_breakpoints(void);
static int set_soft_breakpoint(pid_t pid, unsigned long addr, int mode);
static int clear_soft_breakpoint(pid_t pid, int idx);
static int clear_all_soft_breakpoints(pid_t pid);
static int set_watchpoint(pid_t pid, unsigned long addr, int force_idx);
static int set_watchpoint_mode(pid_t pid, unsigned long addr, int mode, int force_idx);
static int clear_watchpoint(pid_t pid, int idx);
static int clear_all_watchpoints(pid_t pid);
static unsigned long page_align_down(unsigned long addr);
static unsigned long page_align_up(unsigned long addr);
static int query_map_prot(pid_t pid, unsigned long addr, unsigned long *start_out, unsigned long *end_out, int *prot_out);
static unsigned long page_align_up(unsigned long addr);
static int mem_page_fill_exec_alias_ranges(my_mem_page_t *slot, pid_t maps_pid, unsigned long addr, unsigned long apply_lo, unsigned long apply_hi);
static int mem_page_apply_prot_ex(pid_t tid, my_mem_page_t *pg, int new_prot, int rollback_prot);
static int remote_mprotect_single(pid_t tid, unsigned long addr, unsigned long len, int prot);
static int find_mem_breakpoint_by_addr(unsigned long addr);
static int find_mem_page_by_page(unsigned long page);
static int find_mem_page_containing_addr(unsigned long addr);
static int find_mem_page_link(int bp_idx, int page_idx);
static int count_mem_links_for_page(int page_idx);
static int memory_page_has_bp_addr(int page_idx, unsigned long addr);
static int mem_page_compute_trap_prot(int page_idx);
static int set_memory_breakpoint(pid_t pid, unsigned long addr, int mode);
static int clear_memory_breakpoint(pid_t pid, int idx);
static int clear_all_memory_breakpoints(pid_t pid);
static void list_memory_breakpoints(void);
static void membp_trace(const char *fmt, ...);
static int find_memory_page_for_fault(unsigned long fault_addr);
static void membp_log_active_pages(const char *reason);
static void clear_memory_hit_pages(void);
static int is_call_instruction(uint32_t insn);
static int init_capstone(void);
static int init_keystone(void);
static uint32_t get_brk_instruction(void);
static int assemble_and_write(pid_t pid, unsigned long addr, const char *asm_text);
static int capstone_disassemble(pid_t pid, unsigned long addr, int lines, unsigned long center, int mark_center);
static int init_disasm_tool(void);
static int external_disassemble(pid_t pid, unsigned long addr, int lines, unsigned long center, int mark_center);
static int llvm_disassemble_collect(pid_t pid, unsigned long addr, int lines, unsigned long center, int mark_center, char out[][VIEW_LEFT_WIDTH], int max_lines, int *out_count);
static void decode_arm64(uint32_t insn, unsigned long pc, char *out, size_t out_size);
static void disassemble_window(pid_t pid, unsigned long center, int before, int after);
static void disassemble_from(pid_t pid, unsigned long addr, int lines);
static void disassemble_from_pkt(pid_t pid, unsigned long addr, int lines);
static void dump_qword(pid_t pid, unsigned long addr, int lines);
static void dump_dword(pid_t pid, unsigned long addr, int lines);
static void dump_word(pid_t pid, unsigned long addr, int lines);
static void dump_byte(pid_t pid, unsigned long addr, int lines);
static void show_help(void);
static void list_modules(pid_t pid);
static void list_threads(pid_t pid);
static void clear_screen(void);
static void emit_packet_end(void);
static int read_line_file(const char *path, char *buf, size_t size);
static int parse_stat_startstack(const char *stat_line, unsigned long *startstack);
static int parse_stat_field(const char *stat_line, int field_no, unsigned long *value);
static int parse_syscall_pc_sp(const char *line, unsigned long *pc, unsigned long *sp);
static int describe_address(pid_t pid, unsigned long addr, char *out, size_t out_size);
static int query_module_for_addr(pid_t pid, unsigned long addr, unsigned long *base_out, unsigned long *end_out, char *name_out, size_t name_size);
static void format_u32_bytes(uint32_t insn, char *out, size_t out_size);
static void render_debug_dashboard(pid_t pid);
static void print_callstack(pid_t pid, unsigned long fp, unsigned long lr, unsigned long pc);
static void handle_step_over(pid_t pid);
static void handle_step_into(pid_t pid);
static void handle_resume(pid_t pid);
static int any_mem_breakpoint_in_use(void);
static void handle_breakpoint_hit(pid_t pid);
static uint32_t fnv1a32_str(const char *s);
static void hex_encode_str(const char *in, char *out, size_t out_size);
static int run_debug_loop(void);
static int setup_tcp_stdio(void);

static unsigned long g_disasm_pkt_session = 1;

static void membp_trace(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, stdout);
    fflush(stdout);
    __android_log_write(ANDROID_LOG_INFO, "MEMBP", buf);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
unsigned long peek_data(pid_t pid, unsigned long addr) {
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    if (val == -1 && errno != 0) {
        perror("PTRACE_PEEKDATA");
        return 0;
    }
    return (unsigned long)val;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int peek_data_quiet(pid_t pid, unsigned long addr, unsigned long *out) {
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    if (val == -1 && errno != 0) return -1;
    *out = (unsigned long)val;
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
uint8_t read_u8(pid_t pid, unsigned long addr) {
    unsigned long aligned = addr & ~0x7UL;
    unsigned long data = 0;
    if (peek_data_quiet(pid, aligned, &data) == -1) return 0;
    int shift = (int)((addr & 0x7UL) * 8UL);
    return (uint8_t)((data >> shift) & 0xffU);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
uint32_t read_u32(pid_t pid, unsigned long addr) {
    unsigned long aligned = addr & ~0x7UL;
    unsigned long data = 0;
    if (peek_data_quiet(pid, aligned, &data) == -1) return 0;
    int shift = (int)((addr & 0x7UL) * 8UL);
    return (uint32_t)((data >> shift) & 0xffffffffU);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
uint16_t read_u16(pid_t pid, unsigned long addr) {
    unsigned long aligned = addr & ~0x7UL;
    unsigned long data = 0;
    if (peek_data_quiet(pid, aligned, &data) == -1) return 0;
    int shift = (int)((addr & 0x7UL) * 8UL);
    return (uint16_t)((data >> shift) & 0xffffU);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
unsigned long long read_u64(pid_t pid, unsigned long addr) {
    unsigned long data = 0;
    if (peek_data_quiet(pid, addr, &data) == -1) return 0;
    return (unsigned long long)data;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int write_u8(pid_t pid, unsigned long addr, uint8_t val) {
    unsigned long aligned = addr & ~0x7UL;
    unsigned long data = 0;
    if (peek_data_quiet(pid, aligned, &data) == -1) return -1;
    int shift = (int)((addr & 0x7UL) * 8UL);
    unsigned long mask = 0xffUL << shift;
    unsigned long new_data = (data & ~mask) | ((unsigned long)val << shift);
    if (ptrace(PTRACE_POKEDATA, pid, (void*)aligned, (void*)new_data) == -1) {
        perror("PTRACE_POKEDATA");
        return -1;
    }
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int write_u32(pid_t pid, unsigned long addr, uint32_t val) {
    unsigned long aligned = addr & ~0x7UL;
    unsigned long data = 0;
    if (peek_data_quiet(pid, aligned, &data) == -1) return -1;
    int shift = (int)((addr & 0x7UL) * 8UL);
    unsigned long mask = 0xffffffffUL << shift;
    unsigned long new_data = (data & ~mask) | ((unsigned long)val << shift);
    if (ptrace(PTRACE_POKEDATA, pid, (void*)aligned, (void*)new_data) == -1) {
        perror("PTRACE_POKEDATA");
        return -1;
    }
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int write_value_le(pid_t pid, unsigned long addr, unsigned long value, int size) {
    if (!(size == 1 || size == 2 || size == 4 || size == 8)) return -1;
    for (int i = 0; i < size; i++) {
        uint8_t b = (uint8_t)((value >> (8 * i)) & 0xffUL);
        if (write_u8(pid, addr + (unsigned long)i, b) == -1) return -1;
    }
    return 0;
}

// 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
int get_regs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) return -1;
    return 0;
}

// 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
int set_regs(pid_t pid, const struct user_pt_regs *regs) {
    struct user_pt_regs tmp = *regs;
    struct iovec iov = { .iov_base = &tmp, .iov_len = sizeof(tmp) };
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) return -1;
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int query_module_for_addr(pid_t pid, unsigned long addr, unsigned long *base_out, unsigned long *end_out, char *name_out, size_t name_size) {
    if (addr == 0) return -1;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[1024];
    char hit_name[512] = {0};
    int hit_named = 0;
    unsigned long hit_start = 0, hit_end = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[8] = {0}, dev[32] = {0}, name[512] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %511[^\n]", &start, &end, perms, &offset, dev, &inode, name);
        if (n < 6) continue;
        if (addr >= start && addr < end) {
            hit_start = start;
            hit_end = end;
            if (n == 7) {
                const char *mod = name;
                while (*mod == ' ' || *mod == '\t') mod++;
                if (*mod != '\0') {
                    snprintf(hit_name, sizeof(hit_name), "%s", mod);
                    hit_named = 1;
                }
            }
            break;
        }
    }
    if (hit_start == 0 && hit_end == 0) {
        fclose(fp);
        return -1;
    }
    unsigned long module_start = hit_start;
    unsigned long module_end = hit_end;
    if (hit_named) {
        rewind(fp);
        while (fgets(line, sizeof(line), fp)) {
            unsigned long start = 0, end = 0, offset = 0, inode = 0;
            char perms[8] = {0}, dev[32] = {0}, name[512] = {0};
            int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %511[^\n]", &start, &end, perms, &offset, dev, &inode, name);
            if (n != 7) continue;
            const char *mod = name;
            while (*mod == ' ' || *mod == '\t') mod++;
            if (strcmp(mod, hit_name) != 0) continue;
            if (start < module_start) module_start = start;
            if (end > module_end) module_end = end;
        }
    }
    const char *modname = hit_named ? hit_name : "[anon]";
    const char *base = strrchr(modname, '/');
    if (base) modname = base + 1;
    if (base_out) *base_out = module_start;
    if (end_out) *end_out = module_end;
    if (name_out && name_size > 0) {
        snprintf(name_out, name_size, "%s", modname);
    }
    fclose(fp);
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int describe_address(pid_t pid, unsigned long addr, char *out, size_t out_size) {
    unsigned long base = 0;
    char name[256] = {0};
    if (query_module_for_addr(pid, addr, &base, NULL, name, sizeof(name)) == -1) return -1;
    snprintf(out, out_size, "%s+0x%lx", name, addr - base);
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void format_u32_bytes(uint32_t insn, char *out, size_t out_size) {
    snprintf(out, out_size, "%02x %02x %02x %02x",
        (unsigned)(insn & 0xffU),
        (unsigned)((insn >> 8) & 0xffU),
        (unsigned)((insn >> 16) & 0xffU),
        (unsigned)((insn >> 24) & 0xffU));
}

// 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
void print_registers(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == 0) {
        printf("\n--- 通用寄存器 ---\n");
        for (int i = 0; i < 31; i++) {
            char mod[256] = {0};
            if (describe_address(target_pid, (unsigned long)regs.regs[i], mod, sizeof(mod)) == 0) {
                printf("x%2d: 0x%016llx (%s)\n", i, (unsigned long long)regs.regs[i], mod);
            } else {
                printf("x%2d: 0x%016llx\n", i, (unsigned long long)regs.regs[i]);
            }
        }
        char mod_sp[256] = {0}, mod_pc[256] = {0};
        if (describe_address(target_pid, (unsigned long)regs.sp, mod_sp, sizeof(mod_sp)) == 0) {
            printf("\nsp : 0x%016llx (%s)\n", (unsigned long long)regs.sp, mod_sp);
        } else {
            printf("\nsp : 0x%016llx\n", (unsigned long long)regs.sp);
        }
        if (describe_address(target_pid, (unsigned long)regs.pc, mod_pc, sizeof(mod_pc)) == 0) {
            printf("pc : 0x%016llx (%s)\n", (unsigned long long)regs.pc, mod_pc);
        } else {
            printf("pc : 0x%016llx\n", (unsigned long long)regs.pc);
        }
        printf("pstate: 0x%016llx\n", (unsigned long long)regs.pstate);
        print_callstack(pid, (unsigned long)regs.regs[29], (unsigned long)regs.regs[30], (unsigned long)regs.pc);
        printf("\n--- 栈顶 ---\n");
        for (int i = 0; i < STACK_DUMP_WORDS; i++) {
            unsigned long a = regs.sp + (unsigned long)i * 8UL;
            unsigned long v = peek_data(pid, a);
            char mod_val[256] = {0};
            if (describe_address(target_pid, v, mod_val, sizeof(mod_val)) == 0) {
                printf("sp+%02d: 0x%016lx => 0x%016lx (%s)\n", i * 8, a, v, mod_val);
            } else {
                printf("sp+%02d: 0x%016lx => 0x%016lx\n", i * 8, a, v);
            }
        }
    } else {
        perror("GETREGSET");
    }
}

// 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
void print_callstack(pid_t pid, unsigned long fp, unsigned long lr, unsigned long pc) {
    printf("\n--- 调用栈 ---\n");
    char mod[256] = {0};
    if (describe_address(target_pid, pc, mod, sizeof(mod)) == 0) {
        printf("#0 pc=0x%016lx (%s) lr=0x%016lx\n", pc, mod, lr);
    } else {
        printf("#0 pc=0x%016lx lr=0x%016lx\n", pc, lr);
    }
    unsigned long cur_fp = fp;
    for (int i = 1; i <= 16; i++) {
        if (cur_fp == 0) break;
        unsigned long next_fp = 0;
        unsigned long ret_addr = 0;
        if (peek_data_quiet(pid, cur_fp, &next_fp) == -1) break;
        if (peek_data_quiet(pid, cur_fp + 8, &ret_addr) == -1) break;
        if (ret_addr == 0) break;
        if (describe_address(target_pid, ret_addr, mod, sizeof(mod)) == 0) {
            printf("#%d pc=0x%016lx (%s)\n", i, ret_addr, mod);
        } else {
            printf("#%d pc=0x%016lx\n", i, ret_addr);
        }
        if (next_fp <= cur_fp) break;
        cur_fp = next_fp;
    }
}

// 功能：负责调试界面的样式重绘与状态可视化。
void render_debug_dashboard(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        perror("GETREGSET");
        return;
    }

    char left_top[VIEW_MAX_LINES][VIEW_LEFT_WIDTH];
    char right_top[VIEW_MAX_LINES][VIEW_RIGHT_WIDTH];
    char left_bottom[VIEW_MAX_LINES][VIEW_LEFT_WIDTH];
    char right_bottom[VIEW_MAX_LINES][VIEW_RIGHT_WIDTH];
    memset(left_top, 0, sizeof(left_top));
    memset(right_top, 0, sizeof(right_top));
    memset(left_bottom, 0, sizeof(left_bottom));
    memset(right_bottom, 0, sizeof(right_bottom));

    snprintf(left_top[0], sizeof(left_top[0]), "[DISASM]");
    unsigned long start = regs.pc >= (unsigned long)DISASM_CONTEXT * 4UL ? regs.pc - (unsigned long)DISASM_CONTEXT * 4UL : 0;
    int total = DISASM_CONTEXT * 2 + 1;
    int lt = 1;
    if (init_capstone() == 0) {
        size_t code_size = (size_t)total * 4;
        uint8_t *code = (uint8_t*)malloc(code_size);
        if (code) {
            for (int i = 0; i < total; i++) {
                uint32_t insn = read_u32(pid, start + (unsigned long)i * 4UL);
                code[i * 4 + 0] = (uint8_t)(insn & 0xff);
                code[i * 4 + 1] = (uint8_t)((insn >> 8) & 0xff);
                code[i * 4 + 2] = (uint8_t)((insn >> 16) & 0xff);
                code[i * 4 + 3] = (uint8_t)((insn >> 24) & 0xff);
            }
            cs_insn_t *insn = NULL;
            size_t count = p_cs_disasm((csh_t)capstone_handle, code, code_size, (uint64_t)start, (size_t)total, &insn);
            if (count > 0 && insn) {
                for (size_t i = 0; i < count && lt < VIEW_MAX_LINES; i++) {
                    unsigned long a = (unsigned long)insn[i].address;
                    uint32_t raw = read_u32(pid, a);
                    char bytes[32];
                    char mod[256] = {0};
                    format_u32_bytes(raw, bytes, sizeof(bytes));
                    if (describe_address(target_pid, a, mod, sizeof(mod)) == 0) {
                        snprintf(left_top[lt++], sizeof(left_top[0]), "%s0x%016lx (%s): %s %-20s %s",
                            a == regs.pc ? "=> " : "   ", a, mod, bytes, insn[i].mnemonic, insn[i].op_str);
                    } else {
                        snprintf(left_top[lt++], sizeof(left_top[0]), "%s0x%016lx: %s %-20s %s",
                            a == regs.pc ? "=> " : "   ", a, bytes, insn[i].mnemonic, insn[i].op_str);
                    }
                }
                p_cs_free(insn, count);
            }
            free(code);
        }
    }
    if (lt == 1) {
        for (int i = 0; i < total && lt < VIEW_MAX_LINES; i++) {
            unsigned long a = start + (unsigned long)i * 4UL;
            uint32_t raw = read_u32(pid, a);
            char text[128], bytes[32], mod[256] = {0};
            decode_arm64(raw, a, text, sizeof(text));
            format_u32_bytes(raw, bytes, sizeof(bytes));
            if (describe_address(target_pid, a, mod, sizeof(mod)) == 0) snprintf(left_top[lt++], sizeof(left_top[0]), "%s0x%016lx (%s): %s %s", a == regs.pc ? "=> " : "   ", a, mod, bytes, text);
            else snprintf(left_top[lt++], sizeof(left_top[0]), "%s0x%016lx: %s %s", a == regs.pc ? "=> " : "   ", a, bytes, text);
        }
    }

    snprintf(right_top[0], sizeof(right_top[0]), "[REGS]");
    int rt = 1;
    for (int row = 0; row < 16 && rt < VIEW_MAX_LINES; row++) {
        int lidx = row;
        int ridx = row + 16;
        char lbuf[128] = {0};
        char rbuf[128] = {0};
        char mod[256] = {0};
        if (lidx < 31) {
            if (describe_address(target_pid, (unsigned long)regs.regs[lidx], mod, sizeof(mod)) == 0) snprintf(lbuf, sizeof(lbuf), "x%-2d=%016llx (%s)", lidx, (unsigned long long)regs.regs[lidx], mod);
            else snprintf(lbuf, sizeof(lbuf), "x%-2d=%016llx", lidx, (unsigned long long)regs.regs[lidx]);
        }
        if (ridx < 31) {
            if (describe_address(target_pid, (unsigned long)regs.regs[ridx], mod, sizeof(mod)) == 0) snprintf(rbuf, sizeof(rbuf), "x%-2d=%016llx (%s)", ridx, (unsigned long long)regs.regs[ridx], mod);
            else snprintf(rbuf, sizeof(rbuf), "x%-2d=%016llx", ridx, (unsigned long long)regs.regs[ridx]);
        }
        snprintf(right_top[rt++], sizeof(right_top[0]), "%-40s | %-40s", lbuf, rbuf);
    }
    char mod_sp[256] = {0}, mod_pc[256] = {0};
    if (describe_address(target_pid, (unsigned long)regs.sp, mod_sp, sizeof(mod_sp)) == 0) snprintf(right_top[rt++], sizeof(right_top[0]), "sp=%016llx (%s) | pc=%016llx (%s)", (unsigned long long)regs.sp, mod_sp, (unsigned long long)regs.pc, describe_address(target_pid, (unsigned long)regs.pc, mod_pc, sizeof(mod_pc)) == 0 ? mod_pc : "");
    else snprintf(right_top[rt++], sizeof(right_top[0]), "sp=%016llx | pc=%016llx", (unsigned long long)regs.sp, (unsigned long long)regs.pc);
    snprintf(right_top[rt++], sizeof(right_top[0]), "pstate=%016llx", (unsigned long long)regs.pstate);

    snprintf(left_bottom[0], sizeof(left_bottom[0]), "[MEMORY]");
    unsigned long mem_base = 0;
    char mem_name[256] = {0};
    if (query_module_for_addr(target_pid, (unsigned long)regs.pc, &mem_base, NULL, mem_name, sizeof(mem_name)) == -1) mem_base = (unsigned long)regs.pc & ~0xffUL;
    snprintf(left_bottom[1], sizeof(left_bottom[1]), "base=0x%016lx %s", mem_base, mem_name);
    int lb = 2;
    for (int i = 0; i < 8 && lb < VIEW_MAX_LINES; i++) {
        unsigned long a = mem_base + (unsigned long)i * 16UL;
        unsigned long long v0 = read_u64(pid, a);
        unsigned long long v1 = read_u64(pid, a + 8);
        snprintf(left_bottom[lb++], sizeof(left_bottom[0]), "0x%016lx: %016llx %016llx", a, v0, v1);
    }

    int rb = 0;
    snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "[CALLSTACK]");
    char mod[256] = {0};
    if (describe_address(target_pid, (unsigned long)regs.pc, mod, sizeof(mod)) == 0) snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "#0 pc=%016llx (%s)", (unsigned long long)regs.pc, mod);
    else snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "#0 pc=%016llx", (unsigned long long)regs.pc);
    unsigned long cur_fp = (unsigned long)regs.regs[29];
    for (int i = 1; i <= 18 && rb < VIEW_MAX_LINES; i++) {
        unsigned long next_fp = 0, ret_addr = 0;
        if (cur_fp == 0) break;
        if (peek_data_quiet(pid, cur_fp, &next_fp) == -1) break;
        if (peek_data_quiet(pid, cur_fp + 8, &ret_addr) == -1) break;
        if (ret_addr == 0) break;
        if (describe_address(target_pid, ret_addr, mod, sizeof(mod)) == 0) snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "#%d pc=%016lx (%s)", i, ret_addr, mod);
        else snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "#%d pc=%016lx", i, ret_addr);
        if (next_fp <= cur_fp) break;
        cur_fp = next_fp;
    }
    snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "[STACK]");
    for (long off = -0x50; off <= 0x50 && rb < VIEW_MAX_LINES; off += 8) {
        unsigned long a = (unsigned long)((long)regs.sp + off);
        unsigned long v = peek_data(pid, a);
        const char *off_sign = off >= 0 ? "+" : "-";
        unsigned long off_abs = (unsigned long)(off >= 0 ? off : -off);
        char ref[256] = {0};
        if (v == (unsigned long)regs.sp) snprintf(ref, sizeof(ref), "sp");
        else if (v == (unsigned long)regs.regs[29]) snprintf(ref, sizeof(ref), "x29");
        else if (v == (unsigned long)regs.regs[30]) snprintf(ref, sizeof(ref), "x30");
        else if (describe_address(target_pid, v, ref, sizeof(ref)) == -1) ref[0] = '\0';
        if (ref[0]) snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "sp%s0x%lx 0x%016lx => 0x%016lx (%s)", off_sign, off_abs, a, v, ref);
        else snprintf(right_bottom[rb++], sizeof(right_bottom[0]), "sp%s0x%lx 0x%016lx => 0x%016lx", off_sign, off_abs, a, v);
    }

    clear_screen();
    printf("[THREAD] 当前中断线程 tid=%d pc=0x%016llx sp=0x%016llx\n",
           pid, (unsigned long long)regs.pc, (unsigned long long)regs.sp);
    int top_rows = lt > rt ? lt : rt;
    for (int i = 0; i < top_rows; i++) {
        printf("%-*.*s | %-*.*s\n", VIEW_LEFT_WIDTH - 1, VIEW_LEFT_WIDTH - 1, left_top[i], VIEW_RIGHT_WIDTH - 1, VIEW_RIGHT_WIDTH - 1, right_top[i]);
    }
    printf("%.*s\n", VIEW_LEFT_WIDTH + VIEW_RIGHT_WIDTH + 2, "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
    int bottom_rows = lb > rb ? lb : rb;
    for (int i = 0; i < bottom_rows; i++) {
        printf("%-*.*s | %-*.*s\n", VIEW_LEFT_WIDTH - 1, VIEW_LEFT_WIDTH - 1, left_bottom[i], VIEW_RIGHT_WIDTH - 1, VIEW_RIGHT_WIDTH - 1, right_bottom[i]);
    }
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
long sign_extend(unsigned long val, int bits) {
    unsigned long m = 1UL << (bits - 1);
    return (long)((val ^ m) - m);
}

// 功能：解析服务端输出并路由到对应调试视图。
int parse_u64(const char *s, unsigned long *v) {
    if (s == NULL || *s == '\0') return -1;
    char *end = NULL;
    unsigned long base = 10;
    if (strlen(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) base = 16;
    errno = 0;
    unsigned long val = strtoul(s, &end, base);
    if (errno != 0 || end == s || *end != '\0') return -1;
    *v = val;
    return 0;
}

// 功能：解析服务端输出并路由到对应调试视图。
int parse_addr_expr(pid_t pid, const char *s, unsigned long *v) {
    if (parse_u64(s, v) == 0) return 0;
    if (!s || !*s) return -1;
    struct user_pt_regs regs;
    if (get_regs(pid, &regs) == -1) return -1;

    char reg[32] = {0};
    const char *op = strchr(s, '+');
    if (!op) op = strchr(s, '-');
    long sign = 1;
    unsigned long off = 0;
    if (op) {
        size_t n = (size_t)(op - s);
        if (n >= sizeof(reg)) return -1;
        memcpy(reg, s, n);
        reg[n] = '\0';
        sign = (*op == '-') ? -1 : 1;
        if (parse_u64(op + 1, &off) == -1) return -1;
    } else {
        snprintf(reg, sizeof(reg), "%s", s);
    }

    unsigned long base = 0;
    if (strcmp(reg, "sp") == 0) base = (unsigned long)regs.sp;
    else if (strcmp(reg, "pc") == 0) base = (unsigned long)regs.pc;
    else if (strcmp(reg, "lr") == 0) base = (unsigned long)regs.regs[30];
    else if (strcmp(reg, "fp") == 0) base = (unsigned long)regs.regs[29];
    else if (reg[0] == 'x' && isdigit((unsigned char)reg[1])) {
        int idx = atoi(reg + 1);
        if (idx < 0 || idx > 30) return -1;
        base = (unsigned long)regs.regs[idx];
    } else {
        return -1;
    }
    *v = sign > 0 ? (base + off) : (base - off);
    return 0;
}

// 功能：处理寄存器数据解析与展示，用于更新当前执行上下文。
int set_register_by_name(pid_t pid, const char *name, unsigned long value) {
    struct user_pt_regs regs;
    if (get_regs(pid, &regs) == -1) {
        perror("GETREGSET setreg");
        return -1;
    }
    if (strcmp(name, "sp") == 0) regs.sp = value;
    else if (strcmp(name, "pc") == 0) regs.pc = value;
    else if (strcmp(name, "pstate") == 0) regs.pstate = value;
    else if (strcmp(name, "lr") == 0) regs.regs[30] = value;
    else if (strcmp(name, "fp") == 0) regs.regs[29] = value;
    else if (name[0] == 'x' && isdigit((unsigned char)name[1])) {
        int idx = atoi(name + 1);
        if (idx < 0 || idx > 30) return -1;
        regs.regs[idx] = value;
    } else {
        return -1;
    }
    if (set_regs(pid, &regs) == -1) {
        perror("SETREGSET setreg");
        return -1;
    }
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int set_hardware_breakpoint(pid_t pid, unsigned long addr, int force_idx) {
    if (refresh_hw_bp_slots(pid) == -1) return -1;
    int max_slots = hw_bp_slots;
    int exists = find_breakpoint_by_addr(addr);
    if (exists >= 0) {
        printf("硬件断点已存在: idx=%d addr=0x%lx\n", exists, addr);
        return exists;
    }

    int idx = -1;
    if (force_idx >= 0 && force_idx < max_slots) {
        idx = force_idx;
    } else {
        for (int i = 0; i < max_slots; i++) {
            if (!my_breakpoints[i].in_use) {
                idx = i;
                break;
            }
        }
    }
    if (idx == -1) {
        fprintf(stderr, "错误：没有可用硬件断点寄存器\n");
        return -1;
    }

    my_breakpoints[idx].addr = addr;
    my_breakpoints[idx].ctrl = DBGBCR_ENABLE | DBGBCR_PMC_EL0 | DBGBCR_BAS | DBGBCR_BT_INST;
    my_breakpoints[idx].in_use = 1;
    if (sync_hw_breakpoints_all_threads(target_pid) == -1) {
        my_breakpoints[idx].addr = 0;
        my_breakpoints[idx].ctrl = 0;
        my_breakpoints[idx].in_use = 0;
        return -1;
    }
    printf("硬件断点已设置: idx=%d addr=0x%lx\n", idx, addr);
    return idx;
}

// 功能：处理断点增删改查与命中后的状态同步。
int clear_breakpoint(pid_t pid, int idx) {
    if (idx < 0 || idx >= HW_BP_MAX) return -1;
    if (!my_breakpoints[idx].in_use) return 0;
    unsigned long old_addr = my_breakpoints[idx].addr;
    uint32_t old_ctrl = my_breakpoints[idx].ctrl;
    my_breakpoints[idx].in_use = 0;
    my_breakpoints[idx].addr = 0;
    my_breakpoints[idx].ctrl = 0;
    if (sync_hw_breakpoints_all_threads(target_pid) == -1) {
        my_breakpoints[idx].in_use = 1;
        my_breakpoints[idx].addr = old_addr;
        my_breakpoints[idx].ctrl = old_ctrl;
        return -1;
    }
    printf("硬件断点已删除: idx=%d\n", idx);
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int clear_all_breakpoints(pid_t pid) {
    for (int i = 0; i < HW_BP_MAX; i++) {
        my_breakpoints[i].in_use = 0;
        my_breakpoints[i].addr = 0;
        my_breakpoints[i].ctrl = 0;
    }
    sync_hw_breakpoints_all_threads(target_pid);
    return 0;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
int load_thread_ids(pid_t pid, pid_t *tids, int max_tids) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (!dir) return -1;
    int cnt = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        if (cnt < max_tids) tids[cnt++] = (pid_t)atoi(ent->d_name);
    }
    closedir(dir);
    return cnt;
}

// 功能：在调试上下文中查找目标地址/模块/条目并返回匹配结果。
int find_traced_tid(pid_t tid) {
    for (int i = 0; i < traced_tid_count; i++) {
        if (traced_tids[i] == tid) return i;
    }
    return -1;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void add_traced_tid(pid_t tid) {
    if (tid <= 0) return;
    if (find_traced_tid(tid) >= 0) return;
    if (traced_tid_count < (int)(sizeof(traced_tids) / sizeof(traced_tids[0]))) {
        traced_tids[traced_tid_count++] = tid;
    }
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void remove_traced_tid(pid_t tid) {
    int idx = find_traced_tid(tid);
    if (idx < 0) return;
    traced_tids[idx] = traced_tids[traced_tid_count - 1];
    traced_tids[traced_tid_count - 1] = 0;
    traced_tid_count--;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int set_ptrace_options(pid_t tid) {
    long opts = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT;
    if (ptrace(PTRACE_SETOPTIONS, tid, NULL, (void*)opts) == -1) {
        if (errno != ESRCH) perror("PTRACE_SETOPTIONS");
        return -1;
    }
    return 0;
}

// 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
int ensure_thread_attached_for_debug(pid_t tid, int auto_continue) {
    if (tid <= 0) return -1;
    if (find_traced_tid(tid) >= 0) return 0;
    if (tid == target_pid) {
        add_traced_tid(tid);
        set_ptrace_options(tid);
        return 0;
    }
    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) return -1;
    int st = 0;
    if (waitpid(tid, &st, __WALL) == -1) {
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        return -1;
    }
    add_traced_tid(tid);
    set_ptrace_options(tid);
    if (auto_continue) continue_execution(tid, 0);
    return 0;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
int stop_thread_for_sync(pid_t tid) {
    if (tid <= 0) return -1;
    if (tid == interactive_tid) return 0;
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    if (ptrace(PTRACE_GETSIGINFO, tid, NULL, &si) == 0) return 0;
    if (kill(tid, SIGSTOP) == -1) {
        if (errno == ESRCH) return -1;
    }
    int st = 0;
    for (int i = 0; i < 200; i++) {
        pid_t r = waitpid(tid, &st, __WALL | WNOHANG);
        if (r == tid) {
            if (WIFSTOPPED(st)) return 0;
            return -1;
        }
        if (r == -1) {
            if (errno == ECHILD || errno == ESRCH) return -1;
            return -1;
        }
        usleep(5000);
    }
    return -1;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
void pause_other_traced_threads(pid_t current_tid) {
    if (interaction_threads_paused) return;
    for (int i = 0; i < traced_tid_count; i++) {
        pid_t tid = traced_tids[i];
        if (tid <= 0 || tid == current_tid) continue;
        stop_thread_for_sync(tid);
    }
    interaction_threads_paused = 1;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
void resume_other_traced_threads(pid_t current_tid) {
    for (int i = 0; i < traced_tid_count; i++) {
        pid_t tid = traced_tids[i];
        if (tid <= 0 || tid == current_tid) continue;
        continue_execution(tid, 0);
    }
    interaction_threads_paused = 0;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
void detach_all_traced_threads(void) {
    for (int i = traced_tid_count - 1; i >= 0; i--) {
        pid_t tid = traced_tids[i];
        if (tid > 0) ptrace(PTRACE_DETACH, tid, NULL, NULL);
    }
    memset(traced_tids, 0, sizeof(traced_tids));
    traced_tid_count = 0;
    interaction_threads_paused = 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int refresh_hw_bp_slots(pid_t pid) {
    struct user_hwdebug_state state;
    struct iovec iov = { .iov_base = &state, .iov_len = sizeof(state) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_BREAK, &iov) == -1) {
        if (errno != ESRCH) perror("GETREGSET");
        return -1;
    }
    int slots = state.dbg_info & 0xff;
    if (slots <= 0) {
        fprintf(stderr, "错误：硬件断点不可用\n");
        return -1;
    }
    if (slots > HW_BP_MAX) slots = HW_BP_MAX;
    hw_bp_slots = slots;
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int refresh_hw_wp_slots(pid_t pid) {
    struct user_hwdebug_state state;
    struct iovec iov = { .iov_base = &state, .iov_len = sizeof(state) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
        if (errno != ESRCH) perror("GETREGSET WATCH");
        return -1;
    }
    int slots = state.dbg_info & 0xff;
    if (slots <= 0) {
        fprintf(stderr, "错误：内存属性断点不可用\n");
        return -1;
    }
    if (slots > HW_WP_MAX) slots = HW_WP_MAX;
    hw_wp_slots = slots;
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int sync_hw_breakpoints(pid_t pid) {
    if (refresh_hw_bp_slots(pid) == -1) return -1;
    struct user_hwdebug_state state;
    memset(&state, 0, sizeof(state));
    for (int i = 0; i < hw_bp_slots; i++) {
        if (my_breakpoints[i].in_use) {
            state.dbg_regs[i].addr = my_breakpoints[i].addr;
            state.dbg_regs[i].ctrl = my_breakpoints[i].ctrl;
        }
    }
    struct iovec iov = { .iov_base = &state, .iov_len = offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(state.dbg_regs[0]) * hw_bp_slots };
    if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &iov) == -1) {
        if (errno != ESRCH) perror("SETREGSET");
        return -1;
    }
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int sync_hw_watchpoints(pid_t pid) {
    if (refresh_hw_wp_slots(pid) == -1) return -1;
    struct user_hwdebug_state state;
    memset(&state, 0, sizeof(state));
    for (int i = 0; i < hw_wp_slots; i++) {
        if (my_watchpoints[i].in_use) {
            state.dbg_regs[i].addr = my_watchpoints[i].addr;
            state.dbg_regs[i].ctrl = my_watchpoints[i].ctrl;
        }
    }
    struct iovec iov = { .iov_base = &state, .iov_len = offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(state.dbg_regs[0]) * hw_wp_slots };
    if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
        if (errno != ESRCH) perror("SETREGSET WATCH");
        return -1;
    }
    return 0;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
int sync_hw_watchpoints_for_thread(pid_t pid, int disable_idx) {
    if (refresh_hw_wp_slots(pid) == -1) return -1;
    struct user_hwdebug_state state;
    memset(&state, 0, sizeof(state));
    for (int i = 0; i < hw_wp_slots; i++) {
        if (i == disable_idx) continue;
        if (my_watchpoints[i].in_use) {
            state.dbg_regs[i].addr = my_watchpoints[i].addr;
            state.dbg_regs[i].ctrl = my_watchpoints[i].ctrl;
        }
    }
    struct iovec iov = { .iov_base = &state, .iov_len = offsetof(struct user_hwdebug_state, dbg_regs) + sizeof(state.dbg_regs[0]) * hw_wp_slots };
    if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
        if (errno != ESRCH) perror("SETREGSET WATCH");
        return -1;
    }
    return 0;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
int sync_hw_breakpoints_all_threads(pid_t pid) {
    pid_t tids[512];
    int cnt = load_thread_ids(pid, tids, 512);
    if (cnt <= 0) return sync_hw_breakpoints(pid);
    int ok = 0;
    for (int i = 0; i < cnt; i++) {
        pid_t tid = tids[i];
        int need_resume = 0;
        if (find_traced_tid(tid) >= 0) {
            if (interaction_threads_paused && tid != interactive_tid) {
                need_resume = 0;
            } else
            if (tid != interactive_tid) {
                if (stop_thread_for_sync(tid) == -1) continue;
                need_resume = 1;
            }
        } else {
            if (ensure_thread_attached_for_debug(tid, 0) == -1) continue;
            if (tid != interactive_tid) need_resume = 1;
        }
        if (sync_hw_breakpoints(tid) == 0) ok = 1;
        if (need_resume) continue_execution(tid, 0);
    }
    return ok ? 0 : -1;
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
int sync_hw_watchpoints_all_threads(pid_t pid) {
    pid_t tids[512];
    int cnt = load_thread_ids(pid, tids, 512);
    if (cnt <= 0) return sync_hw_watchpoints(pid);
    int ok = 0;
    for (int i = 0; i < cnt; i++) {
        pid_t tid = tids[i];
        int need_resume = 0;
        if (find_traced_tid(tid) >= 0) {
            if (interaction_threads_paused && tid != interactive_tid) {
                need_resume = 0;
            } else
            if (tid != interactive_tid) {
                if (stop_thread_for_sync(tid) == -1) continue;
                need_resume = 1;
            }
        } else {
            if (ensure_thread_attached_for_debug(tid, 0) == -1) continue;
            if (tid != interactive_tid) need_resume = 1;
        }
        if (sync_hw_watchpoints(tid) == 0) ok = 1;
        if (need_resume) continue_execution(tid, 0);
    }
    return ok ? 0 : -1;
}

// 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
int ensure_all_threads_attached_for_debug(pid_t pid) {
    pid_t tids[512];
    int cnt = load_thread_ids(pid, tids, 512);
    if (cnt <= 0) return 0;
    int ok = 0;
    for (int i = 0; i < cnt; i++) {
        pid_t tid = tids[i];
        if (tid <= 0) continue;
        if (find_traced_tid(tid) >= 0) {
            ok = 1;
            continue;
        }
        if (ensure_thread_attached_for_debug(tid, 0) == 0) ok = 1;
    }
    return ok ? 0 : -1;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int continue_execution(pid_t pid, int signo) {
    if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)signo) == -1) {
        if (errno != ESRCH) perror("ptrace CONT");
        return -1;
    }
    return 0;
}

// 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
int single_step(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("ptrace SINGLESTEP");
        return -1;
    }
    return 0;
}

// 功能：处理附加目标进程流程，建立调试会话并同步初始状态。
int attach_process(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return -1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "进程停止异常\n");
        return -1;
    }
    add_traced_tid(pid);
    set_ptrace_options(pid);
    printf("已附加进程 %d，停止信号: %d\n", pid, WSTOPSIG(status));
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int detach_process(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        if (errno != ESRCH) perror("ptrace DETACH");
        return -1;
    }
    printf("已从进程 %d 分离\n", pid);
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
unsigned long get_pc(pid_t pid) {
    struct user_pt_regs regs;
    if (get_regs(pid, &regs) == -1) {
        perror("GETREGSET PC");
        return 0;
    }
    return regs.pc;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int set_pc(pid_t pid, unsigned long pc) {
    struct user_pt_regs regs;
    if (get_regs(pid, &regs) == -1) {
        perror("GETREGSET set_pc");
        return -1;
    }
    regs.pc = pc;
    if (set_regs(pid, &regs) == -1) {
        perror("SETREGSET set_pc");
        return -1;
    }
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int find_breakpoint_by_addr(unsigned long addr) {
    for (int i = 0; i < HW_BP_MAX; i++) {
        if (my_breakpoints[i].in_use && my_breakpoints[i].addr == addr) return i;
    }
    return -1;
}

// 功能：在调试上下文中查找目标地址/模块/条目并返回匹配结果。
int find_watchpoint_by_addr(unsigned long addr) {
    for (int i = 0; i < HW_WP_MAX; i++) {
        if (!my_watchpoints[i].in_use) continue;
        if (my_watchpoints[i].addr_raw == addr) return i;
        if (my_watchpoints[i].addr == addr) return i;
    }
    return -1;
}

// 功能：处理断点增删改查与命中后的状态同步。
int find_soft_breakpoint_by_addr(unsigned long addr) {
    for (int i = 0; i < SW_BP_MAX; i++) {
        if (my_soft_breakpoints[i].in_use && my_soft_breakpoints[i].addr == addr) return i;
    }
    return -1;
}

// 功能：处理断点增删改查与命中后的状态同步。
int set_soft_breakpoint(pid_t pid, unsigned long addr, int mode) {
    ensure_all_threads_attached_for_debug(target_pid);
    int exists = find_soft_breakpoint_by_addr(addr);
    if (exists >= 0) return exists;
    int idx = -1;
    for (int i = 0; i < SW_BP_MAX; i++) {
        if (!my_soft_breakpoints[i].in_use) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return -1;
    my_soft_breakpoints[idx].addr = addr;
    my_soft_breakpoints[idx].in_use = 1;
    my_soft_breakpoints[idx].mode = mode;
    my_soft_breakpoints[idx].backend_wp_idx = -1;
    if (mode > 0) {
        int wp_idx = set_watchpoint_mode(pid, addr, mode == 1 ? 1 : (mode == 2 ? 2 : 3), -1);
        if (wp_idx < 0) {
            my_soft_breakpoints[idx].in_use = 0;
            my_soft_breakpoints[idx].addr = 0;
            my_soft_breakpoints[idx].mode = 0;
            return -1;
        }
        my_soft_breakpoints[idx].orig_insn = 0;
        my_soft_breakpoints[idx].backend_wp_idx = wp_idx;
        return idx;
    }
    uint32_t orig = read_u32(pid, addr);
    if (write_u32(pid, addr, get_brk_instruction()) == -1) {
        my_soft_breakpoints[idx].in_use = 0;
        my_soft_breakpoints[idx].addr = 0;
        my_soft_breakpoints[idx].mode = 0;
        return -1;
    }
    my_soft_breakpoints[idx].orig_insn = orig;
    return idx;
}

// 功能：处理断点增删改查与命中后的状态同步。
int clear_soft_breakpoint(pid_t pid, int idx) {
    if (idx < 0 || idx >= SW_BP_MAX) return -1;
    if (!my_soft_breakpoints[idx].in_use) return 0;
    unsigned long old_addr = my_soft_breakpoints[idx].addr;
    if (my_soft_breakpoints[idx].mode > 0) {
        if (my_soft_breakpoints[idx].backend_wp_idx >= 0) clear_watchpoint(pid, my_soft_breakpoints[idx].backend_wp_idx);
    } else {
        if (write_u32(pid, my_soft_breakpoints[idx].addr, my_soft_breakpoints[idx].orig_insn) == -1) return -1;
    }
    my_soft_breakpoints[idx].in_use = 0;
    my_soft_breakpoints[idx].addr = 0;
    my_soft_breakpoints[idx].orig_insn = 0;
    my_soft_breakpoints[idx].mode = 0;
    my_soft_breakpoints[idx].backend_wp_idx = -1;
    if (current_soft_hit_idx == idx || current_soft_hit_addr == old_addr) {
        current_soft_hit_idx = -1;
        current_soft_hit_addr = 0;
    }
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int clear_all_soft_breakpoints(pid_t pid) {
    for (int i = 0; i < SW_BP_MAX; i++) {
        if (my_soft_breakpoints[i].in_use) clear_soft_breakpoint(pid, i);
    }
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int set_watchpoint_mode(pid_t pid, unsigned long addr, int mode, int force_idx) {
    ensure_all_threads_attached_for_debug(target_pid);
    if (refresh_hw_wp_slots(pid) == -1) return -1;
    int max_slots = hw_wp_slots;
    int exists = find_watchpoint_by_addr(addr);
    if (exists >= 0) return exists;
    int idx = -1;
    if (force_idx >= 0 && force_idx < max_slots) idx = force_idx;
    else {
        for (int i = 0; i < max_slots; i++) {
            if (!my_watchpoints[i].in_use) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) return -1;
    unsigned long aligned = addr & ~0x7UL;
    unsigned bas = 0;
    unsigned byte_off = (unsigned)(addr & 0x7UL);
    for (unsigned i = 0; i < 4 && byte_off + i < 8; i++) bas |= (1U << (byte_off + i));
    my_watchpoints[idx].addr = aligned;
    my_watchpoints[idx].addr_raw = addr;
    my_watchpoints[idx].ctrl = DBGBCR_ENABLE | DBGBCR_PMC_EL0 | (((uint32_t)mode & 0x3U) << 3) | ((uint32_t)bas << 5);
    my_watchpoints[idx].in_use = 1;
    my_watchpoints[idx].mode = mode;
    if (sync_hw_watchpoints_all_threads(target_pid) == -1) {
        my_watchpoints[idx].in_use = 0;
        my_watchpoints[idx].addr = 0;
        my_watchpoints[idx].addr_raw = 0;
        my_watchpoints[idx].ctrl = 0;
        my_watchpoints[idx].mode = 0;
        return -1;
    }
    return idx;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int set_watchpoint(pid_t pid, unsigned long addr, int force_idx) {
    return set_watchpoint_mode(pid, addr, 3, force_idx);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int clear_watchpoint(pid_t pid, int idx) {
    if (idx < 0 || idx >= HW_WP_MAX) return -1;
    if (!my_watchpoints[idx].in_use) return 0;
    my_watchpoints[idx].in_use = 0;
    my_watchpoints[idx].addr = 0;
    my_watchpoints[idx].addr_raw = 0;
    my_watchpoints[idx].ctrl = 0;
    my_watchpoints[idx].mode = 0;
    if (current_watch_hit_idx == idx) {
        current_watch_hit_idx = -1;
        current_watch_hit_addr = 0;
    }
    for (int i = 0; i < SW_BP_MAX; i++) {
        if (my_soft_breakpoints[i].in_use && my_soft_breakpoints[i].mode > 0 && my_soft_breakpoints[i].backend_wp_idx == idx) {
            my_soft_breakpoints[i].in_use = 0;
            my_soft_breakpoints[i].addr = 0;
            my_soft_breakpoints[i].orig_insn = 0;
            my_soft_breakpoints[i].mode = 0;
            my_soft_breakpoints[i].backend_wp_idx = -1;
        }
    }
    if (sync_hw_watchpoints_all_threads(target_pid) == -1) return -1;
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int clear_all_watchpoints(pid_t pid) {
    for (int i = 0; i < HW_WP_MAX; i++) {
        my_watchpoints[i].in_use = 0;
        my_watchpoints[i].addr = 0;
        my_watchpoints[i].addr_raw = 0;
        my_watchpoints[i].ctrl = 0;
        my_watchpoints[i].mode = 0;
    }
    current_watch_hit_idx = -1;
    current_watch_hit_addr = 0;
    for (int i = 0; i < SW_BP_MAX; i++) {
        if (my_soft_breakpoints[i].in_use && my_soft_breakpoints[i].mode > 0) {
            my_soft_breakpoints[i].in_use = 0;
            my_soft_breakpoints[i].addr = 0;
            my_soft_breakpoints[i].orig_insn = 0;
            my_soft_breakpoints[i].mode = 0;
            my_soft_breakpoints[i].backend_wp_idx = -1;
        }
    }
    sync_hw_watchpoints_all_threads(target_pid);
    return 0;
}

unsigned long page_align_down(unsigned long addr) {
    unsigned long ps = (unsigned long)sysconf(_SC_PAGESIZE);
    if (ps == 0) ps = 4096UL;
    return addr & ~(ps - 1UL);
}

unsigned long page_align_up(unsigned long addr) {
    unsigned long ps = (unsigned long)sysconf(_SC_PAGESIZE);
    if (ps == 0) ps = 4096UL;
    if (addr == 0) return 0;
    return (addr + ps - 1UL) & ~(ps - 1UL);
}

typedef struct {
    unsigned long s, e, off, ino;
    char perms[8];
    char dev[32];
} pmap_ent;

static int pmap_parse_line(const char *line, pmap_ent *m) {
    char name[512];
    unsigned long inode = 0;
    m->dev[0] = '\0';
    int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %511[^\n]", &m->s, &m->e, m->perms, &m->off, m->dev, &inode, name);
    if (n < 5) return 0;
    m->ino = inode;
    return 1;
}

static int pmap_find_addr(pid_t pid, unsigned long addr, pmap_ent *base) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        pmap_ent m;
        if (!pmap_parse_line(line, &m)) continue;
        if (addr >= m.s && addr < m.e) {
            fclose(fp);
            *base = m;
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

static void merge_map_ranges(unsigned long *rs, unsigned long *re, int *n) {
    int N = *n;
    if (N <= 1) return;
    for (int i = 0; i < N; i++) {
        for (int j = i + 1; j < N; j++) {
            if (rs[j] < rs[i]) {
                unsigned long t = rs[i];
                rs[i] = rs[j];
                rs[j] = t;
                t = re[i];
                re[i] = re[j];
                re[j] = t;
            }
        }
    }
    int w = 0;
    for (int i = 1; i < N; i++) {
        if (rs[i] <= re[w]) {
            if (re[i] > re[w])
                re[w] = re[i];
        } else {
            w++;
            rs[w] = rs[i];
            re[w] = re[i];
        }
    }
    *n = w + 1;
}

static int mem_page_fill_exec_alias_ranges(my_mem_page_t *slot, pid_t maps_pid, unsigned long addr, unsigned long apply_lo, unsigned long apply_hi) {
    pmap_ent base;
    if (pmap_find_addr(maps_pid, addr, &base) != 0) return -1;
    if (apply_lo < base.s) apply_lo = base.s;
    if (apply_hi > base.e) apply_hi = base.e;
    if (apply_lo >= apply_hi) return -1;

    unsigned long f_lo = base.off + (apply_lo - base.s);
    unsigned long f_hi = base.off + (apply_hi - base.s);

    unsigned long rs[MEM_PAGE_RANGE_MAX * 2];
    unsigned long re[MEM_PAGE_RANGE_MAX * 2];
    int n = 0;

    if (base.ino == 0) {
        slot->range_count = 1;
        slot->range_start[0] = page_align_down(apply_lo);
        slot->range_end[0] = page_align_up(apply_hi);
        if (slot->range_start[0] >= slot->range_end[0]) return -1;
    } else {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/maps", (int)maps_pid);
        FILE *fp = fopen(path, "r");
        if (!fp) return -1;
        char line[2048];
        while (fgets(line, sizeof(line), fp)) {
            pmap_ent m;
            if (!pmap_parse_line(line, &m)) continue;
            if (m.ino != base.ino || strcmp(m.dev, base.dev) != 0) continue;
            if (!strchr(m.perms, 'x')) continue;
            unsigned long line_fend = m.off + (m.e - m.s);
            unsigned long a = f_lo > m.off ? f_lo : m.off;
            unsigned long b = f_hi < line_fend ? f_hi : line_fend;
            if (a >= b) continue;
            unsigned long va0 = m.s + (a - m.off);
            unsigned long va1 = m.s + (b - m.off);
            unsigned long lo = page_align_down(va0);
            unsigned long hi = page_align_up(va1);
            if (lo >= hi) continue;
            if (n >= (int)(sizeof(rs) / sizeof(rs[0]))) {
                fclose(fp);
                return -1;
            }
            rs[n] = lo;
            re[n] = hi;
            n++;
        }
        fclose(fp);

        if (n == 0) {
            slot->range_count = 1;
            slot->range_start[0] = page_align_down(apply_lo);
            slot->range_end[0] = page_align_up(apply_hi);
            if (slot->range_start[0] >= slot->range_end[0]) return -1;
        } else {
            merge_map_ranges(rs, re, &n);
            if (n > MEM_PAGE_RANGE_MAX) return -1;
            slot->range_count = n;
            for (int i = 0; i < n; i++) {
                slot->range_start[i] = rs[i];
                slot->range_end[i] = re[i];
            }
        }
    }
    slot->map_start = slot->range_start[0];
    slot->map_end = slot->range_end[0];
    for (int i = 1; i < slot->range_count; i++) {
        if (slot->range_start[i] < slot->map_start) slot->map_start = slot->range_start[i];
        if (slot->range_end[i] > slot->map_end) slot->map_end = slot->range_end[i];
    }
    membp_trace("[MEMBP] set: exec_alias ranges=%d map_hull=[0x%lx,0x%lx) ino=%lu dev=%s\n",
        slot->range_count, slot->map_start, slot->map_end, (unsigned long)base.ino, base.dev[0] ? base.dev : "?");
    return 0;
}

int query_map_prot(pid_t pid, unsigned long addr, unsigned long *start_out, unsigned long *end_out, int *prot_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[8] = {0}, dev[32] = {0}, name[512] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %511[^\n]", &start, &end, perms, &offset, dev, &inode, name);
        if (n < 6) continue;
        if (addr < start || addr >= end) continue;
        int prot = 0;
        if (strchr(perms, 'r')) prot |= PROT_READ;
        if (strchr(perms, 'w')) prot |= PROT_WRITE;
        if (strchr(perms, 'x')) prot |= PROT_EXEC;
        if (start_out) *start_out = start;
        if (end_out) *end_out = end;
        if (prot_out) *prot_out = prot;
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return -1;
}

int remote_mprotect_single(pid_t tid, unsigned long addr, unsigned long len, int prot) {
    struct user_pt_regs saved_regs;
    struct user_pt_regs call_regs;
    if (get_regs(tid, &saved_regs) == -1) return -1;
    membp_trace("[MEMBP] inj mprotect tid=%d start=0x%lx len=0x%lx prot=0x%x cur_pc=0x%lx\n",
        (int)tid, addr, len, prot, (unsigned long)saved_regs.pc);
    call_regs = saved_regs;
    uint32_t saved_insn = read_u32(tid, (unsigned long)saved_regs.pc);
    if (write_u32(tid, (unsigned long)saved_regs.pc, 0xD4000001U) == -1) return -1; // svc #0
    call_regs.regs[0] = addr;
    call_regs.regs[1] = len;
    call_regs.regs[2] = (unsigned long)prot;
    call_regs.regs[8] = (unsigned long)__NR_mprotect;
    call_regs.pc = saved_regs.pc;
    if (set_regs(tid, &call_regs) == -1) {
        write_u32(tid, (unsigned long)saved_regs.pc, saved_insn);
        return -1;
    }
    if (single_step(tid) == -1) {
        write_u32(tid, (unsigned long)saved_regs.pc, saved_insn);
        set_regs(tid, &saved_regs);
        return -1;
    }
    int status = 0;
    if (waitpid(tid, &status, __WALL) == -1) {
        write_u32(tid, (unsigned long)saved_regs.pc, saved_insn);
        set_regs(tid, &saved_regs);
        return -1;
    }
    int ok = 0;
    int wstopsig = WIFSTOPPED(status) ? WSTOPSIG(status) : -1;
    if (WIFSTOPPED(status) && wstopsig == SIGTRAP) {
        struct user_pt_regs ret_regs;
        if (get_regs(tid, &ret_regs) == 0) {
            long retv = (long)ret_regs.regs[0];
            ok = (retv == 0);
            membp_trace("[MEMBP] inj mprotect tid=%d post-wait sig=%d x0(ret)=%ld %s\n", (int)tid, wstopsig, retv, ok ? "OK" : "FAIL");
        } else {
            membp_trace("[MEMBP] inj mprotect tid=%d post-wait sig=%d get_regs FAIL\n", (int)tid, wstopsig);
        }
    } else {
        membp_trace("[MEMBP] inj mprotect tid=%d post-wait WIFSTOPPED=%d sig=%d (expect SIGTRAP)\n",
            (int)tid, WIFSTOPPED(status) ? 1 : 0, wstopsig);
    }
    write_u32(tid, (unsigned long)saved_regs.pc, saved_insn);
    set_regs(tid, &saved_regs);
    return ok ? 0 : -1;
}

static int mem_page_apply_prot_ex(pid_t tid, my_mem_page_t *pg, int new_prot, int rollback_prot) {
    int r;
    if (pg->range_count <= 0) {
        unsigned long lo = pg->map_start, hi = pg->map_end;
        if (lo >= hi) return -1;
        return remote_mprotect_single(tid, lo, hi - lo, new_prot);
    }
    for (r = 0; r < pg->range_count; r++) {
        unsigned long lo = pg->range_start[r];
        unsigned long hi = pg->range_end[r];
        if (lo >= hi) continue;
        if (remote_mprotect_single(tid, lo, hi - lo, new_prot) == -1) goto undo;
    }
    return 0;
undo:
    for (int k = 0; k < r; k++) {
        unsigned long lo = pg->range_start[k];
        unsigned long hi = pg->range_end[k];
        if (lo >= hi) continue;
        (void)remote_mprotect_single(tid, lo, hi - lo, rollback_prot);
    }
    return -1;
}

int find_mem_breakpoint_by_addr(unsigned long addr) {
    for (int i = 0; i < MEM_BP_MAX; i++) {
        if (my_mem_breakpoints[i].in_use && my_mem_breakpoints[i].addr == addr) return i;
    }
    return -1;
}

int find_mem_page_by_page(unsigned long page) {
    for (int i = 0; i < MEM_PAGE_MAX; i++) {
        if (my_mem_pages[i].in_use && my_mem_pages[i].page == page) return i;
    }
    return -1;
}

static int find_mem_page_containing_addr(unsigned long addr) {
    for (int i = 0; i < MEM_PAGE_MAX; i++) {
        if (!my_mem_pages[i].in_use) continue;
        if (my_mem_pages[i].range_count > 0) {
            for (int j = 0; j < my_mem_pages[i].range_count; j++) {
                if (addr >= my_mem_pages[i].range_start[j] && addr < my_mem_pages[i].range_end[j]) return i;
            }
        } else if (addr >= my_mem_pages[i].map_start && addr < my_mem_pages[i].map_end) {
            return i;
        }
    }
    return -1;
}

int find_mem_page_link(int bp_idx, int page_idx) {
    for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
        if (!my_mem_page_bp_links[i].in_use) continue;
        if (my_mem_page_bp_links[i].bp_idx == bp_idx && my_mem_page_bp_links[i].page_idx == page_idx) return i;
    }
    return -1;
}

int count_mem_links_for_page(int page_idx) {
    int cnt = 0;
    for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
        if (!my_mem_page_bp_links[i].in_use) continue;
        if (my_mem_page_bp_links[i].page_idx == page_idx) cnt++;
    }
    return cnt;
}

int memory_page_has_bp_addr(int page_idx, unsigned long addr) {
    for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
        if (!my_mem_page_bp_links[i].in_use) continue;
        if (my_mem_page_bp_links[i].page_idx != page_idx) continue;
        int bp_idx = my_mem_page_bp_links[i].bp_idx;
        if (bp_idx < 0 || bp_idx >= MEM_BP_MAX) continue;
        if (my_mem_breakpoints[bp_idx].in_use && my_mem_breakpoints[bp_idx].addr == addr) return 1;
    }
    return 0;
}

// 按该页上所有内存断点的 mode 合并计算 mprotect 目标权限（最小实现：用缺页/SIGSEGV 停下目标）。
int mem_page_compute_trap_prot(int page_idx) {
    if (page_idx < 0 || page_idx >= MEM_PAGE_MAX || !my_mem_pages[page_idx].in_use) return 0;
    int trap = my_mem_pages[page_idx].orig_prot;
    for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
        if (!my_mem_page_bp_links[i].in_use || my_mem_page_bp_links[i].page_idx != page_idx) continue;
        int bi = my_mem_page_bp_links[i].bp_idx;
        if (bi < 0 || bi >= MEM_BP_MAX || !my_mem_breakpoints[bi].in_use) continue;
        int m = my_mem_breakpoints[bi].mode;
        if (m == 0)
            trap &= ~PROT_EXEC;
        else if (m == 1)
            trap &= ~PROT_READ;
        else if (m == 2)
            trap &= ~PROT_WRITE;
        else if (m == 3)
            trap &= ~(PROT_READ | PROT_WRITE);
    }
    return trap;
}

int set_memory_breakpoint(pid_t pid, unsigned long addr, int mode) {
    int exists = find_mem_breakpoint_by_addr(addr);
    if (exists >= 0) return exists;
    unsigned long map_start = 0, map_end = 0;
    int orig_prot = 0;
    if (query_map_prot(target_pid, addr, &map_start, &map_end, &orig_prot) == -1) {
        printf("设置内存断点失败: 地址未映射(可能缺页) 0x%lx\n", addr);
        return -1;
    }
    unsigned long page = page_align_down(addr);
    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096UL;
    membp_trace("[MEMBP] set: addr=0x%lx mode=%d inj_tid=%d target_pid=%d vma=[0x%lx,0x%lx) orig_prot=0x%x psz=0x%lx\n",
        addr, mode, (int)pid, (int)target_pid, map_start, map_end, orig_prot, page_size);
    int bp_idx = -1;
    for (int i = 0; i < MEM_BP_MAX; i++) {
        if (!my_mem_breakpoints[i].in_use) {
            bp_idx = i;
            break;
        }
    }
    if (bp_idx < 0) return -1;
    int page_idx = find_mem_page_containing_addr(addr);
    if (page_idx < 0) {
        for (int i = 0; i < MEM_PAGE_MAX; i++) {
            if (!my_mem_pages[i].in_use) {
                page_idx = i;
                break;
            }
        }
        if (page_idx < 0) return -1;
        my_mem_pages[page_idx].in_use = 1;
        my_mem_pages[page_idx].page = page;
        unsigned long apply_start = page;
        unsigned long apply_end = page + page_size;
        /* 部分设备上单页 mprotect 去 X 不生效（syscall 仍返回 0）；bmx 在较小 VMA 内对整段 r-x 映射去 X 更可靠 */
        if (mode == 0) {
            unsigned long vma_sz = map_end - map_start;
            if (vma_sz > 0 && vma_sz <= (4UL * 1024 * 1024)) {
                apply_start = map_start;
                apply_end = map_end;
            }
        }
        my_mem_pages[page_idx].orig_prot = orig_prot;
        my_mem_pages[page_idx].nx_active = 0;
        my_mem_pages[page_idx].range_count = 0;
        membp_trace("[MEMBP] set: new slot page_idx=%d apply=[0x%lx,0x%lx) page_key=0x%lx vma_sz=0x%lx whole_vma=%d\n",
            page_idx,
            apply_start,
            apply_end,
            page,
            (unsigned long)(map_end - map_start),
            (mode == 0 && map_end > map_start && (unsigned long)(map_end - map_start) <= (4UL * 1024 * 1024)) ? 1 : 0);
        if (mem_page_fill_exec_alias_ranges(&my_mem_pages[page_idx], target_pid, addr, apply_start, apply_end) != 0) {
            my_mem_pages[page_idx].in_use = 0;
            my_mem_pages[page_idx].page = 0;
            my_mem_pages[page_idx].map_start = 0;
            my_mem_pages[page_idx].map_end = 0;
            my_mem_pages[page_idx].orig_prot = 0;
            my_mem_pages[page_idx].nx_active = 0;
            my_mem_pages[page_idx].range_count = 0;
            printf("设置内存断点失败: 无法解析可执行映射别名(文件偏移/inode) addr=0x%lx\n", addr);
            return -1;
        }
    } else {
        membp_trace("[MEMBP] set: reuse page_idx=%d range=[0x%lx,0x%lx) orig=0x%x nx_active=%d\n",
            page_idx,
            my_mem_pages[page_idx].map_start,
            my_mem_pages[page_idx].map_end,
            my_mem_pages[page_idx].orig_prot,
            my_mem_pages[page_idx].nx_active);
        if (my_mem_pages[page_idx].range_count <= 0) {
            my_mem_pages[page_idx].range_count = 1;
            my_mem_pages[page_idx].range_start[0] = my_mem_pages[page_idx].map_start;
            my_mem_pages[page_idx].range_end[0] = my_mem_pages[page_idx].map_end;
        }
    }
    int link_idx = find_mem_page_link(bp_idx, page_idx);
    if (link_idx < 0) {
        for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
            if (!my_mem_page_bp_links[i].in_use) {
                link_idx = i;
                break;
            }
        }
        if (link_idx < 0) return -1;
        my_mem_page_bp_links[link_idx].in_use = 1;
        my_mem_page_bp_links[link_idx].bp_idx = bp_idx;
        my_mem_page_bp_links[link_idx].page_idx = page_idx;
    }
    my_mem_breakpoints[bp_idx].in_use = 1;
    my_mem_breakpoints[bp_idx].addr = addr;
    my_mem_breakpoints[bp_idx].mode = mode;
    {
        int trap_prot = mem_page_compute_trap_prot(page_idx);
        int orig = my_mem_pages[page_idx].orig_prot;
        if (trap_prot == orig) {
            my_mem_breakpoints[bp_idx].in_use = 0;
            my_mem_breakpoints[bp_idx].addr = 0;
            my_mem_breakpoints[bp_idx].mode = 0;
            my_mem_page_bp_links[link_idx].in_use = 0;
            my_mem_page_bp_links[link_idx].bp_idx = -1;
            my_mem_page_bp_links[link_idx].page_idx = -1;
            if (count_mem_links_for_page(page_idx) == 0) {
                my_mem_pages[page_idx].in_use = 0;
                my_mem_pages[page_idx].page = 0;
                my_mem_pages[page_idx].map_start = 0;
                my_mem_pages[page_idx].map_end = 0;
                my_mem_pages[page_idx].orig_prot = 0;
                my_mem_pages[page_idx].nx_active = 0;
                my_mem_pages[page_idx].range_count = 0;
            }
            printf("设置内存断点失败: 当前映射权限无法用mprotect产生访问异常 addr=0x%lx mode=%d orig=0x%x\n", addr, mode, orig);
            return -1;
        }
        membp_trace("[MEMBP] set: mprotect page_idx=%d ranges=%d trap_prot=0x%x orig=0x%x removed=0x%x\n",
            page_idx, my_mem_pages[page_idx].range_count, trap_prot, orig, orig & ~trap_prot);
        if (mem_page_apply_prot_ex(pid, &my_mem_pages[page_idx], trap_prot, orig) == -1) {
            my_mem_breakpoints[bp_idx].in_use = 0;
            my_mem_breakpoints[bp_idx].addr = 0;
            my_mem_breakpoints[bp_idx].mode = 0;
            my_mem_page_bp_links[link_idx].in_use = 0;
            my_mem_page_bp_links[link_idx].bp_idx = -1;
            my_mem_page_bp_links[link_idx].page_idx = -1;
            if (count_mem_links_for_page(page_idx) == 0) {
                my_mem_pages[page_idx].in_use = 0;
                my_mem_pages[page_idx].page = 0;
                my_mem_pages[page_idx].map_start = 0;
                my_mem_pages[page_idx].map_end = 0;
                my_mem_pages[page_idx].orig_prot = 0;
                my_mem_pages[page_idx].nx_active = 0;
                my_mem_pages[page_idx].range_count = 0;
            }
            printf("设置内存断点失败: mprotect失败 page=0x%lx trap=0x%x\n", page, trap_prot);
            return -1;
        }
        int verify_prot = 0;
        int removed = orig & ~trap_prot;
        /* bmx 仅去掉 PROT_EXEC 时：部分 Android 上 mprotect 已返回 0，但 /proc/maps 仍短时显示 r-x，
         * 误判会回滚导致内存执行断点从未生效；纯去 EXEC 时以 syscall 成功为准，其它 removed 仍用 maps 校验。 */
        int maps_prot_mismatch = 0;
        if (query_map_prot(target_pid, addr, NULL, NULL, &verify_prot) == -1) {
            maps_prot_mismatch = 1;
        } else if (removed != 0 && (verify_prot & removed) != 0) {
            if (removed != PROT_EXEC)
                maps_prot_mismatch = 1;
        }
        if (removed == PROT_EXEC && (verify_prot & removed) != 0 && !maps_prot_mismatch) {
            membp_trace("[MEMBP] set: maps still has EXEC in verify=0x%x; accept (syscall mprotect OK)\n", verify_prot);
        }
        if (maps_prot_mismatch) {
            membp_trace("[MEMBP] set: maps verify fail rollback removed=0x%x verify=0x%x\n", removed, verify_prot);
            (void)mem_page_apply_prot_ex(pid, &my_mem_pages[page_idx], my_mem_pages[page_idx].orig_prot, my_mem_pages[page_idx].orig_prot);
            my_mem_breakpoints[bp_idx].in_use = 0;
            my_mem_breakpoints[bp_idx].addr = 0;
            my_mem_breakpoints[bp_idx].mode = 0;
            my_mem_page_bp_links[link_idx].in_use = 0;
            my_mem_page_bp_links[link_idx].bp_idx = -1;
            my_mem_page_bp_links[link_idx].page_idx = -1;
            if (count_mem_links_for_page(page_idx) == 0) {
                my_mem_pages[page_idx].in_use = 0;
                my_mem_pages[page_idx].page = 0;
                my_mem_pages[page_idx].map_start = 0;
                my_mem_pages[page_idx].map_end = 0;
                my_mem_pages[page_idx].orig_prot = 0;
                my_mem_pages[page_idx].nx_active = 0;
                my_mem_pages[page_idx].range_count = 0;
            }
            printf("设置内存断点失败: 页属性校验失败 addr=0x%lx removed=0x%x verify=0x%x\n", addr, removed, verify_prot);
            return -1;
        }
        my_mem_pages[page_idx].nx_active = (trap_prot != orig) ? 1 : 0;
        membp_trace("[MEMBP] set: OK bp_idx=%d page_idx=%d nx_active=%d range=[0x%lx,0x%lx) trap=0x%x\n",
            bp_idx,
            page_idx,
            my_mem_pages[page_idx].nx_active,
            my_mem_pages[page_idx].map_start,
            my_mem_pages[page_idx].map_end,
            trap_prot);
    }
    return bp_idx;
}

int clear_memory_breakpoint(pid_t pid, int idx) {
    if (idx < 0 || idx >= MEM_BP_MAX) return -1;
    if (!my_mem_breakpoints[idx].in_use) return 0;
    int pages_to_check[MEM_PAGE_MAX];
    int page_cnt = 0;
    for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
        if (!my_mem_page_bp_links[i].in_use) continue;
        if (my_mem_page_bp_links[i].bp_idx != idx) continue;
        int page_idx = my_mem_page_bp_links[i].page_idx;
        int seen = 0;
        for (int j = 0; j < page_cnt; j++) {
            if (pages_to_check[j] == page_idx) {
                seen = 1;
                break;
            }
        }
        if (!seen && page_cnt < MEM_PAGE_MAX) pages_to_check[page_cnt++] = page_idx;
        my_mem_page_bp_links[i].in_use = 0;
        my_mem_page_bp_links[i].bp_idx = -1;
        my_mem_page_bp_links[i].page_idx = -1;
    }
    my_mem_breakpoints[idx].in_use = 0;
    my_mem_breakpoints[idx].addr = 0;
    my_mem_breakpoints[idx].mode = 0;
    for (int i = 0; i < page_cnt; i++) {
        int page_idx = pages_to_check[i];
        if (page_idx < 0 || page_idx >= MEM_PAGE_MAX || !my_mem_pages[page_idx].in_use) continue;
        if (count_mem_links_for_page(page_idx) > 0) {
            int trap_prot = mem_page_compute_trap_prot(page_idx);
            int orig = my_mem_pages[page_idx].orig_prot;
            if (trap_prot != orig) {
                if (mem_page_apply_prot_ex(pid, &my_mem_pages[page_idx], trap_prot, orig) == 0) {
                    my_mem_pages[page_idx].nx_active = 1;
                }
            } else {
                if (my_mem_pages[page_idx].nx_active) {
                    (void)mem_page_apply_prot_ex(pid, &my_mem_pages[page_idx], orig, orig);
                }
                my_mem_pages[page_idx].nx_active = 0;
            }
            continue;
        }
        if (my_mem_pages[page_idx].nx_active) {
            (void)mem_page_apply_prot_ex(pid, &my_mem_pages[page_idx], my_mem_pages[page_idx].orig_prot, my_mem_pages[page_idx].orig_prot);
        }
        my_mem_pages[page_idx].in_use = 0;
        my_mem_pages[page_idx].page = 0;
        my_mem_pages[page_idx].map_start = 0;
        my_mem_pages[page_idx].map_end = 0;
        my_mem_pages[page_idx].orig_prot = 0;
        my_mem_pages[page_idx].nx_active = 0;
        my_mem_pages[page_idx].range_count = 0;
    }
    return 0;
}

int clear_all_memory_breakpoints(pid_t pid) {
    for (int i = 0; i < MEM_PAGE_MAX; i++) {
        if (!my_mem_pages[i].in_use) continue;
        if (my_mem_pages[i].nx_active) {
            (void)mem_page_apply_prot_ex(pid, &my_mem_pages[i], my_mem_pages[i].orig_prot, my_mem_pages[i].orig_prot);
        }
        my_mem_pages[i].in_use = 0;
        my_mem_pages[i].page = 0;
        my_mem_pages[i].map_start = 0;
        my_mem_pages[i].map_end = 0;
        my_mem_pages[i].orig_prot = 0;
        my_mem_pages[i].nx_active = 0;
        my_mem_pages[i].range_count = 0;
    }
    for (int i = 0; i < MEM_BP_MAX; i++) {
        my_mem_breakpoints[i].in_use = 0;
        my_mem_breakpoints[i].addr = 0;
        my_mem_breakpoints[i].mode = 0;
    }
    for (int i = 0; i < MEM_PAGE_BP_LINK_MAX; i++) {
        my_mem_page_bp_links[i].in_use = 0;
        my_mem_page_bp_links[i].bp_idx = -1;
        my_mem_page_bp_links[i].page_idx = -1;
    }
    clear_memory_hit_pages();
    stepping_mem_active = 0;
    stepping_mem_tid = 0;
    return 0;
}

void list_memory_breakpoints(void) {
    int count = 0;
    printf("\n--- 内存断点列表(页属性NX) ---\n");
    for (int i = 0; i < MEM_BP_MAX; i++) {
        if (!my_mem_breakpoints[i].in_use) continue;
        const char *mode = my_mem_breakpoints[i].mode == 1 ? "read" : (my_mem_breakpoints[i].mode == 2 ? "write" : (my_mem_breakpoints[i].mode == 3 ? "read/write" : "execute"));
        printf("idx=%d addr=0x%lx mode=%s\n", i, my_mem_breakpoints[i].addr, mode);
        count++;
    }
    if (count == 0) printf("无内存断点\n");
}

static void membp_log_active_pages(const char *reason) {
    char buf[2048];
    size_t off = 0;
    int n = 0;
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, "[MEMBP] %s: pages=", reason ? reason : "?");
    for (int i = 0; i < MEM_PAGE_MAX; i++) {
        if (!my_mem_pages[i].in_use) continue;
        if (off >= sizeof(buf) - 160) break;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            " [%d:0x%lx-0x%lx orig=0x%x nx=%d]",
            i,
            my_mem_pages[i].map_start,
            my_mem_pages[i].map_end,
            my_mem_pages[i].orig_prot,
            my_mem_pages[i].nx_active);
        n++;
        if (n >= 12) {
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, " ...");
            break;
        }
    }
    if (n == 0) off += (size_t)snprintf(buf + off, sizeof(buf) - off, " (none)");
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, " | bps=");
    n = 0;
    for (int i = 0; i < MEM_BP_MAX; i++) {
        if (!my_mem_breakpoints[i].in_use) continue;
        if (off >= sizeof(buf) - 120) break;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, " [%d:0x%lx m%d]", i, my_mem_breakpoints[i].addr, my_mem_breakpoints[i].mode);
        n++;
        if (n >= 16) {
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, " ...");
            break;
        }
    }
    if (n == 0) off += (size_t)snprintf(buf + off, sizeof(buf) - off, "(none)");
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, "\n");
    membp_trace("%s", buf);
}

static int find_memory_page_for_fault(unsigned long fault_addr) {
    return find_mem_page_containing_addr(fault_addr);
}

void clear_memory_hit_pages(void) {
    for (int i = 0; i < MEM_HIT_PAGE_MAX; i++) {
        my_mem_hit_pages[i].in_use = 0;
        my_mem_hit_pages[i].page_idx = -1;
        my_mem_hit_pages[i].fault_pc = 0;
    }
}

// 功能：处理断点增删改查与命中后的状态同步。
int step_past_soft_breakpoint(pid_t pid, int bp_idx, unsigned long bp_addr, int resume_after_step, int step_over_mode) {
    if (bp_idx < 0 || bp_idx >= SW_BP_MAX || !my_soft_breakpoints[bp_idx].in_use) return -1;
    uint32_t orig = my_soft_breakpoints[bp_idx].orig_insn;
    if (write_u32(pid, bp_addr, orig) == -1) return -1;
    if (set_pc(pid, bp_addr) == -1) {
        write_u32(pid, bp_addr, get_brk_instruction());
        return -1;
    }
    if (step_over_mode && is_call_instruction(orig)) {
        unsigned long return_addr = bp_addr + 4;
        step_over_source_bp_idx = -1;
        step_over_source_soft_bp_idx = bp_idx;
        step_over_source_bp_addr = bp_addr;
        step_over_temp_bp_idx = set_hardware_breakpoint(pid, return_addr, -1);
        if (step_over_temp_bp_idx == -1) {
            write_u32(pid, bp_addr, get_brk_instruction());
            return -1;
        }
        step_over_active = 1;
        step_over_return_addr = return_addr;
    } else {
        step_over_source_soft_bp_idx = -1;
    }
    stepping_soft_active = 1;
    stepping_soft_idx = bp_idx;
    stepping_soft_addr = bp_addr;
    stepping_soft_resume = resume_after_step;
    stepping_soft_step_over = step_over_active ? 1 : 0;
    stepping_soft_tid = pid;
    current_soft_hit_idx = -1;
    current_soft_hit_addr = 0;
    if (single_step(pid) == -1) {
        stepping_soft_active = 0;
        stepping_soft_idx = -1;
        stepping_soft_addr = 0;
        stepping_soft_resume = 0;
        stepping_soft_step_over = 0;
        stepping_soft_tid = 0;
        write_u32(pid, bp_addr, get_brk_instruction());
        return -1;
    }
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
int step_past_breakpoint(pid_t pid, int bp_idx, unsigned long bp_addr, int resume_after_step) {
    if (bp_idx < 0) return -1;
    if (clear_breakpoint(pid, bp_idx) == -1) return -1;
    stepping_bp_active = 1;
    stepping_bp_idx = bp_idx;
    stepping_bp_addr = bp_addr;
    stepping_bp_resume = resume_after_step;
    if (single_step(pid) == -1) {
        stepping_bp_active = 0;
        stepping_bp_idx = -1;
        stepping_bp_addr = 0;
        stepping_bp_resume = 0;
        set_hardware_breakpoint(pid, bp_addr, bp_idx);
        return -1;
    }
    return 0;
}

// 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
int step_past_watchpoint(pid_t pid, int wp_idx, int resume_after_step) {
    if (wp_idx < 0 || wp_idx >= HW_WP_MAX || !my_watchpoints[wp_idx].in_use) return -1;
    if (sync_hw_watchpoints_for_thread(pid, wp_idx) == -1) return -1;
    stepping_watch_active = 1;
    stepping_watch_idx = wp_idx;
    stepping_watch_mode = my_watchpoints[wp_idx].mode;
    stepping_watch_addr = my_watchpoints[wp_idx].addr_raw ? my_watchpoints[wp_idx].addr_raw : my_watchpoints[wp_idx].addr;
    stepping_watch_resume = resume_after_step;
    stepping_watch_tid = pid;
    current_watch_hit_idx = -1;
    current_watch_hit_addr = 0;
    if (single_step(pid) == -1) {
        stepping_watch_active = 0;
        stepping_watch_idx = -1;
        stepping_watch_mode = 0;
        stepping_watch_addr = 0;
        stepping_watch_resume = 0;
        stepping_watch_tid = 0;
        sync_hw_watchpoints(pid);
        return -1;
    }
    return 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
void list_breakpoints(void) {
    int count = 0;
    printf("\n--- 硬件断点列表 ---\n");
    for (int i = 0; i < HW_BP_MAX; i++) {
        if (my_breakpoints[i].in_use) {
            printf("idx=%d type=execute addr=0x%lx ctrl=0x%x\n", i, my_breakpoints[i].addr, my_breakpoints[i].ctrl);
            count++;
        }
    }
    for (int i = 0; i < HW_WP_MAX; i++) {
        if (my_watchpoints[i].in_use) {
            const char *mode = my_watchpoints[i].mode == 1 ? "read" : (my_watchpoints[i].mode == 2 ? "write" : "read/write");
            printf("idx=%d type=%s addr=0x%lx ctrl=0x%x\n", i, mode, my_watchpoints[i].addr, my_watchpoints[i].ctrl);
            count++;
        }
    }
    if (count == 0) printf("无硬件断点\n");
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void list_watchpoints(void) {
    int count = 0;
    printf("\n--- 内存属性断点列表 ---\n");
    for (int i = 0; i < HW_WP_MAX; i++) {
        if (my_watchpoints[i].in_use) {
            const char *mode = my_watchpoints[i].mode == 1 ? "read" : (my_watchpoints[i].mode == 2 ? "write" : "read/write");
            printf("idx=%d addr=0x%lx ctrl=0x%x mode=%s\n", i, my_watchpoints[i].addr, my_watchpoints[i].ctrl, mode);
            count++;
        }
    }
    if (count == 0) printf("无内存属性断点\n");
}

// 功能：处理断点增删改查与命中后的状态同步。
void list_soft_breakpoints(void) {
    int count = 0;
    printf("\n--- 软件断点列表(BRK) ---\n");
    for (int i = 0; i < SW_BP_MAX; i++) {
        if (my_soft_breakpoints[i].in_use) {
            const char *mode = my_soft_breakpoints[i].mode == 1 ? "read" : (my_soft_breakpoints[i].mode == 2 ? "write" : (my_soft_breakpoints[i].mode == 3 ? "read/write" : "execute"));
            printf("idx=%d type=%s addr=0x%lx orig=0x%08x\n", i, mode, my_soft_breakpoints[i].addr, my_soft_breakpoints[i].orig_insn);
            count++;
        }
    }
    if (count == 0) printf("无软件断点\n");
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int is_call_instruction(uint32_t insn) {
    if ((insn & 0xFC000000) == 0x94000000) return 1;
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) return 1;
    // 覆盖常见指针认证调用变体：BLRAA/BLRAB/BLRAAZ/BLRABZ
    if ((insn & 0xFFFFFC00) == 0xD73F0800) return 1;
    if ((insn & 0xFFFFFC00) == 0xD73F0C00) return 1;
    return 0;
}

// 功能：初始化调试组件状态与运行所需资源。
int init_capstone(void) {
    if (capstone_ready != -1) return capstone_ready == 1 ? 0 : -1;
    const char *paths[] = {
        "libcapstone.so.5",
        "libcapstone.so",
        "libcapstone.so.4",
        "libcapstone.so.3",
        "/data/local/tmp/libcapstone.so",
        "/data/data/com.termux/files/usr/lib/libcapstone.so",
        "/system/lib64/libcapstone.so",
        "/system/lib/libcapstone.so"
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        capstone_lib = dlopen(paths[i], RTLD_NOW);
        if (capstone_lib) break;
    }
    if (!capstone_lib) {
        capstone_ready = 0;
        return -1;
    }
    p_cs_open = (cs_err_t (*)(cs_arch_t, cs_mode_t, csh_t*))dlsym(capstone_lib, "cs_open");
    p_cs_disasm = (size_t (*)(csh_t, const uint8_t*, size_t, uint64_t, size_t, cs_insn_t**))dlsym(capstone_lib, "cs_disasm");
    p_cs_free = (void (*)(cs_insn_t*, size_t))dlsym(capstone_lib, "cs_free");
    p_cs_close = (cs_err_t (*)(csh_t*))dlsym(capstone_lib, "cs_close");
    p_cs_option = (cs_err_t (*)(csh_t, size_t, size_t))dlsym(capstone_lib, "cs_option");
    if (!p_cs_open || !p_cs_disasm || !p_cs_free || !p_cs_close) {
        dlclose(capstone_lib);
        capstone_lib = NULL;
        capstone_ready = 0;
        return -1;
    }
    csh_t h = 0;
    if (p_cs_open(1, 0, &h) != 0) {
        dlclose(capstone_lib);
        capstone_lib = NULL;
        capstone_ready = 0;
        return -1;
    }
    capstone_handle = h;
    if (p_cs_option) {
        p_cs_option(h, 2, 3);
    }
    capstone_ready = 1;
    return 0;
}

// 功能：初始化调试组件状态与运行所需资源。
int init_keystone(void) {
    if (keystone_ready != -1) return keystone_ready == 1 ? 0 : -1;
    const char *paths[] = {
        "libkeystone.so",
        "libkeystone.so.1",
        "/data/local/tmp/libkeystone.so",
        "/data/data/com.termux/files/usr/lib/libkeystone.so",
        "/system/lib64/libkeystone.so",
        "/system/lib/libkeystone.so"
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        keystone_lib = dlopen(paths[i], RTLD_NOW);
        if (keystone_lib) break;
    }
    if (!keystone_lib) {
        keystone_ready = 0;
        return -1;
    }
    p_ks_open = (ks_err_t (*)(ks_arch_t, ks_mode_t, ks_engine_t**))dlsym(keystone_lib, "ks_open");
    p_ks_asm = (int (*)(ks_engine_t*, const char*, uint64_t, unsigned char**, size_t*, size_t*))dlsym(keystone_lib, "ks_asm");
    p_ks_free = (void (*)(unsigned char*))dlsym(keystone_lib, "ks_free");
    p_ks_close = (ks_err_t (*)(ks_engine_t*))dlsym(keystone_lib, "ks_close");
    if (!p_ks_open || !p_ks_asm || !p_ks_free || !p_ks_close) {
        dlclose(keystone_lib);
        keystone_lib = NULL;
        keystone_ready = 0;
        return -1;
    }
    ks_engine_t *ks = NULL;
    if (p_ks_open(1, 0, &ks) != 0 || !ks) {
        dlclose(keystone_lib);
        keystone_lib = NULL;
        keystone_ready = 0;
        return -1;
    }
    keystone_handle = (size_t)ks;
    keystone_ready = 1;
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
uint32_t get_brk_instruction(void) {
    if (init_keystone() == 0) {
        unsigned char *enc = NULL;
        size_t size = 0;
        size_t count = 0;
        if (p_ks_asm((ks_engine_t*)keystone_handle, "brk #0", 0, &enc, &size, &count) == 0 && enc && size >= 4) {
            uint32_t v = (uint32_t)enc[0] | ((uint32_t)enc[1] << 8) | ((uint32_t)enc[2] << 16) | ((uint32_t)enc[3] << 24);
            p_ks_free(enc);
            return v;
        }
        if (enc) p_ks_free(enc);
    }
    return 0xD4200000U;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int assemble_and_write(pid_t pid, unsigned long addr, const char *asm_text) {
    if (!asm_text || !*asm_text) return -1;
    if (init_keystone() != 0) {
        printf("asm失败: keystone未就绪\n");
        return -1;
    }
    unsigned char *enc = NULL;
    size_t size = 0;
    size_t count = 0;
    if (p_ks_asm((ks_engine_t*)keystone_handle, asm_text, (uint64_t)addr, &enc, &size, &count) != 0 || !enc || size == 0) {
        if (enc) p_ks_free(enc);
        printf("asm失败: 指令无法汇编\n");
        return -1;
    }
    for (size_t i = 0; i < size; i++) {
        if (write_u8(pid, addr + (unsigned long)i, enc[i]) == -1) {
            p_ks_free(enc);
            printf("asm失败: 写入目标内存失败\n");
            return -1;
        }
    }
    p_ks_free(enc);
    printf("asm写入成功: addr=0x%lx bytes=%zu\n", addr, size);
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int capstone_disassemble(pid_t pid, unsigned long addr, int lines, unsigned long center, int mark_center) {
    if (lines <= 0) return -1;
    if (init_capstone() == -1) return -1;
    size_t code_size = (size_t)lines * 4;
    uint8_t *code = (uint8_t*)malloc(code_size);
    if (!code) return -1;
    for (int i = 0; i < lines; i++) {
        uint32_t insn = read_u32(pid, addr + (unsigned long)i * 4UL);
        code[i * 4 + 0] = (uint8_t)(insn & 0xff);
        code[i * 4 + 1] = (uint8_t)((insn >> 8) & 0xff);
        code[i * 4 + 2] = (uint8_t)((insn >> 16) & 0xff);
        code[i * 4 + 3] = (uint8_t)((insn >> 24) & 0xff);
    }
    cs_insn_t *insn = NULL;
    size_t count = p_cs_disasm((csh_t)capstone_handle, code, code_size, (uint64_t)addr, (size_t)lines, &insn);
    free(code);
    if (count == 0 || !insn) return -1;
    for (size_t i = 0; i < count; i++) {
        unsigned long a = (unsigned long)insn[i].address;
        uint32_t raw = read_u32(pid, a);
        char bytes[32];
        format_u32_bytes(raw, bytes, sizeof(bytes));
        char mod[256] = {0};
        int has_mod = describe_address(target_pid, a, mod, sizeof(mod)) == 0;
        if (has_mod) {
            printf("%s 0x%016lx (%s): %s  %s %s\n",
                (mark_center && a == center) ? "=>" : "  ",
                a,
                mod,
                bytes,
                insn[i].mnemonic,
                insn[i].op_str);
        } else {
            printf("%s 0x%016lx: %s  %s %s\n",
                (mark_center && a == center) ? "=>" : "  ",
                a,
                bytes,
                insn[i].mnemonic,
                insn[i].op_str);
        }
    }
    p_cs_free(insn, count);
    return 0;
}

// 功能：处理反汇编数据请求与渲染，维护指令视图定位与刷新。
int init_disasm_tool(void) {
    if (disasm_tool[0] != '\0') return 0;
    FILE *fp = popen("llvm-objdump --version 2>/dev/null", "r");
    if (fp) {
        pclose(fp);
        strcpy(disasm_tool, "llvm-objdump");
        return 0;
    }
    fp = popen("/system/bin/llvm-objdump --version 2>/dev/null", "r");
    if (fp) {
        pclose(fp);
        strcpy(disasm_tool, "/system/bin/llvm-objdump");
        return 0;
    }
    return -1;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int llvm_disassemble_collect(pid_t pid, unsigned long addr, int lines, unsigned long center, int mark_center, char out[][VIEW_LEFT_WIDTH], int max_lines, int *out_count) {
    if (lines <= 0) return -1;
    if (init_disasm_tool() == -1) return -1;

    char tmp[] = "/data/local/tmp/hwdasmXXXXXX";
    int fd = mkstemp(tmp);
    if (fd == -1) return -1;

    for (int i = 0; i < lines; i++) {
        uint32_t insn = read_u32(pid, addr + (unsigned long)i * 4UL);
        uint8_t b[4];
        b[0] = (uint8_t)(insn & 0xff);
        b[1] = (uint8_t)((insn >> 8) & 0xff);
        b[2] = (uint8_t)((insn >> 16) & 0xff);
        b[3] = (uint8_t)((insn >> 24) & 0xff);
        if (write(fd, b, 4) != 4) {
            close(fd);
            unlink(tmp);
            return -1;
        }
    }
    close(fd);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s -D --triple=aarch64 -b binary --adjust-vma=0x%lx %s 2>/dev/null", disasm_tool, addr, tmp);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        unlink(tmp);
        return -1;
    }

    char line[1024];
    int printed = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!isxdigit((unsigned char)*p)) {
            continue;
        }
        char *colon = strchr(p, ':');
        if (!colon) continue;
        *colon = '\0';
        char *end = NULL;
        unsigned long a = strtoul(p, &end, 16);
        *colon = ':';
        if (end == p) continue;
        char *body = colon + 1;
        while (*body == ' ' || *body == '\t') body++;
        size_t l = strlen(body);
        if (l > 0 && body[l - 1] == '\n') body[l - 1] = '\0';
        char mod[256] = {0};
        int has_mod = describe_address(target_pid, a, mod, sizeof(mod)) == 0;
        if (out && printed < max_lines) {
            if (has_mod) snprintf(out[printed], VIEW_LEFT_WIDTH, "%s0x%016lx (%s): %s", (mark_center && a == center) ? "=> " : "   ", a, mod, body);
            else snprintf(out[printed], VIEW_LEFT_WIDTH, "%s0x%016lx: %s", (mark_center && a == center) ? "=> " : "   ", a, body);
        } else {
            if (has_mod) printf("%s0x%016lx (%s): %s\n", (mark_center && a == center) ? "=> " : "   ", a, mod, body);
            else printf("%s0x%016lx: %s\n", (mark_center && a == center) ? "=> " : "   ", a, body);
        }
        printed++;
    }

    pclose(fp);
    unlink(tmp);
    if (out_count) *out_count = printed;
    if (printed == 0) return -1;
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int external_disassemble(pid_t pid, unsigned long addr, int lines, unsigned long center, int mark_center) {
    return llvm_disassemble_collect(pid, addr, lines, center, mark_center, NULL, 0, NULL);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void decode_arm64(uint32_t insn, unsigned long pc, char *out, size_t out_size) {
    static const char *cond_name[16] = {
        "eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"
    };
    if ((insn & 0xFFE0001F) == 0xD4000001) {
        unsigned imm16 = (insn >> 5) & 0xffff;
        snprintf(out, out_size, "svc #0x%x", imm16);
        return;
    }
    if ((insn & 0x9F000000) == 0x90000000) {
        long immhi = (long)((insn >> 5) & 0x7ffff);
        long immlo = (long)((insn >> 29) & 0x3);
        long imm = sign_extend((unsigned long)((immhi << 2) | immlo), 21) << 12;
        int rd = insn & 0x1f;
        unsigned long page = pc & ~0xfffUL;
        snprintf(out, out_size, "adrp x%d, 0x%lx", rd, page + (unsigned long)imm);
        return;
    }
    if ((insn & 0x9F000000) == 0x10000000) {
        long immhi = (long)((insn >> 5) & 0x7ffff);
        long immlo = (long)((insn >> 29) & 0x3);
        long imm = sign_extend((unsigned long)((immhi << 2) | immlo), 21);
        int rd = insn & 0x1f;
        snprintf(out, out_size, "adr x%d, 0x%lx", rd, pc + (unsigned long)imm);
        return;
    }
    if (insn == 0xD503201F) {
        snprintf(out, out_size, "nop");
        return;
    }
    if (insn == 0xD503245F) {
        snprintf(out, out_size, "bti c");
        return;
    }
    if (insn == 0xD503249F) {
        snprintf(out, out_size, "bti j");
        return;
    }
    if (insn == 0xD50324DF) {
        snprintf(out, out_size, "bti jc");
        return;
    }
    if ((insn & 0xFC000000) == 0x14000000) {
        long imm = sign_extend(insn & 0x03ffffff, 26) << 2;
        snprintf(out, out_size, "b 0x%lx", pc + (unsigned long)imm);
        return;
    }
    if ((insn & 0xFC000000) == 0x94000000) {
        long imm = sign_extend(insn & 0x03ffffff, 26) << 2;
        snprintf(out, out_size, "bl 0x%lx", pc + (unsigned long)imm);
        return;
    }
    if ((insn & 0xFFFFFC1F) == 0xD61F0000) {
        int rn = (insn >> 5) & 0x1f;
        snprintf(out, out_size, "br x%d", rn);
        return;
    }
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) {
        int rn = (insn >> 5) & 0x1f;
        snprintf(out, out_size, "blr x%d", rn);
        return;
    }
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        int rn = (insn >> 5) & 0x1f;
        snprintf(out, out_size, "ret x%d", rn);
        return;
    }
    if ((insn & 0xFF000010) == 0x54000000) {
        long imm = sign_extend((insn >> 5) & 0x7ffff, 19) << 2;
        int cond = insn & 0xf;
        snprintf(out, out_size, "b.%s 0x%lx", cond_name[cond], pc + (unsigned long)imm);
        return;
    }
    if ((insn & 0x7F000000) == 0x34000000 || (insn & 0x7F000000) == 0x35000000) {
        int sf = (insn >> 31) & 1;
        int rt = insn & 0x1f;
        long imm = sign_extend((insn >> 5) & 0x7ffff, 19) << 2;
        const char *mn = ((insn & 0x7F000000) == 0x34000000) ? "cbz" : "cbnz";
        snprintf(out, out_size, "%s %c%d, 0x%lx", mn, sf ? 'x' : 'w', rt, pc + (unsigned long)imm);
        return;
    }
    if ((insn & 0x7FE0FC00) == 0x2A000000) {
        int sf = (insn >> 31) & 1;
        int shift = (insn >> 22) & 0x3;
        int rm = (insn >> 16) & 0x1f;
        int imm6 = (insn >> 10) & 0x3f;
        int rn = (insn >> 5) & 0x1f;
        int rd = insn & 0x1f;
        if (shift == 0 && imm6 == 0 && rn == 31) {
            snprintf(out, out_size, "mov %c%d, %c%d", sf ? 'x' : 'w', rd, sf ? 'x' : 'w', rm);
            return;
        }
        snprintf(out, out_size, "orr %c%d, %c%d, %c%d", sf ? 'x' : 'w', rd, sf ? 'x' : 'w', rn, sf ? 'x' : 'w', rm);
        return;
    }
    if ((insn & 0x1F000000) == 0x11000000) {
        int sf = (insn >> 31) & 1;
        int op = (insn >> 30) & 1;
        int s = (insn >> 29) & 1;
        int rn = (insn >> 5) & 0x1f;
        int rd = insn & 0x1f;
        unsigned imm12 = (insn >> 10) & 0xfff;
        int sh = (insn >> 22) & 1;
        unsigned imm = sh ? (imm12 << 12) : imm12;
        if (s && rd == 31) {
            if (rn == 31) snprintf(out, out_size, "%s sp, #%u", op ? "cmp" : "cmn", imm);
            else snprintf(out, out_size, "%s %c%d, #%u", op ? "cmp" : "cmn", sf ? 'x' : 'w', rn, imm);
            return;
        }
        if (!s && rn == 31 && imm == 0) {
            snprintf(out, out_size, "mov %c%d, sp", sf ? 'x' : 'w', rd);
            return;
        }
        const char *mn = op ? (s ? "subs" : "sub") : (s ? "adds" : "add");
        if (!s && (rd == 31 || rn == 31)) {
            char rd_name[8];
            char rn_name[8];
            if (rd == 31) strcpy(rd_name, "sp");
            else snprintf(rd_name, sizeof(rd_name), "%c%d", sf ? 'x' : 'w', rd);
            if (rn == 31) strcpy(rn_name, "sp");
            else snprintf(rn_name, sizeof(rn_name), "%c%d", sf ? 'x' : 'w', rn);
            snprintf(out, out_size, "%s %s, %s, #%u", mn, rd_name, rn_name, imm);
            return;
        }
        snprintf(out, out_size, "%s %c%d, %c%d, #%u", mn, sf ? 'x' : 'w', rd, sf ? 'x' : 'w', rn, imm);
        return;
    }
    if ((insn & 0x3B200C00) == 0x38000000) {
        int size = (insn >> 30) & 0x3;
        int v = (insn >> 26) & 1;
        int opc = (insn >> 22) & 0x3;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        int imm9 = (int)sign_extend((unsigned long)((insn >> 12) & 0x1ff), 9);
        if (v == 0 && (size == 2 || size == 3)) {
            char rn_name[8];
            if (rn == 31) strcpy(rn_name, "sp");
            else snprintf(rn_name, sizeof(rn_name), "x%d", rn);
            if (opc == 0) {
                snprintf(out, out_size, "stur %c%d, [%s, #%d]", size == 3 ? 'x' : 'w', rt, rn_name, imm9);
                return;
            }
            if (opc == 1) {
                snprintf(out, out_size, "ldur %c%d, [%s, #%d]", size == 3 ? 'x' : 'w', rt, rn_name, imm9);
                return;
            }
        }
    }
    if ((insn & 0x3F000000) == 0x28000000 || (insn & 0x3F000000) == 0x29000000) {
        int opc = (insn >> 30) & 0x3;
        if (opc != 0 && opc != 2) {
            snprintf(out, out_size, ".word 0x%08x", insn);
            return;
        }
        int l = (insn >> 22) & 1;
        int mode = (insn >> 23) & 0x3;
        int rt2 = (insn >> 10) & 0x1f;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        int scale = opc == 2 ? 8 : 4;
        int imm7 = (int)sign_extend((unsigned long)((insn >> 15) & 0x7f), 7) * scale;
        const char *mn = l ? "ldp" : "stp";
        char rn_name[8];
        if (rn == 31) strcpy(rn_name, "sp");
        else snprintf(rn_name, sizeof(rn_name), "x%d", rn);
        char rt_prefix = opc == 2 ? 'x' : 'w';
        if (mode == 3) {
            snprintf(out, out_size, "%s %c%d, %c%d, [%s, #%d]!", mn, rt_prefix, rt, rt_prefix, rt2, rn_name, imm7);
            return;
        }
        if (mode == 1) {
            snprintf(out, out_size, "%s %c%d, %c%d, [%s], #%d", mn, rt_prefix, rt, rt_prefix, rt2, rn_name, imm7);
            return;
        }
        snprintf(out, out_size, "%s %c%d, %c%d, [%s, #%d]", mn, rt_prefix, rt, rt_prefix, rt2, rn_name, imm7);
        return;
    }
    if ((insn & 0x7F800000) == 0x52800000 || (insn & 0x7F800000) == 0x72800000 || (insn & 0x7F800000) == 0x12800000) {
        int sf = (insn >> 31) & 1;
        int opc = (insn >> 29) & 0x3;
        int hw = (insn >> 21) & 0x3;
        int rd = insn & 0x1f;
        unsigned imm16 = (insn >> 5) & 0xffff;
        const char *mn = opc == 2 ? "movz" : (opc == 3 ? "movk" : "movn");
        snprintf(out, out_size, "%s %c%d, #0x%x, lsl #%d", mn, sf ? 'x' : 'w', rd, imm16, hw * 16);
        return;
    }
    if ((insn & 0xFFC00000) == 0xD2800000) {
        int rd = insn & 0x1f;
        unsigned imm16 = (insn >> 5) & 0xffff;
        int hw = (insn >> 21) & 0x3;
        snprintf(out, out_size, "movz x%d, #0x%x, lsl #%d", rd, imm16, hw * 16);
        return;
    }
    if ((insn & 0x3B000000) == 0x39000000) {
        int size = (insn >> 30) & 0x3;
        int is_load = (insn >> 22) & 1;
        int rn = (insn >> 5) & 0x1f;
        int rt = insn & 0x1f;
        unsigned imm12 = (insn >> 10) & 0xfff;
        unsigned scale = (unsigned)(1U << size);
        unsigned off = imm12 * scale;
        snprintf(out, out_size, "%s %c%d, [x%d, #%u]", is_load ? "ldr" : "str", size == 3 ? 'x' : 'w', rt, rn, off);
        return;
    }
    snprintf(out, out_size, ".word 0x%08x", insn);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void disassemble_window(pid_t pid, unsigned long center, int before, int after) {
    unsigned long start = center >= (unsigned long)before * 4UL ? center - (unsigned long)before * 4UL : 0;
    int total = before + after + 1;
    printf("\n--- 反汇编上下文 ---\n");
    if (capstone_disassemble(pid, start, total, center, 1) == 0) return;
    for (int i = 0; i < total; i++) {
        unsigned long addr = start + (unsigned long)i * 4UL;
        uint32_t insn = read_u32(pid, addr);
        char text[128];
        char bytes[32];
        decode_arm64(insn, addr, text, sizeof(text));
        format_u32_bytes(insn, bytes, sizeof(bytes));
        char mod[256] = {0};
        int has_mod = describe_address(target_pid, addr, mod, sizeof(mod)) == 0;
        if (has_mod) printf("%s 0x%016lx (%s): %s  %s\n", addr == center ? "=>" : "  ", addr, mod, bytes, text);
        else printf("%s 0x%016lx: %s  %s\n", addr == center ? "=>" : "  ", addr, bytes, text);
    }
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void disassemble_from(pid_t pid, unsigned long addr, int lines) {
    if (lines <= 0) lines = 20;
    printf("\n--- 反汇编 ---\n");
    if (capstone_disassemble(pid, addr, lines, 0, 0) == 0) return;
    for (int i = 0; i < lines; i++) {
        unsigned long a = addr + (unsigned long)i * 4UL;
        uint32_t insn = read_u32(pid, a);
        char text[128];
        char bytes[32];
        decode_arm64(insn, a, text, sizeof(text));
        format_u32_bytes(insn, bytes, sizeof(bytes));
        char mod[256] = {0};
        int has_mod = describe_address(target_pid, a, mod, sizeof(mod)) == 0;
        if (has_mod) printf("   0x%016lx (%s): %s  %s\n", a, mod, bytes, text);
        else printf("   0x%016lx: %s  %s\n", a, bytes, text);
    }
}

// 功能：按序号分片发送反汇编结果，支持客户端排序、校验与完整性判断。
void disassemble_from_pkt(pid_t pid, unsigned long addr, int lines) {
    if (lines <= 0) lines = 20;
    unsigned long sid = g_disasm_pkt_session++;
    unsigned long pc_now = get_pc(pid);
    int sent = 0;
    for (int i = 0; i < lines; i++) {
        unsigned long a = addr + (unsigned long)i * 4UL;
        uint32_t insn = read_u32(pid, a);
        char text[128];
        char bytes[32];
        char payload[512];
        char payload_hex[1024];
        decode_arm64(insn, a, text, sizeof(text));
        format_u32_bytes(insn, bytes, sizeof(bytes));
        char mod[256] = {0};
        int has_mod = describe_address(target_pid, a, mod, sizeof(mod)) == 0;
        const char *prefix = (a == pc_now) ? "=> " : "   ";
        if (has_mod) snprintf(payload, sizeof(payload), "%s0x%016lx (%s): %s  %s", prefix, a, mod, bytes, text);
        else snprintf(payload, sizeof(payload), "%s0x%016lx: %s  %s", prefix, a, bytes, text);

        uint32_t crc = fnv1a32_str(payload);
        hex_encode_str(payload, payload_hex, sizeof(payload_hex));
        if (printf("[PKT]|DISASMSEQ|sid=%lu;seq=%d;total=%d;crc=%08X|%s\n", sid, i + 1, lines, crc, payload_hex) < 0) {
            break;
        }
        sent++;
    }
    // 结束包按“实际发送数量”回传，避免客户端误判缺片
    printf("[PKT]|DISASMSEQ_END|sid=%lu;total=%d|ok\n", sid, sent);
    printf("[PKT]|LOG|sid=%lu asked=%d sent=%d\n", sid, lines, sent);
    fflush(stdout);
}

// 功能：执行内存/模块转储，用于离线分析目标数据。
void dump_dword(pid_t pid, unsigned long addr, int lines) {
    if (lines <= 0) lines = 5;
    printf("\n--- dd 0x%lx ---\n", addr);
    for (int l = 0; l < lines; l++) {
        unsigned long line_addr = addr + (unsigned long)l * 16UL * 4UL;
        printf("0x%016lx: ", line_addr);
        for (int i = 0; i < 16; i++) {
            uint32_t v = read_u32(pid, line_addr + (unsigned long)i * 4UL);
            printf("%08x ", v);
        }
        printf("\n");
    }
}

// 功能：执行内存/模块转储，用于离线分析目标数据。
void dump_qword(pid_t pid, unsigned long addr, int lines) {
    if (lines <= 0) lines = 5;
    printf("\n--- dq 0x%lx ---\n", addr);
    for (int l = 0; l < lines; l++) {
        unsigned long line_addr = addr + (unsigned long)l * 2UL * 8UL;
        printf("0x%016lx: ", line_addr);
        for (int i = 0; i < 2; i++) {
            unsigned long long v = read_u64(pid, line_addr + (unsigned long)i * 8UL);
            printf("%016llx ", v);
        }
        printf("\n");
    }
}

// 功能：执行内存/模块转储，用于离线分析目标数据。
void dump_word(pid_t pid, unsigned long addr, int lines) {
    if (lines <= 0) lines = 5;
    printf("\n--- dw 0x%lx ---\n", addr);
    for (int l = 0; l < lines; l++) {
        unsigned long line_addr = addr + (unsigned long)l * 16UL * 2UL;
        printf("0x%016lx: ", line_addr);
        for (int i = 0; i < 16; i++) {
            uint16_t v = read_u16(pid, line_addr + (unsigned long)i * 2UL);
            printf("%04x ", v);
        }
        printf("\n");
    }
}

// 功能：执行内存/模块转储，用于离线分析目标数据。
void dump_byte(pid_t pid, unsigned long addr, int lines) {
    if (lines <= 0) lines = 5;
    printf("\n--- db 0x%lx ---\n", addr);
    for (int l = 0; l < lines; l++) {
        unsigned long line_addr = addr + (unsigned long)l * 16UL;
        printf("0x%016lx: ", line_addr);
        for (int i = 0; i < 16; i++) {
            uint8_t v = read_u8(pid, line_addr + (unsigned long)i);
            printf("%02x ", v);
        }
        printf("\n");
    }
}

// 功能：输出调试命令帮助信息，说明可用控制指令。
void show_help(void) {
    const int W = 34;
    printf("\n可用命令:\n");
    printf("%-*s| %-*s| %-*s\n", W, "c                  单步步入", W, "n                  单步步过", W, "r                  继续运行/改寄存器");
    printf("%-*s| %-*s| %-*s\n", W, "q                  退出调试器", W, "bhx <addr>         硬件执行断点", W, "bhr <addr>         硬件读断点");
    printf("%-*s| %-*s| %-*s\n", W, "bhw <addr>         硬件写断点", W, "bha <addr>         硬件读写断点", W, "bhc <idx|addr|all> 删硬件断点");
    printf("%-*s| %-*s| %-*s\n", W, "bhl                查看所有硬件断点", W, "brk <addr>         软件执行断点", W, "brkc <idx|addr|all> 删软件断点");
    printf("%-*s| %-*s| %-*s\n", W, "brkl               查看软件断点", W, "bmx <addr>         内存执行断点", W, "bmr <addr>         内存读断点");
    printf("%-*s| %-*s| %-*s\n", W, "bmw <addr>         内存写断点", W, "bma <addr>         内存读写断点", W, "bmc <idx|addr|all> 删内存断点");
    printf("%-*s| %-*s| %-*s\n", W, "bml                查看内存断点", W, "u <addr> [行数]    反汇编", W, "upkt <addr> [行数] 分片反汇编");
    printf("%-*s| %-*s| %-*s\n", W, "dd <addr> [行数]   4字节显示", W, "dw <addr> [行数]   2字节显示", W, "db <addr> [行数]   1字节显示");
    printf("%-*s| %-*s| %-*s\n", W, "dq <addr> [行数]   8字节显示", W, "wm <addr> <v> <n>  写内存(1/2/4/8字节)", W, "asm <addr> <insn>  写汇编");
    printf("%-*s| %-*s| %-*s\n", W, "ml                 进程模块列表", W, "tl                 进程线程信息", W, " ");
    printf("%-*s| %-*s\n", W, "cls                清屏", W, "help               显示帮助");
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void list_modules(pid_t pid) {
    typedef struct {
        char name[256];
        unsigned long start;
        unsigned long end;
        unsigned long text_start;
        int has_text;
        int r;
        int w;
        int x;
        int p;
        int s;
        int segs;
    } mod_info_t;

    mod_info_t mods[1024];
    int mod_count = 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen maps");
        return;
    }
    printf("\n--- 模块列表(基址/范围/大小/权限/关键地址) ---\n");
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0;
        unsigned long end = 0;
        char perms[8] = {0};
        unsigned long offset = 0;
        char dev[32] = {0};
        unsigned long inode = 0;
        char name_raw[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %255[^\n]", &start, &end, perms, &offset, dev, &inode, name_raw);
        if (n < 6) continue;
        char name[256] = {0};
        if (n == 7) {
            while (name_raw[0] == ' ' || name_raw[0] == '\t') memmove(name_raw, name_raw + 1, strlen(name_raw));
            strncpy(name, name_raw, sizeof(name) - 1);
        } else {
            strcpy(name, "[anon]");
        }

        int idx = -1;
        for (int i = 0; i < mod_count; i++) {
            if (strcmp(mods[i].name, name) == 0) {
                idx = i;
                break;
            }
        }
        if (idx == -1) {
            if (mod_count >= 1024) continue;
            idx = mod_count++;
            memset(&mods[idx], 0, sizeof(mod_info_t));
            strncpy(mods[idx].name, name, sizeof(mods[idx].name) - 1);
            mods[idx].start = start;
            mods[idx].end = end;
        } else {
            if (start < mods[idx].start) mods[idx].start = start;
            if (end > mods[idx].end) mods[idx].end = end;
        }
        mods[idx].segs++;
        if (strchr(perms, 'r')) mods[idx].r = 1;
        if (strchr(perms, 'w')) mods[idx].w = 1;
        if (strchr(perms, 'x')) {
            mods[idx].x = 1;
            if (!mods[idx].has_text || start < mods[idx].text_start) {
                mods[idx].text_start = start;
                mods[idx].has_text = 1;
            }
        }
        if (strchr(perms, 'p')) mods[idx].p = 1;
        if (strchr(perms, 's')) mods[idx].s = 1;
    }
    fclose(fp);

    for (int i = 0; i < mod_count; i++) {
        unsigned long size = mods[i].end - mods[i].start;
        printf("base=0x%016lx end=0x%016lx size=0x%lx perms=%c%c%c%c segs=%d text=0x%016lx %s\n",
            mods[i].start,
            mods[i].end,
            size,
            mods[i].r ? 'r' : '-',
            mods[i].w ? 'w' : '-',
            mods[i].x ? 'x' : '-',
            mods[i].p ? 'p' : (mods[i].s ? 's' : '-'),
            mods[i].segs,
            mods[i].has_text ? mods[i].text_start : 0UL,
            mods[i].name);
    }
}

// 功能：处理线程状态与切换逻辑，确保断下线程与界面状态一致。
void list_threads(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir task");
        return;
    }
    printf("\n--- 线程列表(tid/name/state/entry/pc/sp/lr/startstack/wchan) ---\n");
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        pid_t tid = (pid_t)atoi(ent->d_name);
        char status_path[128];
        snprintf(status_path, sizeof(status_path), "/proc/%d/task/%s/status", pid, ent->d_name);
        FILE *fp = fopen(status_path, "r");
        if (!fp) {
            printf("tid=%s\n", ent->d_name);
            continue;
        }
        char name[128] = {0};
        char state[64] = {0};
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line + 5, "%127s", name);
            } else if (strncmp(line, "State:", 6) == 0) {
                sscanf(line + 6, "%63[^\n]", state);
            }
        }
        fclose(fp);

        unsigned long pc = 0;
        unsigned long sp = 0;
        unsigned long lr = 0;
        int has_regs = 0;
        if (tid == pid) {
            struct user_pt_regs regs;
            struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == 0) {
                pc = regs.pc;
                sp = regs.sp;
                lr = regs.regs[30];
                has_regs = 1;
            }
        } else {
            char syscall_path[128];
            char syscall_line[512];
            snprintf(syscall_path, sizeof(syscall_path), "/proc/%d/task/%s/syscall", pid, ent->d_name);
            if (read_line_file(syscall_path, syscall_line, sizeof(syscall_line)) == 0) {
                if (parse_syscall_pc_sp(syscall_line, &pc, &sp) == 0) has_regs = 1;
            }
        }

        unsigned long startstack = 0;
        unsigned long entry = 0;
        char stat_path[128];
        char stat_line[1024];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/task/%s/stat", pid, ent->d_name);
        if (read_line_file(stat_path, stat_line, sizeof(stat_line)) == 0) {
            parse_stat_startstack(stat_line, &startstack);
            parse_stat_field(stat_line, 26, &entry);
        }

        char wchan_path[128];
        char wchan[128] = {0};
        snprintf(wchan_path, sizeof(wchan_path), "/proc/%d/task/%s/wchan", pid, ent->d_name);
        if (read_line_file(wchan_path, wchan, sizeof(wchan)) != 0) strcpy(wchan, "?");
        size_t wl = strlen(wchan);
        if (wl > 0 && wchan[wl - 1] == '\n') wchan[wl - 1] = '\0';

        char pc_buf[128];
        char sp_buf[128];
        char lr_buf[128];
        char entry_buf[128];
        char stack_buf[128];
        char mod[256] = {0};
        if (entry && describe_address(pid, entry, mod, sizeof(mod)) == 0) snprintf(entry_buf, sizeof(entry_buf), "0x%016lx(%s)", entry, mod);
        else snprintf(entry_buf, sizeof(entry_buf), entry ? "0x%016lx" : "N/A", entry);
        if (has_regs && describe_address(pid, pc, mod, sizeof(mod)) == 0) snprintf(pc_buf, sizeof(pc_buf), "0x%016lx(%s)", pc, mod);
        else snprintf(pc_buf, sizeof(pc_buf), has_regs ? "0x%016lx" : "N/A", pc);
        if (has_regs && describe_address(pid, sp, mod, sizeof(mod)) == 0) snprintf(sp_buf, sizeof(sp_buf), "0x%016lx(%s)", sp, mod);
        else snprintf(sp_buf, sizeof(sp_buf), has_regs ? "0x%016lx" : "N/A", sp);
        if (tid == pid && has_regs && describe_address(pid, lr, mod, sizeof(mod)) == 0) snprintf(lr_buf, sizeof(lr_buf), "0x%016lx(%s)", lr, mod);
        else snprintf(lr_buf, sizeof(lr_buf), (tid == pid && has_regs) ? "0x%016lx" : "N/A", lr);
        if (startstack && describe_address(pid, startstack, mod, sizeof(mod)) == 0) snprintf(stack_buf, sizeof(stack_buf), "0x%016lx(%s)", startstack, mod);
        else snprintf(stack_buf, sizeof(stack_buf), "0x%016lx", startstack);

        printf("tid=%s name=%s state=%s entry=%s pc=%s sp=%s lr=%s startstack=%s wchan=%s\n",
            ent->d_name,
            name[0] ? name : "?",
            state[0] ? state : "?",
            entry_buf,
            pc_buf,
            sp_buf,
            lr_buf,
            stack_buf,
            wchan[0] ? wchan : "?");
    }
    closedir(dir);
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
int read_line_file(const char *path, char *buf, size_t size) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(buf, (int)size, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

// 功能：处理调用栈/栈数据采集与展示，辅助定位执行路径。
int parse_stat_startstack(const char *stat_line, unsigned long *startstack) {
    return parse_stat_field(stat_line, 28, startstack);
}

// 功能：解析服务端输出并路由到对应调试视图。
int parse_stat_field(const char *stat_line, int field_no, unsigned long *value) {
    const char *rp = strrchr(stat_line, ')');
    if (!rp) return -1;
    rp++;
    while (*rp == ' ') rp++;
    if (*rp == '\0') return -1;
    char tmp[1024];
    strncpy(tmp, rp, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *save = NULL;
    char *tok = strtok_r(tmp, " ", &save);
    int idx = 3;
    while (tok) {
        if (idx == field_no) {
            *value = strtoul(tok, NULL, 10);
            return 0;
        }
        tok = strtok_r(NULL, " ", &save);
        idx++;
    }
    return -1;
}

// 功能：解析服务端输出并路由到对应调试视图。
int parse_syscall_pc_sp(const char *line, unsigned long *pc, unsigned long *sp) {
    unsigned long vals[16] = {0};
    int cnt = 0;
    char tmp[512];
    strncpy(tmp, line, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *save = NULL;
    char *tok = strtok_r(tmp, " \t\n", &save);
    while (tok && cnt < 16) {
        if (tok[0] == '-') return -1;
        vals[cnt++] = strtoul(tok, NULL, 0);
        tok = strtok_r(NULL, " \t\n", &save);
    }
    if (cnt < 3) return -1;
    *sp = vals[cnt - 3];
    *pc = vals[cnt - 2];
    return 0;
}

// 功能：在调试器中执行该模块的核心辅助逻辑。
void clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

// 功能：在调试器中输出一轮数据结束标记，供客户端精确判断完整包边界。
void emit_packet_end(void) {
    printf("[PKT_END]\n");
    fflush(stdout);
}

// 功能：计算字符串的FNV-1a校验值，用于客户端包校验。
uint32_t fnv1a32_str(const char *s) {
    uint32_t h = 2166136261u;
    if (!s) return h;
    while (*s) {
        h ^= (uint8_t)(*s++);
        h *= 16777619u;
    }
    return h;
}

// 功能：将文本编码为十六进制字符串，避免分隔符冲突。
void hex_encode_str(const char *in, char *out, size_t out_size) {
    static const char *hex = "0123456789ABCDEF";
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!in) return;
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        if (j + 2 >= out_size) break;
        uint8_t c = (uint8_t)in[i];
        out[j++] = hex[(c >> 4) & 0xF];
        out[j++] = hex[c & 0xF];
    }
    out[j] = '\0';
}

// 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
void handle_step_into(pid_t pid) {
    printf("-> 执行单步步入\n");
    unsigned long pc = get_pc(pid);
    int bp_idx = find_breakpoint_by_addr(pc);
    int soft_idx = current_soft_hit_idx;
    unsigned long soft_addr = current_soft_hit_addr;
    int watch_idx = current_watch_hit_idx;
    if (bp_idx >= 0) {
        if (step_past_breakpoint(pid, bp_idx, pc, 0) == -1) fprintf(stderr, "单步失败\n");
        interactive_tid = 0;
        return;
    }
    if (watch_idx >= 0) {
        if (step_past_watchpoint(pid, watch_idx, 0) == -1) fprintf(stderr, "硬件读写断点单步失败\n");
        interactive_tid = 0;
        return;
    }
    if (soft_idx >= 0) {
        if (step_past_soft_breakpoint(pid, soft_idx, soft_addr, 0, 0) == -1) fprintf(stderr, "软件断点单步失败\n");
        interactive_tid = 0;
        return;
    }
    if (single_step(pid) == -1) fprintf(stderr, "单步失败\n");
    interactive_tid = 0;
}

// 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
void handle_step_over(pid_t pid) {
    unsigned long pc = get_pc(pid);
    int bp_idx = find_breakpoint_by_addr(pc);
    int soft_idx = current_soft_hit_idx;
    unsigned long soft_addr = current_soft_hit_addr;
    int watch_idx = current_watch_hit_idx;
    uint32_t insn = (soft_idx >= 0) ? my_soft_breakpoints[soft_idx].orig_insn : read_u32(pid, pc);
    char bytes[32];
    format_u32_bytes(insn, bytes, sizeof(bytes));
    printf("当前指令: %s\n", bytes);
    if (watch_idx >= 0) {
        if (step_past_watchpoint(pid, watch_idx, 0) == -1) fprintf(stderr, "硬件读写断点步过失败\n");
        interactive_tid = 0;
        return;
    }
    if (soft_idx >= 0) {
        if (step_past_soft_breakpoint(pid, soft_idx, soft_addr, 0, 1) == -1) fprintf(stderr, "软件断点步过失败\n");
        interactive_tid = 0;
        return;
    }

    if (is_call_instruction(insn)) {
        unsigned long return_addr = pc + 4;
        printf("-> 调用指令，返回地址 0x%lx\n", return_addr);
        step_over_source_bp_idx = bp_idx;
        step_over_source_bp_addr = pc;
        if (bp_idx >= 0) clear_breakpoint(pid, bp_idx);
        step_over_temp_bp_idx = set_hardware_breakpoint(pid, return_addr, -1);
        if (step_over_temp_bp_idx == -1) {
            fprintf(stderr, "设置步过临时断点失败，改为单步\n");
            if (bp_idx >= 0) set_hardware_breakpoint(pid, pc, bp_idx);
            if (bp_idx >= 0) {
                if (step_past_breakpoint(pid, bp_idx, pc, 0) == -1) fprintf(stderr, "单步失败\n");
            } else {
                if (single_step(pid) == -1) fprintf(stderr, "单步失败\n");
            }
            interactive_tid = 0;
            return;
        }
        step_over_active = 1;
        step_over_return_addr = return_addr;
        continue_execution(pid, 0);
        interactive_tid = 0;
        return;
    }

    printf("-> 非调用指令，直接单步\n");
    if (bp_idx >= 0) {
        if (step_past_breakpoint(pid, bp_idx, pc, 0) == -1) fprintf(stderr, "单步失败\n");
        interactive_tid = 0;
        return;
    }
    if (single_step(pid) == -1) fprintf(stderr, "单步失败\n");
    interactive_tid = 0;
}

// 功能：处理单步/继续执行控制，驱动断下后的界面刷新链路。
static int any_mem_breakpoint_in_use(void) {
    for (int i = 0; i < MEM_BP_MAX; i++) {
        if (my_mem_breakpoints[i].in_use) return 1;
    }
    return 0;
}

static void handle_resume(pid_t pid) {
    printf("-> 继续运行\n");
    unsigned long pc = get_pc(pid);
    int mem_on = any_mem_breakpoint_in_use();
    membp_trace("[MEMBP] resume: tid=%d pc=0x%lx any_mem_bp=%d resume_other_threads=%s\n",
        (int)pid, pc, mem_on ? 1 : 0, mem_on ? "no" : "yes");
    int bp_idx = find_breakpoint_by_addr(pc);
    int soft_idx = current_soft_hit_idx;
    unsigned long soft_addr = current_soft_hit_addr;
    int watch_idx = current_watch_hit_idx;
    /* 有内存断点时先不要恢复其它线程，避免并发 mprotect/取指与主线程竞态导致“永远不断” */
    if (!any_mem_breakpoint_in_use()) resume_other_traced_threads(pid);
    if (bp_idx >= 0) {
        if (step_past_breakpoint(pid, bp_idx, pc, 1) == -1) fprintf(stderr, "继续运行失败\n");
        interactive_tid = 0;
        return;
    }
    if (watch_idx >= 0) {
        if (watch_idx < 0 || watch_idx >= HW_WP_MAX || !my_watchpoints[watch_idx].in_use) {
            current_watch_hit_idx = -1;
            current_watch_hit_addr = 0;
            continue_execution(pid, 0);
            interactive_tid = 0;
            return;
        }
        if (step_past_watchpoint(pid, watch_idx, 1) == -1) {
            fprintf(stderr, "硬件读写断点继续失败\n");
            current_watch_hit_idx = -1;
            current_watch_hit_addr = 0;
            continue_execution(pid, 0);
        }
        interactive_tid = 0;
        return;
    }
    if (soft_idx >= 0) {
        if (step_past_soft_breakpoint(pid, soft_idx, soft_addr, 1, 0) == -1) fprintf(stderr, "软件断点继续失败\n");
        interactive_tid = 0;
        return;
    }
    continue_execution(pid, 0);
    interactive_tid = 0;
}

// 功能：处理断点增删改查与命中后的状态同步。
void handle_breakpoint_hit(pid_t pid) {
    interactive_tid = pid;
    pause_other_traced_threads(pid);
    render_debug_dashboard(pid);

    char line[512];
    while (1) {
        emit_packet_end();
        printf("\n命令 [c/n/r/q/bhx/bhr/bhw/bha/bhc/bhl/brk/brkc/brkl/bmx/bmr/bmw/bma/bmc/bml/u/upkt/dq/dd/dw/db/wm/asm/ml/tl/cls/help]: ");
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) break;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (line[0] == '\0') continue;

        char *cmd = strtok(line, " \t");
        if (!cmd) continue;

        if (strcmp(cmd, "c") == 0) {
            handle_step_into(pid);
            return;
        }
        if (strcmp(cmd, "n") == 0) {
            handle_step_over(pid);
            return;
        }
        if (strcmp(cmd, "r") == 0) {
            char *reg = strtok(NULL, " \t");
            if (reg) {
                char *val_s = strtok(NULL, " \t");
                unsigned long value = 0;
                if (!val_s || parse_addr_expr(pid, val_s, &value) == -1 || set_register_by_name(pid, reg, value) == -1) {
                    printf("用法: r <reg> <hex|reg+off>\n");
                } else {
                    printf("寄存器已修改: %s = 0x%lx\n", reg, value);
                    render_debug_dashboard(pid);
                }
                continue;
            }
            handle_resume(pid);
            return;
        }
        if (strcmp(cmd, "q") == 0) {
            interactive_tid = 0;
            clear_all_soft_breakpoints(pid);
            clear_all_memory_breakpoints(pid);
            clear_all_watchpoints(pid);
            clear_all_breakpoints(pid);
            detach_all_traced_threads();
            exit(0);
        }
        if (strcmp(cmd, "bh") == 0 || strcmp(cmd, "bhx") == 0) {
            char *arg = strtok(NULL, " \t");
            unsigned long addr = 0;
            if (!arg || parse_addr_expr(pid, arg, &addr) == -1 || (addr & 3UL)) {
                printf("用法: %s <addr(4字节对齐)>\n", cmd);
                continue;
            }
            set_hardware_breakpoint(pid, addr, -1);
            continue;
        }
        if (strcmp(cmd, "bhc") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) {
                printf("用法: bhc <idx|addr|all>\n");
                continue;
            }
            if (strcmp(arg, "all") == 0) {
                clear_all_breakpoints(pid);
                clear_all_watchpoints(pid);
                continue;
            }
            unsigned long val = 0;
            if (parse_u64(arg, &val) == -1) {
                printf("参数无效\n");
                continue;
            }
            if (strlen(arg) > 2 && arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
                int idx = find_breakpoint_by_addr(val);
                if (idx >= 0) clear_breakpoint(pid, idx);
                else {
                    idx = find_watchpoint_by_addr(val);
                    if (idx < 0) printf("未找到该地址断点\n");
                    else clear_watchpoint(pid, idx);
                }
            } else {
                int idx = (int)val;
                if (idx >= 0 && idx < HW_BP_MAX && my_breakpoints[idx].in_use) clear_breakpoint(pid, idx);
                else if (idx >= 0 && idx < HW_WP_MAX && my_watchpoints[idx].in_use) clear_watchpoint(pid, idx);
                else printf("无效断点索引\n");
            }
            continue;
        }
        if (strcmp(cmd, "bhl") == 0) {
            list_breakpoints();
            continue;
        }
        if (strcmp(cmd, "brk") == 0) {
            char *arg = strtok(NULL, " \t");
            unsigned long addr = 0;
            if (!arg || parse_addr_expr(pid, arg, &addr) == -1 || (addr & 3UL)) {
                printf("用法: brk <addr(4字节对齐)>\n");
                continue;
            }
            int idx = set_soft_breakpoint(pid, addr, 0);
            if (idx < 0) printf("设置软件断点失败\n");
            else printf("软件断点已设置: idx=%d addr=0x%lx\n", idx, addr);
            continue;
        }
        if (strcmp(cmd, "brkc") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) {
                printf("用法: brkc <idx|addr|all>\n");
                continue;
            }
            if (strcmp(arg, "all") == 0) {
                clear_all_soft_breakpoints(pid);
                continue;
            }
            unsigned long val = 0;
            if (parse_u64(arg, &val) == -1) {
                printf("参数无效\n");
                continue;
            }
            if (strlen(arg) > 2 && arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
                int idx = find_soft_breakpoint_by_addr(val);
                if (idx < 0) printf("未找到该地址软件断点\n");
                else clear_soft_breakpoint(pid, idx);
            } else {
                int idx = (int)val;
                if (idx < 0 || idx >= SW_BP_MAX || !my_soft_breakpoints[idx].in_use) printf("无效软件断点索引\n");
                else clear_soft_breakpoint(pid, idx);
            }
            continue;
        }
        if (strcmp(cmd, "brkl") == 0) {
            list_soft_breakpoints();
            continue;
        }
        if (strcmp(cmd, "bha") == 0) {
            char *arg = strtok(NULL, " \t");
            unsigned long addr = 0;
            if (!arg || parse_addr_expr(pid, arg, &addr) == -1 || (addr & 3UL)) {
                printf("用法: bha <addr(4字节对齐)>\n");
                continue;
            }
            int idx = set_watchpoint(pid, addr, -1);
            if (idx < 0) printf("设置硬件读写断点失败\n");
            else printf("硬件读写断点已设置: idx=%d addr=0x%lx\n", idx, addr);
            continue;
        }
        if (strcmp(cmd, "bhr") == 0) {
            char *arg = strtok(NULL, " \t");
            unsigned long addr = 0;
            if (!arg || parse_addr_expr(pid, arg, &addr) == -1 || (addr & 3UL)) {
                printf("用法: bhr <addr(4字节对齐)>\n");
                continue;
            }
            int idx = set_watchpoint_mode(pid, addr, 1, -1);
            if (idx < 0) printf("设置硬件读断点失败\n");
            else printf("硬件读断点已设置: idx=%d addr=0x%lx\n", idx, addr);
            continue;
        }
        if (strcmp(cmd, "bhw") == 0) {
            char *arg = strtok(NULL, " \t");
            unsigned long addr = 0;
            if (!arg || parse_addr_expr(pid, arg, &addr) == -1 || (addr & 3UL)) {
                printf("用法: bhw <addr(4字节对齐)>\n");
                continue;
            }
            int idx = set_watchpoint_mode(pid, addr, 2, -1);
            if (idx < 0) printf("设置硬件写断点失败\n");
            else printf("硬件写断点已设置: idx=%d addr=0x%lx\n", idx, addr);
            continue;
        }
        if (strcmp(cmd, "bmx") == 0 || strcmp(cmd, "bma") == 0 || strcmp(cmd, "bmr") == 0 || strcmp(cmd, "bmw") == 0) {
            char *arg = strtok(NULL, " \t");
            unsigned long addr = 0;
            if (!arg || parse_addr_expr(pid, arg, &addr) == -1 || (addr & 3UL)) {
                printf("用法: %s <addr(4字节对齐)>\n", cmd);
                continue;
            }
            int mode = strcmp(cmd, "bmx") == 0 ? 0 : (strcmp(cmd, "bmr") == 0 ? 1 : (strcmp(cmd, "bmw") == 0 ? 2 : 3));
            int idx = set_memory_breakpoint(pid, addr, mode);
            if (idx < 0) printf("设置内存断点失败\n");
            else {
                printf("内存断点已设置: idx=%d addr=0x%lx\n", idx, addr);
                fflush(stdout);
            }
            continue;
        }
        if (strcmp(cmd, "bmc") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) {
                printf("用法: bmc <idx|addr|all>\n");
                continue;
            }
            if (strcmp(arg, "all") == 0) {
                clear_all_memory_breakpoints(pid);
                continue;
            }
            unsigned long val = 0;
            if (parse_u64(arg, &val) == -1) {
                printf("参数无效\n");
                continue;
            }
            if (strlen(arg) > 2 && arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X')) {
                int idx = find_mem_breakpoint_by_addr(val);
                if (idx >= 0) {
                    clear_memory_breakpoint(pid, idx);
                } else {
                    printf("未找到该地址内存断点\n");
                }
            } else {
                int idx = (int)val;
                if (idx >= 0 && idx < MEM_BP_MAX && my_mem_breakpoints[idx].in_use) {
                    clear_memory_breakpoint(pid, idx);
                } else {
                    printf("无效内存断点索引\n");
                }
            }
            continue;
        }
        if (strcmp(cmd, "bml") == 0) {
            list_memory_breakpoints();
            continue;
        }
        if (strcmp(cmd, "u") == 0) {
            char *a = strtok(NULL, " \t");
            char *c = strtok(NULL, " \t");
            unsigned long addr = 0;
            int lines = 20;
            if (!a || parse_addr_expr(pid, a, &addr) == -1) {
                printf("用法: u <addr> [行数]\n");
                continue;
            }
            if (c) lines = atoi(c);
            disassemble_from(pid, addr, lines);
            continue;
        }
        if (strcmp(cmd, "upkt") == 0) {
            char *a = strtok(NULL, " \t");
            char *c = strtok(NULL, " \t");
            unsigned long addr = 0;
            int lines = 20;
            if (!a || parse_addr_expr(pid, a, &addr) == -1) {
                printf("用法: upkt <addr> [行数]\n");
                continue;
            }
            if (c) lines = atoi(c);
            disassemble_from_pkt(pid, addr, lines);
            continue;
        }
        if (strcmp(cmd, "dd") == 0) {
            char *a = strtok(NULL, " \t");
            char *c = strtok(NULL, " \t");
            unsigned long addr = 0;
            int lines = 5;
            if (!a || parse_addr_expr(pid, a, &addr) == -1) {
                printf("用法: dd <addr> [行数]\n");
                continue;
            }
            if (c) lines = atoi(c);
            dump_dword(pid, addr, lines);
            continue;
        }
        if (strcmp(cmd, "dq") == 0) {
            char *a = strtok(NULL, " \t");
            char *c = strtok(NULL, " \t");
            unsigned long addr = 0;
            int lines = 5;
            if (!a || parse_addr_expr(pid, a, &addr) == -1) {
                printf("用法: dq <addr> [行数]\n");
                continue;
            }
            if (c) lines = atoi(c);
            dump_qword(pid, addr, lines);
            continue;
        }
        if (strcmp(cmd, "dw") == 0) {
            char *a = strtok(NULL, " \t");
            char *c = strtok(NULL, " \t");
            unsigned long addr = 0;
            int lines = 5;
            if (!a || parse_addr_expr(pid, a, &addr) == -1) {
                printf("用法: dw <addr> [行数]\n");
                continue;
            }
            if (c) lines = atoi(c);
            dump_word(pid, addr, lines);
            continue;
        }
        if (strcmp(cmd, "db") == 0) {
            char *a = strtok(NULL, " \t");
            char *c = strtok(NULL, " \t");
            unsigned long addr = 0;
            int lines = 5;
            if (!a || parse_addr_expr(pid, a, &addr) == -1) {
                printf("用法: db <addr> [行数]\n");
                continue;
            }
            if (c) lines = atoi(c);
            dump_byte(pid, addr, lines);
            continue;
        }
        if (strcmp(cmd, "wm") == 0) {
            char *a = strtok(NULL, " \t");
            char *v = strtok(NULL, " \t");
            char *n = strtok(NULL, " \t");
            unsigned long addr = 0;
            unsigned long value = 0;
            int size = 1;
            if (!a || !v || parse_addr_expr(pid, a, &addr) == -1 || parse_u64(v, &value) == -1) {
                printf("用法: wm <addr> <value> <size:1|2|4|8>\n");
                continue;
            }
            if (n) size = atoi(n);
            if (!(size == 1 || size == 2 || size == 4 || size == 8)) {
                printf("wm失败: size仅支持1/2/4/8\n");
                continue;
            }
            if (write_value_le(pid, addr, value, size) == -1) {
                printf("wm失败: 写入内存失败\n");
            } else {
                printf("wm成功: addr=0x%lx value=0x%lx size=%d\n", addr, value, size);
            }
            continue;
        }
        if (strcmp(cmd, "asm") == 0) {
            char *a = strtok(NULL, " \t");
            char *ins = strtok(NULL, "");
            unsigned long addr = 0;
            if (!a || parse_addr_expr(pid, a, &addr) == -1 || !ins) {
                printf("用法: asm <addr> <insn>\n");
                continue;
            }
            while (*ins == ' ' || *ins == '\t') ins++;
            if (*ins == '\0') {
                printf("用法: asm <addr> <insn>\n");
                continue;
            }
            (void)assemble_and_write(pid, addr, ins);
            continue;
        }
        if (strcmp(cmd, "ml") == 0) {
            list_modules(pid);
            continue;
        }
        if (strcmp(cmd, "tl") == 0) {
            list_threads(pid);
            continue;
        }
        if (strcmp(cmd, "cls") == 0) {
            clear_screen();
            continue;
        }
        if (strcmp(cmd, "help") == 0) {
            show_help();
            continue;
        }
        printf("未知命令: %s\n", cmd);
    }
}

// 功能：调试器程序入口，负责初始化并启动主循环。
int run_debug_loop(void) {
    while (1) {
        int status = 0;
        pid_t ret = waitpid(-1, &status, __WALL);
        if (ret == -1) {
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }
        pid_t stopped_tid = ret;
        add_traced_tid(stopped_tid);

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            int event = (status >> 16) & 0xffff;
            if (sig == SIGTRAP) {
                siginfo_t si;
                memset(&si, 0, sizeof(si));
                int has_siginfo = (ptrace(PTRACE_GETSIGINFO, stopped_tid, NULL, &si) == 0);
                if (stepping_mem_active && stopped_tid == stepping_mem_tid) {
                    membp_trace("[MEMBP] trap: mem-step done tid=%d reapply trap_prot on hit pages\n", (int)stopped_tid);
                    for (int i = 0; i < MEM_HIT_PAGE_MAX; i++) {
                        if (!my_mem_hit_pages[i].in_use) continue;
                        int page_idx = my_mem_hit_pages[i].page_idx;
                        if (page_idx < 0 || page_idx >= MEM_PAGE_MAX || !my_mem_pages[page_idx].in_use) continue;
                        if (count_mem_links_for_page(page_idx) <= 0) continue;
                        int trap_prot = mem_page_compute_trap_prot(page_idx);
                        if (mem_page_apply_prot_ex(stopped_tid, &my_mem_pages[page_idx], trap_prot, my_mem_pages[page_idx].orig_prot) == 0) {
                            my_mem_pages[page_idx].nx_active = (trap_prot != my_mem_pages[page_idx].orig_prot) ? 1 : 0;
                        }
                    }
                    clear_memory_hit_pages();
                    stepping_mem_active = 0;
                    stepping_mem_tid = 0;
                }
                if (event != 0) {
                    if (event == PTRACE_EVENT_CLONE) {
                        unsigned long new_tid = 0;
                        if (ptrace(PTRACE_GETEVENTMSG, stopped_tid, NULL, &new_tid) == 0 && new_tid > 0) {
                            add_traced_tid((pid_t)new_tid);
                            set_ptrace_options((pid_t)new_tid);
                            sync_hw_breakpoints((pid_t)new_tid);
                            sync_hw_watchpoints((pid_t)new_tid);
                            continue_execution((pid_t)new_tid, 0);
                        }
                    }
                    continue_execution(stopped_tid, 0);
                    continue;
                }
                if (stepping_soft_active && stopped_tid == stepping_soft_tid) {
                    write_u32(stopped_tid, stepping_soft_addr, get_brk_instruction());
                    int resume = stepping_soft_resume;
                    int continue_step_over = stepping_soft_step_over;
                    stepping_soft_active = 0;
                    stepping_soft_idx = -1;
                    stepping_soft_addr = 0;
                    stepping_soft_resume = 0;
                    stepping_soft_step_over = 0;
                    stepping_soft_tid = 0;
                    if (continue_step_over) {
                        continue_execution(stopped_tid, 0);
                    } else if (resume) {
                        continue_execution(stopped_tid, 0);
                    } else {
                        current_soft_hit_idx = -1;
                        current_soft_hit_addr = 0;
                        // 单步越过软件断点后，若下一条立即也是软件断点，需要在本轮就标记命中，
                        // 否则会出现“同一地址要再按两次单步才能越过”的现象。
                        {
                            unsigned long pc2 = get_pc(stopped_tid);
                            int next_soft_idx = find_soft_breakpoint_by_addr(pc2);
                            if (next_soft_idx < 0 && pc2 >= 4) next_soft_idx = find_soft_breakpoint_by_addr(pc2 - 4);
                            if (next_soft_idx >= 0) {
                                current_soft_hit_idx = next_soft_idx;
                                current_soft_hit_addr = my_soft_breakpoints[next_soft_idx].addr;
                            }
                        }
                        handle_breakpoint_hit(stopped_tid);
                    }
                    continue;
                }
                if (stepping_watch_active && stopped_tid == stepping_watch_tid && (!has_siginfo || si.si_code == TRAP_TRACE)) {
                    if (sync_hw_watchpoints(stopped_tid) == -1) sync_hw_watchpoints_all_threads(target_pid);
                    int resume = stepping_watch_resume;
                    stepping_watch_active = 0;
                    stepping_watch_idx = -1;
                    stepping_watch_mode = 0;
                    stepping_watch_addr = 0;
                    stepping_watch_resume = 0;
                    stepping_watch_tid = 0;
                    if (resume) {
                        continue_execution(stopped_tid, 0);
                    } else {
                        current_watch_hit_idx = -1;
                        current_watch_hit_addr = 0;
                        unsigned long pc2 = get_pc(stopped_tid);
                        int next_soft_idx = find_soft_breakpoint_by_addr(pc2);
                        if (next_soft_idx < 0 && pc2 >= 4) next_soft_idx = find_soft_breakpoint_by_addr(pc2 - 4);
                        if (next_soft_idx >= 0) {
                            current_soft_hit_idx = next_soft_idx;
                            current_soft_hit_addr = my_soft_breakpoints[next_soft_idx].addr;
                        }
                        handle_breakpoint_hit(stopped_tid);
                    }
                    continue;
                }
                if (stepping_bp_active) {
                    stepping_bp_active = 0;
                    set_hardware_breakpoint(target_pid, stepping_bp_addr, stepping_bp_idx);
                    int resume = stepping_bp_resume;
                    stepping_bp_idx = -1;
                    stepping_bp_addr = 0;
                    stepping_bp_resume = 0;
                    if (resume) {
                        continue_execution(stopped_tid, 0);
                    } else {
                        unsigned long pc2 = get_pc(stopped_tid);
                        int next_soft_idx = find_soft_breakpoint_by_addr(pc2);
                        if (next_soft_idx < 0 && pc2 >= 4) next_soft_idx = find_soft_breakpoint_by_addr(pc2 - 4);
                        if (next_soft_idx >= 0) {
                            current_soft_hit_idx = next_soft_idx;
                            current_soft_hit_addr = my_soft_breakpoints[next_soft_idx].addr;
                        }
                        handle_breakpoint_hit(stopped_tid);
                    }
                    continue;
                }
                if (step_over_active) {
                    unsigned long pc = get_pc(stopped_tid);
                    if (pc != step_over_return_addr) {
                        continue_execution(stopped_tid, 0);
                        continue;
                    }
                    if (step_over_temp_bp_idx >= 0) clear_breakpoint(target_pid, step_over_temp_bp_idx);
                    if (step_over_source_bp_idx >= 0) set_hardware_breakpoint(target_pid, step_over_source_bp_addr, step_over_source_bp_idx);
                    if (step_over_source_soft_bp_idx >= 0) write_u32(stopped_tid, step_over_source_bp_addr, get_brk_instruction());
                    current_soft_hit_idx = -1;
                    current_soft_hit_addr = 0;
                    step_over_active = 0;
                    step_over_temp_bp_idx = -1;
                    step_over_source_bp_idx = -1;
                    step_over_source_soft_bp_idx = -1;
                    step_over_source_bp_addr = 0;
                    step_over_return_addr = 0;
                    if (pc != 0) handle_breakpoint_hit(stopped_tid);
                    continue;
                }
                current_soft_hit_idx = -1;
                current_soft_hit_addr = 0;
                current_watch_hit_idx = -1;
                current_watch_hit_addr = 0;
                {
                    unsigned long pc = get_pc(stopped_tid);
                    int soft_idx = find_soft_breakpoint_by_addr(pc);
                    if (soft_idx < 0 && pc >= 4) soft_idx = find_soft_breakpoint_by_addr(pc - 4);
                    if (soft_idx >= 0) {
                        current_soft_hit_idx = soft_idx;
                        current_soft_hit_addr = my_soft_breakpoints[soft_idx].addr;
                    }
                    if (has_siginfo && si.si_code == TRAP_HWBKPT) {
                        unsigned long hit_addr = (unsigned long)si.si_addr;
                        for (int i = 0; i < HW_WP_MAX; i++) {
                            if (!my_watchpoints[i].in_use) continue;
                            unsigned long base = my_watchpoints[i].addr;
                            if (hit_addr >= base && hit_addr < base + 8UL) {
                                current_watch_hit_idx = i;
                                current_watch_hit_addr = hit_addr;
                                break;
                            }
                        }
                    }
                }
                handle_breakpoint_hit(stopped_tid);
            } else {
                if (sig == SIGSEGV || sig == SIGBUS) {
                    siginfo_t si;
                    memset(&si, 0, sizeof(si));
                    int page_idx = -1;
                    unsigned long pc_fault = get_pc(stopped_tid);
                    membp_trace("[MEMBP] fault: sig=%d tid=%d target_pid=%d pc=0x%lx\n", sig, (int)stopped_tid, (int)target_pid, pc_fault);
                    if (ptrace(PTRACE_GETSIGINFO, stopped_tid, NULL, &si) == 0) {
                        unsigned long fault_addr = (unsigned long)si.si_addr;
                        membp_trace("[MEMBP] fault: siginfo code=%d addr=0x%lx\n", si.si_code, fault_addr);
                        page_idx = find_memory_page_for_fault(fault_addr);
                        if (page_idx < 0 && pc_fault != 0) page_idx = find_memory_page_for_fault(pc_fault);
                    } else {
                        membp_trace("[MEMBP] fault: GETSIGINFO errno=%d, fallback pc page\n", errno);
                        /* 部分环境下 GETSIGINFO 失败，若仍按“透传”处理则内存断点永不断下；用 PC 所在页回退匹配 */
                        if (pc_fault != 0) page_idx = find_memory_page_for_fault(pc_fault);
                    }
                    membp_trace("[MEMBP] fault: page_idx=%d after lookup\n", page_idx);
                    if (page_idx >= 0 && page_idx < MEM_PAGE_MAX && my_mem_pages[page_idx].in_use) {
                        membp_trace("[MEMBP] fault: MATCH page_idx=%d range=[0x%lx,0x%lx) orig=0x%x nx=%d\n",
                            page_idx,
                            my_mem_pages[page_idx].map_start,
                            my_mem_pages[page_idx].map_end,
                            my_mem_pages[page_idx].orig_prot,
                            my_mem_pages[page_idx].nx_active);
                        clear_memory_hit_pages();
                        unsigned long fault_pc = get_pc(stopped_tid);
                        for (int i = 0; i < MEM_HIT_PAGE_MAX; i++) {
                            if (!my_mem_hit_pages[i].in_use) {
                                my_mem_hit_pages[i].in_use = 1;
                                my_mem_hit_pages[i].page_idx = page_idx;
                                my_mem_hit_pages[i].fault_pc = fault_pc;
                                break;
                            }
                        }
                        if (mem_page_apply_prot_ex(stopped_tid, &my_mem_pages[page_idx], my_mem_pages[page_idx].orig_prot, my_mem_pages[page_idx].orig_prot) == 0) {
                            my_mem_pages[page_idx].nx_active = 0;
                            stepping_mem_active = 1;
                            stepping_mem_tid = stopped_tid;
                            if (single_step(stopped_tid) == 0) {
                                continue;
                            }
                            membp_trace("[MEMBP] fault: WARN single_step failed after restore orig\n");
                            stepping_mem_active = 0;
                            stepping_mem_tid = 0;
                        } else {
                            membp_trace("[MEMBP] fault: WARN remote_mprotect(restore orig) failed\n");
                        }
                        clear_memory_hit_pages();
                        continue_execution(stopped_tid, sig);
                        continue;
                    }
                    membp_trace("[MEMBP] fault: NO match mem page for sig=%d -> pass to tracee\n", sig);
                    membp_log_active_pages("fault_nomatch");
                    printf("线程 %d 收到信号 %d，继续透传\n", stopped_tid, sig);
                    continue_execution(stopped_tid, sig);
                } else if (sig == SIGSTOP || sig == SIGCHLD || sig == SIGCONT) {
                    continue_execution(stopped_tid, 0);
                } else {
                    if (any_mem_breakpoint_in_use()) {
                        membp_trace("[MEMBP] notice: tid=%d sig=%d (not TRAP/SEGV/BUS; mem bp still armed)\n", (int)stopped_tid, sig);
                    }
                    printf("线程 %d 收到信号 %d，继续透传\n", stopped_tid, sig);
                    continue_execution(stopped_tid, sig);
                }
            }
        } else if (WIFEXITED(status)) {
            remove_traced_tid(ret);
            if (ret == target_pid) {
                printf("目标进程已退出，状态: %d\n", WEXITSTATUS(status));
                break;
            }
            continue;
        } else if (WIFSIGNALED(status)) {
            remove_traced_tid(ret);
            if (ret == target_pid) {
                printf("目标进程被信号 %d 终止\n", WTERMSIG(status));
                break;
            }
            continue;
        }
    }

    clear_all_soft_breakpoints(target_pid);
    clear_all_memory_breakpoints(target_pid);
    clear_all_watchpoints(target_pid);
    clear_all_breakpoints(target_pid);
    detach_all_traced_threads();
    return 0;
}

// 功能：调试器程序入口，负责初始化并启动主循环。
int main(int argc, char *argv[]) {
    if (argc == 2) {
        target_pid = atoi(argv[1]);
        if (target_pid <= 0) {
            fprintf(stderr, "PID 无效\n");
            return 1;
        }
        if (attach_process(target_pid) == -1) return 1;
        show_help();
        handle_breakpoint_hit(target_pid);
        return run_debug_loop();
    }

    // 兼容客户端无参数启动：监听31337，等待attach <pid>指令再进入调试循环
    if (setup_tcp_stdio() != 0) return 1;
    printf("SERVER_READY\n");
    fflush(stdout);
    char line[256];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (line[0] == '\0') continue;
        char *cmd = strtok(line, " \t");
        if (!cmd) continue;
        if (strcmp(cmd, "q") == 0 || strcmp(cmd, "quit") == 0) return 0;
        if (strcmp(cmd, "help") == 0) {
            printf("用法: attach <PID>\n");
            fflush(stdout);
            continue;
        }
        if (strcmp(cmd, "attach") == 0) {
            char *p = strtok(NULL, " \t");
            if (!p) {
                printf("ATTACH_FAIL\n");
                fflush(stdout);
                continue;
            }
            pid_t pid = (pid_t)atoi(p);
            if (pid <= 0 || attach_process(pid) == -1) {
                printf("ATTACH_FAIL\n");
                fflush(stdout);
                continue;
            }
            target_pid = pid;
            printf("ATTACH_OK %d %d\n", target_pid, (int)getpid());
            fflush(stdout);
            show_help();
            handle_breakpoint_hit(target_pid);
            return run_debug_loop();
        }
        printf("ATTACH_FAIL\n");
        fflush(stdout);
    }
    return 0;
}

// 功能：建立31337端口TCP会话，并将stdin/stdout重定向到socket，兼容客户端forward直连。
int setup_tcp_stdio(void) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return -1;
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(31337);
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        return -1;
    }
    if (listen(listen_fd, 1) < 0) {
        close(listen_fd);
        return -1;
    }
    int client_fd = accept(listen_fd, NULL, NULL);
    close(listen_fd);
    if (client_fd < 0) return -1;
    if (dup2(client_fd, STDIN_FILENO) < 0) { close(client_fd); return -1; }
    if (dup2(client_fd, STDOUT_FILENO) < 0) { close(client_fd); return -1; }
    if (dup2(client_fd, STDERR_FILENO) < 0) { close(client_fd); return -1; }
    close(client_fd);
    return 0;
}
