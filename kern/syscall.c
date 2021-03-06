/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>
#include <kern/time.h>
#include <kern/e1000.h>

static bool check_perm(int perm);

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.
	user_mem_assert(curenv, s, len, 0);

	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	int r;
	struct Env *newenv = NULL;

	assert(curenv != NULL);

	if ((r = env_alloc(&newenv, curenv->env_id)) < 0) {
		return r;
	}

	// New environment is not runnable until its virtual memory is mapped.
	newenv->env_status = ENV_NOT_RUNNABLE;

	// Copy all registers from parent to child except eax, so the child appears
	// to return 0.
	newenv->env_tf = curenv->env_tf;
	newenv->env_tf.tf_regs.reg_eax = 0;

	return newenv->env_id;
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	struct Env *env = NULL;

	if (status < 0 || status > ENV_NOT_RUNNABLE) {
		return -E_INVAL;
	}

	if (envid2env(envid, &env, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	env->env_status = status;

	return 0;
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// Remember to check whether the user has supplied us with a good
	// address!
	user_mem_assert(curenv, tf, sizeof(struct Trapframe), PTE_W);

	struct Env *env = NULL;

	if (envid2env(envid, &env, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	// CPL 3.
	tf->tf_ds |= 3;
	tf->tf_es |= 3;
	tf->tf_ss |= 3;
	tf->tf_cs |= 3;

	// Enable interrupts.
	tf->tf_eflags |= FL_IF;

	// No evil IO.
	tf->tf_eflags &= ~FL_IOPL_MASK;

	env->env_tf = *tf;

	return 0;
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	struct Env *env = NULL;

	if (envid2env(envid, &env, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	env->env_pgfault_upcall = func;
	return 0;
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	struct Env *env = NULL;
	struct PageInfo *page;

	if (envid2env(envid, &env, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	// -E_INVAL if va is above UTOP (kernel address), or not page-aligned.
	if ((uint32_t) va >= UTOP || (uint32_t) va % PGSIZE != 0) {
		return -E_INVAL;
	}

	if (!check_perm(perm)) {
		return -E_INVAL;
	}

	page = page_alloc(ALLOC_ZERO);
	if (page == NULL) {
		return -E_NO_MEM;
	}

	if (page_insert(env->env_pgdir, page, va, perm) < 0) {
		page_free(page);
		return -E_NO_MEM;
	}

	return 0;
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	struct Env *srcenv = NULL, *dstenv = NULL;
	struct PageInfo *page;
	pte_t *pte = NULL;

	if (envid2env(srcenvid, &srcenv, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}
	if (envid2env(dstenvid, &dstenv, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	if ((uint32_t) srcva >= UTOP || (uint32_t) srcva % PGSIZE != 0) {
		return -E_INVAL;
	}
	if ((uint32_t) dstva >= UTOP || (uint32_t) dstva % PGSIZE != 0) {
		return -E_INVAL;
	}

	page = page_lookup(srcenv->env_pgdir, srcva, &pte);
	if (page == NULL) {
		return -E_INVAL;
	}

	// Permissions on PDE below UTOP are all P|U|W.
	if (!check_perm(perm)) {
		return -E_INVAL;
	}

	// Mapping a read-only page as writable is invalid.
	if ((perm & PTE_W) && (~(*pte) & PTE_W)) {
		return -E_INVAL;
	}

	if (page_insert(dstenv->env_pgdir, page, dstva, perm) < 0) {
		return -E_NO_MEM;
	}

	return 0;
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	struct Env *env = NULL;

	if (envid2env(envid, &env, true /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}
	if ((uint32_t) va >= UTOP || (uint32_t) va % PGSIZE != 0) {
		return -E_INVAL;
	}

	page_remove(env->env_pgdir, va);
	return 0;
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	struct Env *env = NULL;
	struct PageInfo *page;
	pte_t *pte = 0;

	// Intentionly to set checkperm as false.
	if (envid2env(envid, &env, false /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	if (env->env_ipc.ipc_status != IPC_BLOCKED_BY_RECV) {
		return -E_IPC_NOT_RECV;
	}

	if ((uint32_t) srcva < UTOP) {
		if ((uint32_t) srcva % PGSIZE != 0) {
			return -E_INVAL;
		}
		if (!check_perm(perm)) {
			return -E_INVAL;
		}
		// srcva is not mapped.
		page = page_lookup(curenv->env_pgdir, srcva, &pte);
		if (page == NULL) {
			return -E_INVAL;
		}
		// Mapping a read-only page as writable is invalid.
		if ((perm & PTE_W) && (~(*pte) & PTE_W)) {
			return -E_INVAL;
		}
	}

	env->env_ipc.ipc_status = IPC_NOT_BLOCKED;
	env->env_ipc.recv.from = curenv->env_id;
	env->env_ipc.recv.value = value;
	if ((uint32_t) srcva < UTOP && (uint32_t) env->env_ipc.recv.dstva < UTOP) {
		env->env_ipc.recv.perm = perm;
		if (page_insert(env->env_pgdir, page, env->env_ipc.recv.dstva, perm) < 0) {
			return -E_NO_MEM;
		}
	} else {
		env->env_ipc.recv.perm = 0;
	}

	env->env_status = ENV_RUNNABLE;

	return 0;
}

// Block version of 'sys_ipc_try_send'.
static int
sys_ipc_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	assert(curenv != NULL);
	assert(curenv->env_ipc.ipc_status == IPC_NOT_BLOCKED);

	struct Env *env = NULL;
	struct PageInfo *page = NULL;
	pte_t *pte = 0;

	// Intentionly to set checkperm as false.
	if (envid2env(envid, &env, false /* checkperm */) < 0) {
		return -E_BAD_ENV;
	}

	if ((uint32_t) srcva < UTOP) {
		if ((uint32_t) srcva % PGSIZE != 0) {
			return -E_INVAL;
		}
		if (!check_perm(perm)) {
			return -E_INVAL;
		}
		// srcva is not mapped.
		page = page_lookup(curenv->env_pgdir, srcva, &pte);
		if (page == NULL) {
			return -E_INVAL;
		}
		// Mapping a read-only page as writable is invalid.
		if ((perm & PTE_W) && (~(*pte) & PTE_W)) {
			return -E_INVAL;
		}
	} else {
		perm = 0;
	}
	curenv->env_ipc.ipc_status = IPC_BLOCKED_BY_SEND;
	curenv->env_ipc.send.value = value;
	curenv->env_ipc.send.to = envid;
	curenv->env_ipc.send.srcva = srcva;
	curenv->env_ipc.send.perm = perm;
	curenv->env_ipc.send.page = page;

	// Mark ourselves not runnable to block ourselves for IPC.
	curenv->env_status = ENV_NOT_RUNNABLE;

	// sys_yield() never returns, set return value as 0 in eax.
	// The return value may be altered by scheduler.
	curenv->env_tf.tf_regs.reg_eax = 0;

	// Give up the CPU.
	sys_yield();

	panic("sys_yield never returns.");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	assert(curenv != NULL);
	assert(curenv->env_ipc.ipc_status == IPC_NOT_BLOCKED);

	// Mark env_ipc_recving as 1 to indicate that we are ready for IPC.
	if ((uint32_t) dstva < UTOP) {
		if ((uint32_t) dstva % PGSIZE != 0) {
			return -E_INVAL;
		}
	}
	curenv->env_ipc.recv.dstva = dstva;

	curenv->env_ipc.ipc_status = IPC_BLOCKED_BY_RECV;

	// Mark ourselves not runnable to block ourselves for IPC.
	curenv->env_status = ENV_NOT_RUNNABLE;

	// sys_yield() never returns, set return value as 0 in eax.
	curenv->env_tf.tf_regs.reg_eax = 0;

	// Give up the CPU.
	sys_yield();

	panic("sys_yield never returns.");
}

// Return the current time.
static int
sys_time_msec(void)
{
	return time_msec();
}

// Transmit a network packet.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_PACKET_TOO_BIG if packet is too big.
//	-E_TX_QUEUE_FULL if transmission queue is full.
static int
sys_transmit_packet(uint8_t *buf, size_t len)
{
	user_mem_assert(curenv, buf, len, 0);

	return e1000_transmit(buf, len);
}

// Receive a network packet.
//
// Return 0 on success, < 0 on error.
// Errors are:
// 	-E_RX_QUEUE_EMPTY if receive queue is empty.
// 	-E_BUF_TOO_SMALL if buffer is too small.
static int
sys_receive_packet(uint8_t *buf, size_t len, size_t *len_store)
{
	ssize_t r;

	user_mem_assert(curenv, buf, len, PTE_W);

	if (len_store != NULL) {
		user_mem_assert(curenv, buf, sizeof(size_t), PTE_W);
	}

	r = e1000_receive(buf, len);
	if (r < 0) {
		return r;
	}

	if (len_store != NULL) {
		*len_store = r;
	}
	return 0;
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.

	if (syscallno >= NSYSCALLS) {
		return -E_INVAL;
	}

	switch (syscallno) {
	case SYS_cputs:
		sys_cputs((const char *) a1, (size_t) a2);
		return 0;
	case SYS_cgetc:
		return sys_cgetc();
	case SYS_env_destroy:
		return sys_env_destroy((envid_t) a1);
	case SYS_getenvid:
		return sys_getenvid();
	case SYS_yield:
		sys_yield();
		return 0;
	case SYS_exofork:
		return sys_exofork();
	case SYS_env_set_status:
		return sys_env_set_status((envid_t) a1, (int) a2);
	case SYS_page_alloc:
		return sys_page_alloc((envid_t) a1, (void *) a2, (int) a3);
	case SYS_page_map:
		return sys_page_map((envid_t) a1, (void *) a2, (envid_t) a3, (void *) a4, (int) a5);
	case SYS_page_unmap:
		return sys_page_unmap((envid_t) a1, (void *) a2);
	case SYS_env_set_pgfault_upcall:
		return sys_env_set_pgfault_upcall((envid_t) a1, (void *) a2);
	case SYS_ipc_try_send:
		return sys_ipc_try_send((envid_t) a1, (uint32_t) a2, (void *) a3, (unsigned) a4);
	case SYS_ipc_send:
		return sys_ipc_send((envid_t) a1, (uint32_t) a2, (void *) a3, (unsigned) a4);
	case SYS_ipc_recv:
		return sys_ipc_recv((void *) a1);
	case SYS_env_set_trapframe:
		return sys_env_set_trapframe((envid_t) a1, (struct Trapframe *) a2);
	case SYS_time_msec:
		return sys_time_msec();
	case SYS_transmit_packet:
		return sys_transmit_packet((uint8_t *) a1, (size_t) a2);
	case SYS_receive_packet:
		return sys_receive_packet((uint8_t *) a1, (size_t) a2, (size_t *) a3);
	default:
		panic("undispatched syscall.");
		return -E_INVAL;
	}
}

// PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
// but no other bits may be set.
static bool
check_perm(int perm) {
	// PTE_U and PTE_P must be set.
	if ((perm & (PTE_U | PTE_P)) != (PTE_U | PTE_P)) {
		return false;
	}
	// Permissions other than PTE_AVAIL | PTE_W is not permitted.
	if (perm & ~(PTE_U | PTE_P | PTE_AVAIL | PTE_W)) {
		return false;
	}
	return true;
}
