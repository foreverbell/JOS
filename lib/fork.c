// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

// Assembly language pgfault entrypoint defined in lib/pfentry.S.
extern void _pgfault_upcall(void);

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;
	uint32_t pn;
	int perm;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	if (~err & FEC_WR) {
		panic("pgfault: va %08x is not a write fault!", addr);
	}

	pn = PGNUM(addr);
	if (~uvpt[pn] & PTE_COW) {
		panic("pgfault: va %08x is not a fault on copy-on-write page!", addr);
	}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// Aligned by page size.
	addr = ROUNDDOWN(addr, PGSIZE);

	if ((r = sys_page_alloc(0, PFTEMP, PTE_P | PTE_U | PTE_W)) < 0) {
		panic("sys_page_alloc fails: %e.", r);
	}

	memmove(PFTEMP, addr, PGSIZE);

	perm = PTE_P | PTE_W;
	if (uvpt[pn] & PTE_U) {
		perm |= PTE_U;
	}

	if ((r = sys_page_map(0, PFTEMP, 0, addr, perm)) < 0) {
		panic("sys_page_map fails: %e.", r);
	}

	if ((r = sys_page_unmap(0, PFTEMP)) < 0) {
		panic("sys_page_unmap fails: %e.", r);
	}
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r, perm = 0;
	void *va = (void *) (pn * PGSIZE);

	if ((uvpt[pn] & PTE_W) || (uvpt[pn] & PTE_COW)) {
		perm = PTE_P | PTE_COW;
		if (uvpt[pn] & PTE_U) {
			perm |= PTE_U;
		}

		if ((r = sys_page_map(0, va, envid, va, perm)) < 0) {
			panic("sys_page_map fails: %e.", r);
			return r;
		}
		if ((r = sys_page_map(0, va, 0, va, perm)) < 0) {
			panic("sys_page_map fails: %e.", r);
			return r;
		}
	} else {
		if ((r = sys_page_map(0, va, envid, va, uvpt[pn] & PTE_SYSCALL)) < 0) {
			panic("sys_page_map fails: %e.", r);
			return r;
		}
	}

	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	envid_t envid;
	int r;
	uintptr_t page_va;

	// Set pgfault_handler for parent environment, as COW is both set for parent
	// and child.
	set_pgfault_handler(pgfault);

	envid = sys_exofork();
	if (envid < 0) {
		return envid;
	}

	if (envid > 0) { // parent
		for (page_va = 0; page_va < UTOP; page_va += PGSIZE) {
			if (page_va == UXSTACKTOP - PGSIZE) { // user exception stack
				continue;
			}
			if ((uvpd[PDX(page_va)] & PTE_P) && (uvpt[PGNUM(page_va)] & PTE_P)) {
				if ((r = duppage(envid, PGNUM(page_va))) < 0) {
					panic("duppage fails: %e\n", r);
				}
			}
		}

		// Setup user exception stack for child.
		if ((r = sys_page_alloc(envid, (void *) (UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W)) < 0) {
			panic("sys_page_alloc fails: %e\n", r);
		}

		// Setup pgfault_handler for child.
		if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) < 0) {
			panic("sys_env_set_pgfault_upcall fails: %e\n", r);
		}

		// Note: We can't move down setting pgfault_handler into child env,
		// as there is possibility that child may raise a page fault on COW
		// pages before it completes installing page fault handler.

		// Mark child environment as runnable.
		if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0) {
			panic("sys_env_set_status fails: %e\n", r);
		}
	} else { // child
		thisenv = envs + ENVX(sys_getenvid());
	}

	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
