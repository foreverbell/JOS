// test user-level fault handler -- alloc pages to fix faults
// doesn't work because we sys_cputs instead of cprintf (exercise: why?)

// Answer: sys_cputs does dereferencing in kernel mode (of course with a
// user_mem_check guard), while cprintf will do dereferencing before entering
// the kernel. In latter case, reading from an invalid address will cause page
// fault.

#include <inc/lib.h>

void
handler(struct UTrapframe *utf)
{
	int r;
	void *addr = (void*)utf->utf_fault_va;

	cprintf("fault %x\n", addr);
	if ((r = sys_page_alloc(0, ROUNDDOWN(addr, PGSIZE),
				PTE_P|PTE_U|PTE_W)) < 0)
		panic("allocating at %x in page fault handler: %e", addr, r);
	snprintf((char*) addr, 100, "this string was faulted in at %x", addr);
}

void
umain(int argc, char **argv)
{
	set_pgfault_handler(handler);
	sys_cputs((char*)0xDEADBEEF, 4);
}
