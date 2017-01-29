/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/* 
 * https://pdos.csail.mit.edu/6.828/2016/readings/i386/s09_10.htm
 *
 * Table 9-7. Error-Code Summary
 * 
 * Description                       Interrupt     Error Code
 * Number
 * 
 * Divide error                       0            No
 * Debug exceptions                   1            No
 * Breakpoint                         3            No
 * Overflow                           4            No
 * Bounds check                       5            No
 * Invalid opcode                     6            No
 * Coprocessor not available          7            No
 * System error                       8            Yes (always 0)
 * Invalid TSS                       10            Yes
 * Segment not present               11            Yes
 * Stack exception                   12            Yes
 * General protection fault          13            Yes
 * Page fault                        14            Yes
 * Coprocessor error                 16            No
 * Two-byte SW interrupt             0-255         No
 *
 */

TRAPHANDLER_NOEC(trap_handler0, 0)
TRAPHANDLER_NOEC(trap_handler1, 1)
TRAPHANDLER_NOEC(trap_handler2, 2)
TRAPHANDLER_NOEC(trap_handler3, 3)
TRAPHANDLER_NOEC(trap_handler4, 4)
TRAPHANDLER_NOEC(trap_handler5, 5)
TRAPHANDLER_NOEC(trap_handler6, 6)
TRAPHANDLER_NOEC(trap_handler7, 7)
TRAPHANDLER     (trap_handler8, 8)
TRAPHANDLER     (trap_handler10, 10)
TRAPHANDLER     (trap_handler11, 11)
TRAPHANDLER     (trap_handler12, 12)
TRAPHANDLER     (trap_handler13, 13)
TRAPHANDLER     (trap_handler14, 14)
TRAPHANDLER_NOEC(trap_handler16, 16)
TRAPHANDLER_NOEC(trap_handler17, 17)
TRAPHANDLER_NOEC(trap_handler18, 18)
TRAPHANDLER_NOEC(trap_handler19, 19)

TRAPHANDLER_NOEC(trap_handler48, 48)  // syscall

_alltraps:
	pushl %ds
	pushl %es
	pushal
	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es
	movl $0, %ebp  // nuke frame pointer
	pushl %esp
	call trap      // trap() never returns
