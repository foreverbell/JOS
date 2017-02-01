#include "ns.h"

extern union Nsipc nsipcbuf;

void
input(envid_t ns_envid)
{
	int i, r;
	size_t len_store;
	uint8_t *buf;

	binaryname = "ns_input";

	// Read a packet from the device driver.
	// Send it to the network server.
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.

	buf = (uint8_t *) nsipcbuf.pkt.jp_data;

	// Warm up the nsipc buffer.
	// This is actually a drawback of current JOS, as JOS is an exokernel
	// which handles copy-on-write and page fault in user mode. The input
	// environment is forked from network server, 'nsipcbuf' is a COW page,
	// but the kernel does not handle the COW page correctly when validating
	// buffer from user in syscall (directly writing to COW memory in kernel
	// will lead to unrecoverable page fault).
	// FIXME: A possible fix is to modify user_mem_assert to make it
	// copy-on-write-aware.
	memset(buf, 0, 1518);

	while (true) {
		while ((r = sys_receive_packet(buf, 1518, &len_store)) < 0) {
			if (r == -E_BUF_TOO_SMALL) {
				panic("Buffer size is too small");
			}
			sys_yield();
		}

		nsipcbuf.pkt.jp_len = len_store;

		// network server has no write permission.
		ipc_send(ns_envid, NSREQ_INPUT, &nsipcbuf, PTE_P | PTE_U | PTE_W);

		for (i = 0; i < 10; ++i) {
			sys_yield();
		}
	}
}
