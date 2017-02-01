#include "ns.h"

extern union Nsipc nsipcbuf;

void
output(envid_t ns_envid)
{
	int r, perm;
	envid_t from_env;
	int nretries;
	uint8_t *pkt_data;
	size_t pkt_len;

	binaryname = "ns_output";

	// Read a packet from the network server.
	// Send the packet to the device driver.
	while (true) {
		r = ipc_recv(&from_env, &nsipcbuf, &perm);

		// Filter invalid RPCs.
		if (r != NSREQ_OUTPUT || from_env != ns_envid) {
			continue;
		}
		if ((perm & (PTE_P | PTE_W | PTE_U)) != (PTE_P | PTE_W | PTE_U)) {
			continue;
		}

		nretries = 0;

		pkt_data = (uint8_t *) nsipcbuf.pkt.jp_data;
		pkt_len = nsipcbuf.pkt.jp_len;

		while ((r = sys_transmit_packet(pkt_data, pkt_len)) < 0) {
			if (r == -E_PACKET_TOO_BIG) {
				cprintf("packet %08x is too big, size = %d.\n", pkt_data, pkt_len);
			}
			++nretries;
			if (nretries > 10) {
				cprintf("packet %08x still fails to send after 10 retries.\n", pkt_data);
				break;
			}

			// Be CPU friendly.
			sys_yield();
		}
	}
}
