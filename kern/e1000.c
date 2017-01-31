#include <inc/assert.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/types.h>
#include <inc/x86.h>

#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>

#define MAXTXD   64  /* max transmit descriptor */
#define MAXTXBUF 1518 /* maximum size of an Ethernet packet is 1518 bytes */

/* Register Set. (82543, 82544)
 *
 * Registers are defined to be 32 bits and  should be accessed as 32 bit values.
 * These registers are physically located on the NIC, but are mapped into the
 * host memory address space.
 *
 * RW - register is both readable and writable
 * RO - register is read only
 * WO - register is write only
 * R/clr - register is read only and is cleared when read
 * A - register array
 */
#define E1000_STATUS   0x00008  /* Device Status - RO */
#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */

/* Transmit Control */
#define E1000_TCTL_RST    0x00000001    /* software reset */
#define E1000_TCTL_EN     0x00000002    /* enable tx */
#define E1000_TCTL_BCE    0x00000004    /* busy check enable */
#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
#define E1000_TCTL_CT     0x00000ff0    /* collision threshold */
#define E1000_TCTL_COLD   0x003ff000    /* collision distance */
#define E1000_TCTL_SWXOFF 0x00400000    /* SW Xoff transmission */
#define E1000_TCTL_PBE    0x00800000    /* Packet Burst Enable */
#define E1000_TCTL_RTLC   0x01000000    /* Re-transmit on late collision */
#define E1000_TCTL_NRTU   0x02000000    /* No Re-transmit on underrun */
#define E1000_TCTL_MULR   0x10000000    /* Multiple request support */

/* Transmit Descriptor bit definitions */
#define E1000_TXD_DTYP_D     0x00100000 /* Data Descriptor */
#define E1000_TXD_DTYP_C     0x00000000 /* Context Descriptor */
#define E1000_TXD_POPTS_IXSM 0x01       /* Insert IP checksum */
#define E1000_TXD_POPTS_TXSM 0x02       /* Insert TCP/UDP checksum */
#define E1000_TXD_CMD_EOP    0x01000000 /* End of Packet */
#define E1000_TXD_CMD_IFCS   0x02000000 /* Insert FCS (Ethernet CRC) */
#define E1000_TXD_CMD_IC     0x04000000 /* Insert Checksum */
#define E1000_TXD_CMD_RS     0x08000000 /* Report Status */
#define E1000_TXD_CMD_RPS    0x10000000 /* Report Packet Sent */
#define E1000_TXD_CMD_DEXT   0x20000000 /* Descriptor extension (0 = legacy) */
#define E1000_TXD_CMD_VLE    0x40000000 /* Add VLAN tag */
#define E1000_TXD_CMD_IDE    0x80000000 /* Enable Tidv register */
#define E1000_TXD_STAT_DD    0x00000001 /* Descriptor Done */
#define E1000_TXD_STAT_EC    0x00000002 /* Excess Collisions */
#define E1000_TXD_STAT_LC    0x00000004 /* Late Collisions */
#define E1000_TXD_STAT_TU    0x00000008 /* Transmit underrun */
#define E1000_TXD_CMD_TCP    0x01000000 /* TCP packet */
#define E1000_TXD_CMD_IP     0x02000000 /* IP packet */
#define E1000_TXD_CMD_TSE    0x04000000 /* TCP Seg enable */
#define E1000_TXD_STAT_TC    0x00000004 /* Tx Underrun */

/* Transmit Descriptor */
struct e1000_tx_desc {
	uint64_t buffer_addr;       /* Address of the descriptor's data buffer */
	union {
		uint32_t data;
		struct {
			uint16_t length;    /* Data buffer length */
			uint8_t cso;        /* Checksum offset */
			uint8_t cmd;        /* Descriptor control */
		} flags;
	} lower;
	union {
		uint32_t data;
		struct {
			uint8_t status;	    /* Descriptor status */
			uint8_t css;        /* Checksum start */
			uint16_t special;
		} fields;
	} upper;
} __attribute__((packed));

typedef struct {
	uint8_t buf[MAXTXBUF];
} packet_t;

physaddr_t e1000addr;
size_t e1000size;
volatile uint32_t *e1000;

__attribute__((__aligned__(16)))
struct e1000_tx_desc e1000_txd[MAXTXD];

packet_t tx_buf[MAXTXD];

int
e1000_attach(struct pci_func *f) {
	int i;

	pci_func_enable(f);

	e1000addr = (physaddr_t) f->reg_base[0];
	e1000size = (size_t) f->reg_size[0];

	e1000 = (uint32_t *) mmio_map_region(e1000addr, e1000size);

	// Check E1000 status register to ensure MMIO memory is mapped correctly.
	// 0x80080783 indicates a full duplex link is up at 1000 MB/s, among other
	// things.
	if (e1000[E1000_STATUS >> 2] != 0x80080783) {
		panic("bad e1000 bar 0 mapping.");
	}

	// Transmit initialization.
	static_assert((uint32_t) e1000_txd % 16 == 0);
	static_assert(sizeof(e1000_txd) % 128 == 0);

	e1000[E1000_TDBAL >> 2] = PADDR(e1000_txd);
	e1000[E1000_TDBAH >> 2] = 0;
	e1000[E1000_TDLEN >> 2] = sizeof(e1000_txd);

	e1000[E1000_TDH >> 2] = 0;
	e1000[E1000_TDT >> 2] = 0;

	e1000[E1000_TCTL >> 2]  = E1000_TCTL_EN | E1000_TCTL_PSP;
	e1000[E1000_TCTL >> 2] |= 0x10 << 4;  // E1000_TCTL_CT
	e1000[E1000_TCTL >> 2] |= 0x40 << 12; // E1000_TCTL_COLD

	e1000[E1000_TIPG >> 2]  = 0xa;
	e1000[E1000_TIPG >> 2] |= 0x8 << 10;
	e1000[E1000_TIPG >> 2] |= 0xc << 20;

	memset(e1000_txd, 0, sizeof(e1000_txd));

	for (i = 0; i < MAXTXD; ++i) {
		e1000_txd[i].buffer_addr = PADDR(&tx_buf[i]);
		e1000_txd[i].lower.data |= E1000_TXD_CMD_RS;
		e1000_txd[i].upper.data |= E1000_TXD_STAT_DD;
	}

	return 1;
}

int
e1000_transmit(uint8_t *buf, size_t len) {
	uint32_t tail;

	if (len > MAXTXBUF) {
		return -E_PACKET_TOO_BIG;
	}

	tail =	e1000[E1000_TDT >> 2];

	if (~e1000_txd[tail].upper.data & E1000_TXD_STAT_DD) {
		return -E_TX_QUEUE_FULL;
	}

	// Copy data into kernel buffer.
	memcpy(&tx_buf[tail].buf, buf, len);
	e1000_txd[tail].lower.flags.length = len;
	
	// Clear DD flag and set EOP flag.
	e1000_txd[tail].upper.data &= ~E1000_TXD_STAT_DD;
	e1000_txd[tail].lower.data |= E1000_TXD_CMD_EOP;

	// Increase tail pointer.
	e1000[E1000_TDT >> 2] = (tail + 1) % MAXTXD;

	return 0;
}
