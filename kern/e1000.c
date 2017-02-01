#include <inc/assert.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/types.h>
#include <inc/x86.h>

#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>

#define MAXTXD   64   /* max transmit descriptor */
#define MAXRXD   128  /* max receive descriptor */
#define MAXTXBUF 1518 /* maximum size of an Ethernet packet is 1518 bytes */
#define MAXRXBUF 2048 /* required by E1000_RCTL_SZ_2048 */

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
#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */

#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */

#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */

#define E1000_MTA      0x05200  /* Multicast Table Array - RW Array */
#define E1000_RAL      0x05400  /* Receive Address Low - RW Array */
#define E1000_RAH      0x05404  /* Receive Address High - RW Array */

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
#define E1000_TXD_CMD_EOP    0x01       /* End of Packet */
#define E1000_TXD_CMD_IFCS   0x02       /* Insert FCS (Ethernet CRC) */
#define E1000_TXD_CMD_IC     0x04       /* Insert Checksum */
#define E1000_TXD_CMD_RS     0x08       /* Report Status */
#define E1000_TXD_CMD_RPS    0x10       /* Report Packet Sent */
#define E1000_TXD_CMD_DEXT   0x20       /* Descriptor extension (0 = legacy) */
#define E1000_TXD_CMD_VLE    0x40       /* Add VLAN tag */
#define E1000_TXD_CMD_IDE    0x80       /* Enable Tidv register */
#define E1000_TXD_STAT_DD    0x00000001 /* Descriptor Done */
#define E1000_TXD_STAT_EC    0x00000002 /* Excess Collisions */
#define E1000_TXD_STAT_LC    0x00000004 /* Late Collisions */
#define E1000_TXD_STAT_TU    0x00000008 /* Transmit underrun */
#define E1000_TXD_CMD_TCP    0x01       /* TCP packet */
#define E1000_TXD_CMD_IP     0x02       /* IP packet */
#define E1000_TXD_CMD_TSE    0x04       /* TCP Seg enable */
#define E1000_TXD_STAT_TC    0x00000004 /* Tx Underrun */

/* Receive Control */
#define E1000_RCTL_RST            0x00000001    /* Software reset */
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_SBP            0x00000004    /* store bad packet */
#define E1000_RCTL_UPE            0x00000008    /* unicast promiscuous enable */
#define E1000_RCTL_MPE            0x00000010    /* multicast promiscuous enab */
#define E1000_RCTL_LPE            0x00000020    /* long packet enable */
#define E1000_RCTL_LBM_NO         0x00000000    /* no loopback mode */
#define E1000_RCTL_LBM_MAC        0x00000040    /* MAC loopback mode */
#define E1000_RCTL_LBM_SLP        0x00000080    /* serial link loopback mode */
#define E1000_RCTL_LBM_TCVR       0x000000C0    /* tcvr loopback mode */
#define E1000_RCTL_DTYP_MASK      0x00000C00    /* Descriptor type mask */
#define E1000_RCTL_DTYP_PS        0x00000400    /* Packet Split descriptor */
#define E1000_RCTL_RDMTS_HALF     0x00000000    /* rx desc min threshold size */
#define E1000_RCTL_RDMTS_QUAT     0x00000100    /* rx desc min threshold size */
#define E1000_RCTL_RDMTS_EIGTH    0x00000200    /* rx desc min threshold size */
#define E1000_RCTL_MO_SHIFT       12            /* multicast offset shift */
#define E1000_RCTL_MO_0           0x00000000    /* multicast offset 11:0 */
#define E1000_RCTL_MO_1           0x00001000    /* multicast offset 12:1 */
#define E1000_RCTL_MO_2           0x00002000    /* multicast offset 13:2 */
#define E1000_RCTL_MO_3           0x00003000    /* multicast offset 15:4 */
#define E1000_RCTL_MDR            0x00004000    /* multicast desc ring 0 */
#define E1000_RCTL_BAM            0x00008000    /* broadcast enable */
/* these buffer sizes are valid if E1000_RCTL_BSEX is 0 */
#define E1000_RCTL_SZ_2048        0x00000000    /* rx buffer size 2048 */
#define E1000_RCTL_SZ_1024        0x00010000    /* rx buffer size 1024 */
#define E1000_RCTL_SZ_512         0x00020000    /* rx buffer size 512 */
#define E1000_RCTL_SZ_256         0x00030000    /* rx buffer size 256 */
/* these buffer sizes are valid if E1000_RCTL_BSEX is 1 */
#define E1000_RCTL_SZ_16384       0x00010000    /* rx buffer size 16384 */
#define E1000_RCTL_SZ_8192        0x00020000    /* rx buffer size 8192 */
#define E1000_RCTL_SZ_4096        0x00030000    /* rx buffer size 4096 */
#define E1000_RCTL_VFE            0x00040000    /* vlan filter enable */
#define E1000_RCTL_CFIEN          0x00080000    /* canonical form enable */
#define E1000_RCTL_CFI            0x00100000    /* canonical form indicator */
#define E1000_RCTL_DPF            0x00400000    /* discard pause frames */
#define E1000_RCTL_PMCF           0x00800000    /* pass MAC control frames */
#define E1000_RCTL_BSEX           0x02000000    /* Buffer size extension */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */
#define E1000_RCTL_FLXBUF_MASK    0x78000000    /* Flexible buffer size */
#define E1000_RCTL_FLXBUF_SHIFT   27            /* Flexible buffer shift */

/* Receive Descriptor bit definitions */
#define E1000_RXD_STAT_DD       0x01    /* Descriptor Done */
#define E1000_RXD_STAT_EOP      0x02    /* End of Packet */
#define E1000_RXD_STAT_IXSM     0x04    /* Ignore checksum */
#define E1000_RXD_STAT_VP       0x08    /* IEEE VLAN Packet */
#define E1000_RXD_STAT_UDPCS    0x10    /* UDP xsum caculated */
#define E1000_RXD_STAT_TCPCS    0x20    /* TCP xsum calculated */
#define E1000_RXD_STAT_IPCS     0x40    /* IP xsum calculated */
#define E1000_RXD_STAT_PIF      0x80    /* passed in-exact filter */
#define E1000_RXD_STAT_IPIDV    0x200   /* IP identification valid */
#define E1000_RXD_STAT_UDPV     0x400   /* Valid UDP checksum */
#define E1000_RXD_STAT_ACK      0x8000  /* ACK Packet indication */

#define E1000_MAXMTA         128

/* Transmit Descriptor */
struct e1000_tx_desc {
	uint64_t buffer_addr; /* Address of the descriptor's data buffer */
	uint16_t length;      /* Data buffer length */
	uint8_t cso;          /* Checksum offset */
	uint8_t cmd;          /* Descriptor control */
	uint8_t status;	      /* Descriptor status */
	uint8_t css;          /* Checksum start */
	uint16_t special;
} __attribute__((packed));

/* Receive Descriptor */
struct e1000_rx_desc {
	uint64_t buffer_addr; /* Address of the descriptor's data buffer */
	uint16_t length;      /* Length of data DMAed into data buffer */
	uint16_t csum;        /* Packet checksum */
	uint8_t status;       /* Descriptor status */
	uint8_t errors;       /* Descriptor Errors */
	uint16_t special;
} __attribute__((packed));

typedef struct {
	uint8_t buf[MAXTXBUF];
} tx_packet_t;

typedef struct {
	uint8_t buf[MAXRXBUF];
} rx_packet_t;

physaddr_t e1000addr;
volatile uint32_t *e1000;

__attribute__((__aligned__(16)))
struct e1000_tx_desc e1000_txd[MAXTXD];
__attribute__((__aligned__(16)))
struct e1000_rx_desc e1000_rxd[MAXRXD];

tx_packet_t tx_buf[MAXTXD];
rx_packet_t rx_buf[MAXRXD];

int
e1000_attach(struct pci_func *f)
{
	int i;

	pci_func_enable(f);

	e1000addr = (physaddr_t) f->reg_base[0];
	e1000 = (uint32_t *) mmio_map_region(e1000addr, (size_t) f->reg_size[0]);

	// Check E1000 status register to ensure MMIO memory is mapped correctly.
	// 0x80080783 indicates a full duplex link is up at 1000 MB/s, among other
	// things.
	if (e1000[E1000_STATUS >> 2] != 0x80080783) {
		panic("bad e1000 bar 0 mapping.");
	}

	// Transmit initialization.
	// See chapter 14.4 and 14.5 of Intel's software developer's manual for the E1000 for details.
	// https://pdos.csail.mit.edu/6.828/2016/readings/hardware/8254x_GBe_SDM.pdf

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
		e1000_txd[i].cmd |= E1000_TXD_CMD_RS;
		e1000_txd[i].status |= E1000_TXD_STAT_DD;
	}

	// Receive initialization.

	// MAC address of QEMU = 52:54:00:12:34:56.
	// Notice host is little endian, and MAC addresses are written from
	// lowest-order byte to highest-order byte
	e1000[E1000_RAL >> 2] = 0x12005452;
	e1000[E1000_RAH >> 2] = 0x5634 | (1u << 31);

	for (i = 0; i < E1000_MAXMTA; ++i) {
		e1000[(E1000_MTA >> 2) + i] = 0;
	}

	e1000[E1000_RDBAL >> 2] = PADDR(e1000_rxd);
	e1000[E1000_RDBAH >> 2] = 0;
	e1000[E1000_RDLEN >> 2] = sizeof(e1000_rxd);

	e1000[E1000_RDH >> 2] = 0;
	e1000[E1000_RDT >> 2] = MAXRXD - 1;

	memset(e1000_rxd, 0, sizeof(e1000_rxd));

	for (i = 0; i < MAXRXD; ++i) {
		e1000_rxd[i].buffer_addr = PADDR(&rx_buf[i]);
	}

	e1000[E1000_RCTL >> 2]  = E1000_RCTL_SECRC | E1000_RCTL_LBM_NO | E1000_RCTL_SZ_2048;
	e1000[E1000_RCTL >> 2] |= E1000_RCTL_EN;

	return 1;
}

// Return 0 on success.
int
e1000_transmit(uint8_t *buf, size_t len)
{
	uint32_t tail;

	if (len > MAXTXBUF) {
		return -E_PACKET_TOO_BIG;
	}

	tail = e1000[E1000_TDT >> 2];

	if (~e1000_txd[tail].status & E1000_TXD_STAT_DD) {
		return -E_TX_QUEUE_FULL;
	}

	// Copy data into kernel buffer.
	memcpy(&tx_buf[tail].buf, buf, len);
	e1000_txd[tail].length = len;
	
	// Clear DD flag and set EOP flag.
	e1000_txd[tail].status &= ~E1000_TXD_STAT_DD;
	e1000_txd[tail].cmd |= E1000_TXD_CMD_EOP;

	// Increase tail pointer.
	e1000[E1000_TDT >> 2] = (tail + 1) % MAXTXD;

	return 0;
}

// Return number of bytes received. Negative value for error.
ssize_t
e1000_receive(uint8_t *buf, size_t len) {
	uint32_t tail, length;

	tail = (e1000[E1000_RDT >> 2] + 1) % MAXRXD;

	if (~e1000_rxd[tail].status & E1000_RXD_STAT_DD) {
		return -E_RX_QUEUE_EMPTY;
	}

	if ((length = e1000_rxd[tail].length) > len) {
		return -E_BUF_TOO_SMALL;
	}

	memcpy(buf, rx_buf[tail].buf, length);

	// Clear DD flag and EOP flag.
	e1000_rxd[tail].status &= ~E1000_RXD_STAT_DD;
	e1000_rxd[tail].status &= ~E1000_RXD_STAT_EOP;

	e1000[E1000_RDT >> 2] = tail;

	return length;
}
