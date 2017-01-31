#include <inc/assert.h>
#include <inc/types.h>
#include <inc/x86.h>
#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>

physaddr_t e1000addr;
size_t e1000size;
volatile uint32_t *e1000;

int
pci_e1000_attach(struct pci_func *f) {
	pci_func_enable(f);

	e1000addr = (physaddr_t) f->reg_base[0];
	e1000size = (size_t) f->reg_size[0];

	e1000 = (uint32_t *) mmio_map_region(e1000addr, e1000size);

	if (e1000[2] != 0x80080783) {
		panic("bad e1000 bar 0 mapping.");
	}

	return 1;
}
