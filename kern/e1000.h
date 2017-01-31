#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <inc/types.h>

struct pci_func;  // forward declaration

int e1000_attach(struct pci_func *f);
int e1000_transmit(uint8_t *buf, size_t len);

#endif	// JOS_KERN_E1000_H
