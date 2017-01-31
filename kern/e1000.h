#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

struct pci_func;  // forward declaration

int pci_e1000_attach(struct pci_func *f);

#endif	// JOS_KERN_E1000_H
