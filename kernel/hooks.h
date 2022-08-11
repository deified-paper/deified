#ifndef _HQ_HOOKS_H_
#define _HQ_HOOKS_H_

extern unsigned long (*lookup_name)(const char *name);

/* Declared definitions */
int tracepoints_insert(void);
void tracepoints_remove(void);

int kprobes_insert(void);
void kprobes_remove(void);

int fpga_init(void);
void fpga_finish(void);

#endif
