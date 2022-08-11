#ifndef _HQ_INTERFACE_IPC_H_
#define _HQ_INTERFACE_IPC_H_

#include <linux/file.h>

#include "interfaces.h"

/* Declared functions */
struct file *ipc_create_file(void);
uintptr_t ipc_map_file(struct file *);

#endif /* _HQ_INTERFACE_IPC_H_ */
