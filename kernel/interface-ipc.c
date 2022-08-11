#include <asm/mman.h>
#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/memfd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <uapi/linux/memfd.h>

#include "config.h"
#include "fpga.h"
#include "hooks.h"
#include "hq.h"
#include "interfaces.h"

#include "interface-ipc.h"

#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/fpga-dfl.h>
typedef struct dfl_fpga_port_region_info fpga_port_info_t;
#define GET_REGION_INFO DFL_FPGA_PORT_GET_REGION_INFO
#define REGION_INDEX_AFU DFL_PORT_REGION_INDEX_AFU
#define MASK_WRITE_MMAP (DFL_PORT_REGION_WRITE | DFL_PORT_REGION_MMAP)
#else
#include <linux/intel-fpga.h>
#include <linux/ioctl.h>
typedef struct fpga_port_region_info fpga_port_info_t;
#define GET_REGION_INFO FPGA_PORT_GET_REGION_INFO
#define REGION_INDEX_AFU FPGA_PORT_INDEX_UAFU
#define MASK_WRITE_MMAP (m)
#endif /* LINUX_VERSION_CODE */
#endif

/* Unexported kernel functions that must be looked up */
static unsigned long (*vm_mmap_pgoff_fp)(struct file *, unsigned long addr,
                                         unsigned long, unsigned long,
                                         unsigned long, unsigned long);
#if INTERFACE_TYPE == INTERFACE_TYPE_MODEL
static struct file *(*hugetlb_file_setup_fp)(const char *, size_t, vm_flags_t,
                                             struct user_struct **uesr, int,
                                             int);
static unsigned int *(*memfd_file_seals_ptr_fp)(struct file *);

static const unsigned get_hugetlb_flags(bool mmap) {
    if (!(HQ_INTERFACE_APPLICATION_SIZE % 1073741824))
        return (mmap ? MAP_HUGETLB : MFD_HUGETLB) | MAP_HUGE_1GB;
    else if (!(HQ_INTERFACE_APPLICATION_SIZE % 2097152))
        return (mmap ? MAP_HUGETLB : MFD_HUGETLB) | MAP_HUGE_2MB;
    return 0;
}
#endif

struct file *ipc_create_file(void) {
#if INTERFACE_TYPE == INTERFACE_TYPE_MODEL
#define MFD_NAME_PREFIX "memfd:"
#define MFD_ALL_FLAGS (MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB)

    // int fd = memfd_create("HQ", MFD_CLOEXEC | MFD_ALLOW_SEALING |
    //                                 get_hugetlb_flags(false));
    // ftruncate(fd, HQ_INTERFACE_APPLICATION_SIZE);
    // fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW);
    struct file *file;
    unsigned int flags =
        MFD_CLOEXEC | MFD_ALLOW_SEALING | get_hugetlb_flags(false);
    unsigned int *file_seals;

    if (!(flags & MFD_HUGETLB)) {
        if (flags & ~(unsigned int)MFD_ALL_FLAGS)
            return NULL;
    } else {
        /* Allow huge page size encoding in flags. */
        if (flags &
            ~(unsigned int)(MFD_ALL_FLAGS | (MFD_HUGE_MASK << MFD_HUGE_SHIFT)))
            return NULL;
    }

    if (flags & MFD_HUGETLB) {
        struct user_struct *user = NULL;

        if (!hugetlb_file_setup_fp) {
            hugetlb_file_setup_fp =
                (void *)(*lookup_name)("hugetlb_file_setup");
            if (!hugetlb_file_setup_fp) {
                pr_err("Cannot lookup 'hugetlb_file_setup'!\n");
                return NULL;
            }
        }

        file = (*hugetlb_file_setup_fp)(
            MFD_NAME_PREFIX "HQ", HQ_INTERFACE_APPLICATION_SIZE, VM_NORESERVE,
            &user, HUGETLB_ANONHUGE_INODE,
            (flags >> MFD_HUGE_SHIFT) & MFD_HUGE_MASK);
    } else
        file = shmem_file_setup(MFD_NAME_PREFIX "HQ",
                                HQ_INTERFACE_APPLICATION_SIZE, VM_NORESERVE);
    if (IS_ERR(file))
        return file;
    file->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
    file->f_flags |= O_LARGEFILE;

    if (flags & MFD_ALLOW_SEALING) {
        if (!memfd_file_seals_ptr_fp) {
            memfd_file_seals_ptr_fp =
                (void *)(*lookup_name)("memfd_file_seals_ptr");
            if (!memfd_file_seals_ptr_fp) {
                pr_err("Cannot lookup 'memfd_file_seals_ptr'!\n");
                return NULL;
            }
        }
        file_seals = (*memfd_file_seals_ptr_fp)(file);
        *file_seals |= F_SEAL_SEAL | F_SEAL_GROW | F_SEAL_SHRINK;
    }

    return file;
#elif INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    // Must be O_RDWR (instead of O_WRONLY) to mmap with MAP_SHARED |
    // PROT_WRITE
    // open(FPGA_PATH, O_CLOEXEC | O_SYNC | O_RDWR, 0)
    return filp_open(FPGA_PATH, O_CLOEXEC | O_SYNC | O_RDWR, 0);
#else
#error "Selected interface has not been implemented in kernel!"
#endif
}

uintptr_t ipc_map_file(struct file *f) {
#if INTERFACE_TYPE == INTERFACE_TYPE_MODEL
    // mmap(HQ_INTERFACE_MAP_ADDRESS, HQ_INTERFACE_APPLICATION_SIZE, PROT_READ |
    // PROT_WRITE, MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE |
    // get_hugetlb_flags(true), fd, 0)
    // madvise(HQ_INTERFACE_MAP_ADDRESS, HQ_INTERFACE_APPLICATION_SIZE,
    // MADV_DONTFORK)
    unsigned long addr;
    struct vm_area_struct *vma;
    if (!vm_mmap_pgoff_fp) {
        vm_mmap_pgoff_fp = (void *)(*lookup_name)("vm_mmap_pgoff");
        if (!vm_mmap_pgoff_fp) {
            pr_err("Cannot lookup 'vm_mmap_pgoff'!\n");
            return -EINVAL;
        }
    }

    addr = (*vm_mmap_pgoff_fp)(f, HQ_INTERFACE_MAP_ADDRESS,
                               HQ_INTERFACE_APPLICATION_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE |
                                   get_hugetlb_flags(true),
                               0);
    if (IS_ERR((const void *)addr)) {
        pr_err("Cannot map file!\n");
        return addr;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    if (mmap_write_lock_killable(current->mm))
        return -EINTR;
#else
    if (down_write_killable(&current->mm->mmap_sem))
        return -EINTR;
#endif

    vma = find_vma_intersection(current->mm, addr,
                                addr + HQ_INTERFACE_APPLICATION_SIZE);
    if (!vma) {
        pr_err("Cannot find VMA!\n");
        goto unlock;
    }

    vma->vm_flags |= VM_DONTCOPY;
unlock:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_write_unlock(current->mm);
#else
    up_write(&current->mm->mmap_sem);
#endif

    return addr;
#elif INTERFACE_TYPE == INTERFACE_TYPE_OPAE
    // ioctl(fd, GET_REGION_INFO, &info) || (info.flags & MASK_WRITE_MMAP) !=
    // MASK_WRITE_MMAP || info.size != FPGA_MMIO_SIZE
    // mmap(HQ_INTERFACE_MAP_ADDRESS, FPGA_MMIO_SIZE, PROT_WRITE,
    // MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE, fd, info.offset);
    fpga_port_info_t info = {
        .argsz = sizeof(info),
        .flags = 0,
        .index = REGION_INDEX_AFU,
        .padding = 0,
    };
    long ret;

    if ((ret = vfs_ioctl(f, GET_REGION_INFO, (uintptr_t)&info)))
        return ret;

    if ((info.flags & MASK_WRITE_MMAP) != MASK_WRITE_MMAP ||
        info.size != FPGA_MMIO_SIZE)
        return -EINVAL;

    if (!vm_mmap_pgoff_fp) {
        vm_mmap_pgoff_fp = (void *)(*lookup_name)("vm_mmap_pgoff");
        if (!vm_mmap_pgoff_fp) {
            pr_err("Cannot lookup 'vm_mmap_pgoff'!\n");
            return -EINVAL;
        }
    }

    return vm_mmap_pgoff_fp(f, HQ_INTERFACE_MAP_ADDRESS, FPGA_MMIO_SIZE,
                            PROT_WRITE,
                            MAP_FIXED | MAP_SHARED_VALIDATE | MAP_POPULATE, 0);
#else
#error "Selected interface has not been implemented in kernel!"
#endif
}
