#ifndef QEMU_TCMU_H
#define QEMU_TCMU_H

#include "qemu-common.h"

typedef struct TCMUExport TCMUExport;
extern QemuOptsList qemu_tcmu_export_opts;

void qemu_tcmu_start(const char *subtype, Error **errp);
TCMUExport *qemu_tcmu_export(BlockBackend *blk, bool writable, Error **errp);
int export_init_func(void *opaque, QemuOpts *all_opts, Error **errp);

#endif
