/* SPDX-License-Identifier: (GPL-2.0 OR MIT OR Apache-2.0) */
/*
 * orthrus — watchdog for the cerberus eBPF agent.
 *
 * Licensed under any of GPL-2.0, MIT, or Apache-2.0 at your option, matching
 * the cerberus project. The MODULE_LICENSE tag below is "Dual MIT/GPL": the
 * kernel recognizes it as GPL-compatible (so the module does not taint and may
 * use GPL-only symbols), while the SPDX line above records the full set. The
 * Apache-2.0 option lives in SPDX and the project LICENSE files — the kernel's
 * MODULE_LICENSE vocabulary has no token that spells it, so it can't appear
 * there.
 *
 * SAFETY: kernel code, no verifier. A bug here panics or hangs the machine.
 * Load only in a VM you can snapshot and hard-reboot.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init orthrus_init(void) {
  pr_info("[orthrus]: loaded\n");
  return 0;
}

static void __exit orthrus_exit(void) { pr_info("[orthrus]: unloaded\n"); }

module_init(orthrus_init);
module_exit(orthrus_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("cerberus");
MODULE_DESCRIPTION("Watchdog for the cerberus eBPF agent");
MODULE_VERSION("0.1");