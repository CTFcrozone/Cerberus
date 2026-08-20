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
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "orthrus.h"

static DEFINE_MUTEX(state_lock);
static u64 last_heartbeat_ns;
static bool heartbeat_seen;
static u32 agent_pid;
static int orthrus_send_tamper(const char *reason, u64 age_ms);

static int orthrus_cmd_heartbeat(struct sk_buff *skb, struct genl_info *info) {
  u32 pid = 0;

  if (info->attrs[ORTHRUS_ATTR_PID]) {
    pid = nla_get_u32(info->attrs[ORTHRUS_ATTR_PID]);
  }

  mutex_lock(&state_lock);
  last_heartbeat_ns = ktime_get_ns();
  heartbeat_seen = true;
  if (pid) {
    agent_pid = pid;
  }

  mutex_unlock(&state_lock);
  orthrus_send_tamper("heartbeat-test", 0);

  return 0;
}

static const struct genl_ops orthrus_ops[] = {
    {.cmd = ORTHRUS_CMD_HEARTBEAT, .doit = orthrus_cmd_heartbeat, .flags = 0}};

static const struct nla_policy orthrus_policy[ORTHRUS_ATTR_MAX + 1] = {
    [ORTHRUS_ATTR_PID] = {.type = NLA_U32},
    [ORTHRUS_ATTR_REASON] = {.type = NLA_NUL_STRING, .len = 64},
    [ORTHRUS_ATTR_AGE_MS] = {.type = NLA_U64}};

static const struct genl_multicast_group orthrus_mcgrps[] = {
    [ORTHRUS_MCGRP_TAMPER] = {.name = "tamper"},
};

static struct genl_family orthrus_family = {.name = ORTHRUS_GENL_NAME,
                                            .version = ORTHRUS_GENL_VERSION,
                                            .maxattr = ORTHRUS_ATTR_MAX,
                                            .policy = orthrus_policy,
                                            .module = THIS_MODULE,
                                            .ops = orthrus_ops,
                                            .n_ops = ARRAY_SIZE(orthrus_ops),
                                            .mcgrps = orthrus_mcgrps,
                                            .n_mcgrps =
                                                ARRAY_SIZE(orthrus_mcgrps)};

static int orthrus_send_tamper(const char *reason, u64 age_ms) {
  struct sk_buff *skb;
  void *hdr;
  int ret;

  skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
  if (!skb) {
    return -ENOMEM;
  }
  hdr = genlmsg_put(skb, 0, 0, &orthrus_family, 0, ORTHRUS_CMD_TAMPER);
  if (!hdr) {
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  if (nla_put_string(skb, ORTHRUS_ATTR_REASON, reason) ||
      nla_put_u64_64bit(skb, ORTHRUS_ATTR_AGE_MS, age_ms, 0)) {
    genlmsg_cancel(skb, hdr);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }
  genlmsg_end(skb, hdr);

  ret = genlmsg_multicast(&orthrus_family, skb, 0, ORTHRUS_MCGRP_TAMPER,
                          GFP_KERNEL);

  if (ret == -ESRCH) {
    ret = 0;
  }
  return ret;
}

static int __init orthrus_init(void) {
  int ret;

  ret = genl_register_family(&orthrus_family);
  if (ret) {
    pr_err("[orthrus]: genl_register_family failed: %d\n", ret);
    return ret;
  }

  pr_info("[orthrus]: netlink family '%s' registered\n", ORTHRUS_GENL_NAME);
  return 0;
}

static void __exit orthrus_exit(void) {
  genl_unregister_family(&orthrus_family);
  pr_info("[orthrus]: unloaded\n");
}

module_init(orthrus_init);
module_exit(orthrus_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("0xvoidbyte");
MODULE_DESCRIPTION("Watchdog for the cerberus eBPF agent");
MODULE_VERSION("0.1");