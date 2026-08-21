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

#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "orthrus.h"

#define ORTHRUS_CHECK_INTERVAL_MS 5000
#define ORTHRUS_STALE_THRESHOLD_MS 15000

static DEFINE_SPINLOCK(state_lock);
static u64 last_heartbeat_ns;
static bool heartbeat_seen;
static u32 agent_pid;
static bool tamper_fired; /* latch: fire heartbeat-stale once per episode */

static u32 n_progs_max; /* highest count seen = established healthy level */
static bool
    progs_dropped; /* latch: fire the drop warning once until recovery */

static struct hrtimer orthrus_timer;

static int orthrus_send_event(u8 severity, const char *reason, u64 age_ms);

static int orthrus_cmd_heartbeat(struct sk_buff *skb, struct genl_info *info) {
  u32 sender_pid = task_tgid_nr(current);
  u32 progs = 0;
  bool warn_drop = false, crit_zero = false;
  u32 dropped_to = 0, expected = 0;

  if (info->attrs[ORTHRUS_ATTR_N_PROGS])
    progs = nla_get_u32(info->attrs[ORTHRUS_ATTR_N_PROGS]);

  spin_lock_bh(&state_lock);

  if (!heartbeat_seen) {
    agent_pid = sender_pid;
  } else if (sender_pid != agent_pid) {
    // Someone other than the registered agent is trying to heartbeat.

    spin_unlock_bh(&state_lock);
    pr_warn(
        "[orthrus]: heartbeat from pid %u, expected agent pid %u - ignored\n",
        sender_pid, agent_pid);
    return 0;
  }

  last_heartbeat_ns = ktime_get_ns();
  heartbeat_seen = true;
  tamper_fired = false;

  if (progs > n_progs_max)
    n_progs_max = progs;

  if (n_progs_max > 0) {
    if (progs == 0 && !progs_dropped) {
      // alive but blind
      crit_zero = true;
      progs_dropped = true;
    } else if (progs < n_progs_max && progs > 0 && !progs_dropped) {
      // degraded
      warn_drop = true;
      progs_dropped = true;
      dropped_to = progs;
      expected = n_progs_max;
    } else if (progs >= n_progs_max) {
      // recovered to full strength
      progs_dropped = false;
    }
  }

  spin_unlock_bh(&state_lock);

  if (crit_zero) {
    orthrus_send_event(ORTHRUS_SEV_CRITICAL, "bpf-progs-zero-while-alive", 0);
  } else if (warn_drop) {
    char reason[64];
    scnprintf(reason, sizeof(reason), "bpf-progs-dropped-%u-of-%u", dropped_to,
              expected);
    orthrus_send_event(ORTHRUS_SEV_MEDIUM, reason, 0);
  }

  return 0;
}

static const struct genl_ops orthrus_ops[] = {{.cmd = ORTHRUS_CMD_HEARTBEAT,
                                               .doit = orthrus_cmd_heartbeat,
                                               .flags = GENL_ADMIN_PERM}};

static const struct nla_policy orthrus_policy[ORTHRUS_ATTR_MAX + 1] = {
    [ORTHRUS_ATTR_PID] = {.type = NLA_U32},
    [ORTHRUS_ATTR_REASON] = {.type = NLA_NUL_STRING, .len = 64},
    [ORTHRUS_ATTR_AGE_MS] = {.type = NLA_U64},
    [ORTHRUS_ATTR_N_PROGS] = {.type = NLA_U32},
    [ORTHRUS_ATTR_SEVERITY] = {.type = NLA_U8},
};

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

static int orthrus_send_event(u8 severity, const char *reason, u64 age_ms) {
  struct sk_buff *skb;
  void *hdr;
  int ret;

  skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }
  hdr = genlmsg_put(skb, 0, 0, &orthrus_family, 0, ORTHRUS_CMD_EVENT);
  if (!hdr) {
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  if (nla_put_u8(skb, ORTHRUS_ATTR_SEVERITY, severity) ||
      nla_put_string(skb, ORTHRUS_ATTR_REASON, reason) ||
      nla_put_u64_64bit(skb, ORTHRUS_ATTR_AGE_MS, age_ms, 0)) {
    genlmsg_cancel(skb, hdr);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, hdr);

  ret = genlmsg_multicast(&orthrus_family, skb, 0, ORTHRUS_MCGRP_TAMPER,
                          GFP_ATOMIC);

  if (ret == -ESRCH) {
    ret = 0;
  }
  return ret;
}

static enum hrtimer_restart orthrus_timer_fn(struct hrtimer *t) {
  u64 now = ktime_get_ns();
  bool fire = false;
  u64 age_ms = 0;

  spin_lock(&state_lock);
  if (heartbeat_seen && !tamper_fired) {
    u64 age_ns = (now > last_heartbeat_ns) ? now - last_heartbeat_ns : 0;
    age_ms = age_ns / 1000000ULL;
    if (age_ms >= ORTHRUS_STALE_THRESHOLD_MS) {
      fire = true;
      tamper_fired = true;
    }
  }
  spin_unlock(&state_lock);

  if (fire)
    orthrus_send_event(ORTHRUS_SEV_HIGH, "heartbeat-stale", age_ms);

  hrtimer_forward_now(t, ms_to_ktime(ORTHRUS_CHECK_INTERVAL_MS));
  return HRTIMER_RESTART;
}

static int __init orthrus_init(void) {
  int ret;

  ret = genl_register_family(&orthrus_family);
  if (ret) {
    pr_err("[orthrus]: genl_register_family failed: %d\n", ret);
    return ret;
  }

  hrtimer_setup(&orthrus_timer, orthrus_timer_fn, CLOCK_MONOTONIC,
                HRTIMER_MODE_REL);
  hrtimer_start(&orthrus_timer, ms_to_ktime(ORTHRUS_CHECK_INTERVAL_MS),
                HRTIMER_MODE_REL);

  pr_info("[orthrus]: loaded; family '%s' registered, watchdog armed (%d ms "
          "check, %d ms threshold)\n",
          ORTHRUS_GENL_NAME, ORTHRUS_CHECK_INTERVAL_MS,
          ORTHRUS_STALE_THRESHOLD_MS);

  return 0;
}

static void __exit orthrus_exit(void) {
  orthrus_send_event(ORTHRUS_SEV_HIGH, "watchdog-unloading", 0);
  hrtimer_cancel(&orthrus_timer);
  genl_unregister_family(&orthrus_family);
  pr_info("[orthrus]: unloaded\n");
}

module_init(orthrus_init);
module_exit(orthrus_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("0xvoidbyte");
MODULE_DESCRIPTION("Watchdog for the cerberus eBPF agent");
MODULE_VERSION("0.3");