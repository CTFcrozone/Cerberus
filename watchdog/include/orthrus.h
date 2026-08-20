#ifndef _ORTHRUS_H
#define _ORTHRUS_H

#define ORTHRUS_GENL_NAME "orthrus"
#define ORTHRUS_GENL_VERSION 1

enum orthrus_attr {
  ORTHRUS_ATTR_UNSPEC,
  ORTHRUS_ATTR_PID,    // agent pid
  ORTHRUS_ATTR_REASON, // why tamper fired (kernel -> user)
  ORTHRUS_ATTR_AGE_MS, // how stale the heartbeat was
  __ORTHRUS_ATTR_MAX
};

#define ORTHRUS_ATTR_MAX (__ORTHRUS_ATTR_MAX - 1)

enum orthrus_cmd {
  ORTHRUS_CMD_UNSPEC,
  ORTHRUS_CMD_HEARTBEAT,
  ORTHRUS_CMD_TAMPER,
  __ORTHRUS_CMD_MAX
};

#define ORTHRUS_CMD_MAX (__ORTHRUS_CMD_MAX - 1)

enum orthrus_mcgrp {
  ORTHRUS_MCGRP_TAMPER = 0,
};

#endif