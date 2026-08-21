pub const ORTHRUS_FAMILY: &str = "orthrus";
pub const ORTHRUS_MCGRP_TAMPER: &str = "tamper";
pub const ORTHRUS_GENL_NAME: &str = "orthrus";
pub const ORTHRUS_GENL_VERSION: u8 = 1;
// commands (enum orthrus_cmd)
pub const ORTHRUS_CMD_HEARTBEAT: u8 = 1;
pub const ORTHRUS_CMD_EVENT: u8 = 2;

// attributes (enum orthrus_attr)
pub const ORTHRUS_ATTR_PID: u16 = 1;
pub const ORTHRUS_ATTR_REASON: u16 = 2;
pub const ORTHRUS_ATTR_AGE_MS: u16 = 3;
pub const ORTHRUS_ATTR_N_PROGS: u16 = 4;
pub const ORTHRUS_ATTR_SEVERITY: u16 = 5;
