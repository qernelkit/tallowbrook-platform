/* On-device file paths (the gateway root filesystem is read-only except /var). */
#ifndef GW_PATHS_H
#define GW_PATHS_H

#define GW_TRUST_ANCHOR_PATH "/etc/tallowbrook/pki/ca/root-ec-2024.crt"
#define GW_DEVICE_KEY_PATH "/var/lib/gwfw/device.key"
#define GW_STATE_DIR "/var/lib/gwfw"
#define GW_UPDATE_SPOOL "/var/spool/gwfw/update.img"

#endif
