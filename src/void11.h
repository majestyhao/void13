/*
 * .vantronix | void11 (802.11b penetration testing utility)
 *
 * last change: 03/24/2003
 *
 * Copyright (c) 2002-2003, Reyk Floeter <reyk@vantronix.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

/* based on hostapd by Jouni Malinen <jkmaline@cc.hut.fi> */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <asm/errno.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>
#include <linux/wireless.h>

#if WIRELESS_EXT < 9
#error "Linux Wireless Extensions version 9 or newer required"
#endif

#include "drivers/driver_hostap.h"
#include "ap/ieee802_11.h"

#ifndef VOID11_HEADER
#define VOID11_HEADER

#ifndef VOID11_VERSION
#define VOID11_VERSION "0.2.0"
#endif

#define VOID11_COPYRIGHT "Copyright (c) 2002-2004 Reyk Floeter <reyk@vantronix.net>"

/* void11 default defines */
#define VOID11_DEBUG 1
#define VOID11_DEFAULT_DELAY 10000 /* usleep(x) */
#define VOID11_TYPE_NULL 0 
#define VOID11_TYPE_DEAUTH 1
#define VOID11_TYPE_AUTH 2
#define VOID11_TYPE_ASSOC 3
#define VOID11_DEFAULT_TYPE VOID11_TYPE_DEAUTH /* deauth */
#define VOID11_MAX_CLIENTS 23
#define VOID11_DEFAULT_TIMEOUT 10 /* seconds */
#define VOID11_MATCH_WHITE 0
#define VOID11_MATCH_BLACK 1
#define VOID11_MATCH_DEFAULT VOID11_MATCH_WHITE
#define VOID11_DEFAULT_DEVICE "wlan0"

#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN 32
#endif

#if VOID11_DEBUG 
#define DPUT(s) fprintf(stderr, s); fflush(stderr);
#define DPRINT(s, args...) fprintf(stderr, s, args); fflush(stderr);
#if VOID11_DEBUG > 1
#define WHILE(x) for(;x;fprintf(stderr, "%s:%d:%s\n", __FUNCTION__, __LINE__, #x), fflush(stderr))
#else
#define WHILE(x) while(x)
#endif
#else
#define DPUT(s)
#define DPRINT(s, args...)
#define WHILE(x) while(x)
#endif

/* structures */
struct void11_ap {
  u8 bssid[6];
  struct ieee802_11_elems elems;
  time_t timestamp;
  struct void11_ap *next;
};

/* functions */
int macstr2addr(char *macstr, u8 *addr);

int void11_deauth_all_stas(hostapd *void11, u8 *station, u8 *bssid);
int void11_assoc_req(hostapd *void11, u8 *bssid);
int void11_auth_req(hostapd *void11, u8 *bssid);

struct void11_ap *void11_read(hostapd *void11);//
int void11_init(hostapd *void11, char *iface);//
int void11_exit(hostapd *void11);

#endif /* VOID11_HEADER */
