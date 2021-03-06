/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / Accounting
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>


#include "hostapd.h"
#include "radius.h"
#include "radius_client.h"
#include "eloop.h"
#include "accounting.h"
#include "driver.h"


static struct radius_msg * accounting_msg(hostapd *hapd, struct sta_info *sta,
					  int status_type)
{
	struct radius_msg *msg;
	char buf[128];
	u8 *val;
	size_t len;

	msg = radius_msg_new(RADIUS_CODE_ACCOUNTING_REQUEST,
			     radius_client_get_id(hapd));
	if (msg == NULL) {
		printf("Could not create net RADIUS packet\n");
		return NULL;
	}

	radius_msg_make_authenticator(msg, (u8 *) sta, sizeof(sta));

	snprintf(buf, sizeof(buf), "%08X-%08X",
		 hapd->radius->acct_session_id_hi, sta->acct_session_id_lo);
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_ACCT_SESSION_ID,
				 buf, strlen(buf))) {
		printf("Could not add Acct-Session-Id\n");
		goto fail;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_ACCT_STATUS_TYPE,
				       status_type)) {
		printf("Could not add Acct-Status-Type\n");
		goto fail;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_ACCT_AUTHENTIC,
				       hapd->conf->ieee802_1x ?
				       RADIUS_ACCT_AUTHENTIC_RADIUS :
				       RADIUS_ACCT_AUTHENTIC_LOCAL)) {
		printf("Could not add Acct-Authentic\n");
		goto fail;
	}

	val = sta->identity;
	len = sta->identity_len;
	if (!val) {
		snprintf(buf, sizeof(buf), RADIUS_ADDR_FORMAT,
			 MAC2STR(sta->addr));
		val = buf;
		len = strlen(val);
	}

	if (!radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, val, len)) {
		printf("Could not add User-Name\n");
		goto fail;
	}

	if (!radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
				 (u8 *) &hapd->conf->own_ip_addr, 4)) {
		printf("Could not add NAS-IP-Address\n");
		goto fail;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT, sta->aid)) {
		printf("Could not add NAS-Port\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT ":%s",
		 MAC2STR(hapd->own_addr), hapd->conf->ssid);
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CALLED_STATION_ID,
				 buf, strlen(buf))) {
		printf("Could not add Called-Station-Id\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT,
		 MAC2STR(sta->addr));
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
				 buf, strlen(buf))) {
		printf("Could not add Calling-Station-Id\n");
		goto fail;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT_TYPE,
				       RADIUS_NAS_PORT_TYPE_IEEE_802_11)) {
		printf("Could not add NAS-Port-Type\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), "CONNECT 11Mbps 802.11b");
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CONNECT_INFO,
				 buf, strlen(buf))) {
		printf("Could not add Connect-Info\n");
		goto fail;
	}

	return msg;

 fail:
	radius_msg_free(msg);
	free(msg);
	return NULL;
}


static void accounting_interim_update(void *eloop_ctx, void *timeout_ctx)
{
	hostapd *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	accounting_sta_interim(hapd, sta);

	if (hapd->conf->radius_acct_interim_interval) {
		eloop_register_timeout(hapd->conf->
				       radius_acct_interim_interval, 0,
				       accounting_interim_update, hapd, sta);
	}
}


void accounting_sta_start(hostapd *hapd, struct sta_info *sta)
{
	struct radius_msg *msg;

	time(&sta->acct_session_start);

	if (!hapd->conf->acct_server)
		return;

	if (hapd->conf->radius_acct_interim_interval) {
		eloop_register_timeout(hapd->conf->
				       radius_acct_interim_interval, 0,
				       accounting_interim_update, hapd, sta);
	}

	msg = accounting_msg(hapd, sta, RADIUS_ACCT_STATUS_TYPE_START);
	if (msg)
		radius_client_send(hapd, msg, RADIUS_ACCT);
}


void accounting_sta_report(hostapd *hapd, struct sta_info *sta, int stop)
{
	struct radius_msg *msg;
	int cause = sta->acct_terminate_cause;
	struct hostap_sta_driver_data data;

	if (!hapd->conf->acct_server)
		return;

	msg = accounting_msg(hapd, sta,
			     stop ? RADIUS_ACCT_STATUS_TYPE_STOP :
			     RADIUS_ACCT_STATUS_TYPE_INTERIM_UPDATE);
	if (!msg) {
		printf("Could not create RADIUS Accounting message\n");
		return;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_ACCT_SESSION_TIME,
				       time(NULL) - sta->acct_session_start)) {
		printf("Could not add Acct-Session-Time\n");
		goto fail;
	}

	if (hostapd_read_sta_driver_data(hapd, &data, sta->addr) == 0) {
		if (!radius_msg_add_attr_int32(msg,
					       RADIUS_ATTR_ACCT_INPUT_PACKETS,
					       data.rx_packets)) {
			printf("Could not add Acct-Input-Packets\n");
			goto fail;
		}
		if (!radius_msg_add_attr_int32(msg,
					       RADIUS_ATTR_ACCT_OUTPUT_PACKETS,
					       data.tx_packets)) {
			printf("Could not add Acct-Output-Packets\n");
			goto fail;
		}
		if (!radius_msg_add_attr_int32(msg,
					       RADIUS_ATTR_ACCT_INPUT_OCTETS,
					       data.rx_bytes)) {
			printf("Could not add Acct-Input-Octets\n");
			goto fail;
		}
		if (!radius_msg_add_attr_int32(msg,
					       RADIUS_ATTR_ACCT_OUTPUT_OCTETS,
					       data.tx_bytes)) {
			printf("Could not add Acct-Output-Octets\n");
			goto fail;
		}
	}

	if (eloop_terminated())
		cause = RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_REBOOT;

	if (stop && cause &&
	    !radius_msg_add_attr_int32(msg, RADIUS_ATTR_ACCT_TERMINATE_CAUSE,
				       cause)) {
		printf("Could not add Acct-Terminate-Cause\n");
		goto fail;
	}

	radius_client_send(hapd, msg, RADIUS_ACCT);
	return;

 fail:
	radius_msg_free(msg);
	free(msg);
}


void accounting_sta_interim(hostapd *hapd, struct sta_info *sta)
{
	accounting_sta_report(hapd, sta, 0);
}


void accounting_sta_stop(hostapd *hapd, struct sta_info *sta)
{
	accounting_sta_report(hapd, sta, 1);
	eloop_cancel_timeout(accounting_interim_update, hapd, sta);
}


/* Process the RADIUS frames from Accounting Server */
static RadiusRxResult
accounting_receive(hostapd *hapd,
		   struct radius_msg *msg, struct radius_msg *req,
		   u8 *shared_secret, size_t shared_secret_len, void *data)
{
	if (msg->hdr->code != RADIUS_CODE_ACCOUNTING_RESPONSE) {
		printf("Unknown RADIUS message code\n");
		return RADIUS_RX_UNKNOWN;
	}

	if (radius_msg_verify_acct(msg, shared_secret, shared_secret_len, req))
	{
		printf("Incoming RADIUS packet did not have correct "
		       "Authenticator - dropped\n");
		return RADIUS_RX_UNKNOWN;
	}

	return RADIUS_RX_PROCESSED;
}


int accounting_init(hostapd *hapd)
{
	/* Acct-Session-Id should be unique over reboots. If reliable clock is
	 * not available, this could be replaced with reboot counter, etc. */
	hapd->radius->acct_session_id_hi = time(NULL);

	if (radius_client_register(hapd, RADIUS_ACCT, accounting_receive,
				   NULL))
		return -1;

	return 0;
}


void accounting_deinit(hostapd *hapd)
{
}
