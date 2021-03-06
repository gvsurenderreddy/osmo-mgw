#pragma once


#include <osmocom/netif/osmux.h>
struct mgcp_conn_rtp;

#define OSMUX_PORT	1984

enum {
	OSMUX_ROLE_BSC = 0,
	OSMUX_ROLE_BSC_NAT,
};

int osmux_init(int role, struct mgcp_config *cfg);
int osmux_enable_conn(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn,
		      struct in_addr *addr, uint16_t port);
void osmux_disable_conn(struct mgcp_conn_rtp *conn);
void osmux_allocate_cid(struct mgcp_conn_rtp *conn);
void osmux_release_cid(struct mgcp_conn_rtp *conn);
int osmux_xfrm_to_osmux(char *buf, int buf_len, struct mgcp_conn_rtp *conn);
int osmux_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn);
int osmux_get_cid(void);
void osmux_put_cid(uint8_t osmux_cid);
int osmux_used_cid(void);

enum osmux_state {
	OSMUX_STATE_DISABLED = 0,
	OSMUX_STATE_NEGOTIATING,
	OSMUX_STATE_ACTIVATING,
	OSMUX_STATE_ENABLED,
};

enum osmux_usage {
	OSMUX_USAGE_OFF = 0,
	OSMUX_USAGE_ON = 1,
	OSMUX_USAGE_ONLY = 2,
};

