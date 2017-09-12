/* MGCP Private Data */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <string.h>
#include <inttypes.h>
#include <osmocom/core/select.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/core/linuxlist.h>

#define CI_UNUSED 0

#define CONN_ID_BTS 0
#define CONN_ID_NET 1

enum mgcp_trunk_type {
	MGCP_TRUNK_VIRTUAL,
	MGCP_TRUNK_E1,
};

struct mgcp_rtp_stream_state {
	uint32_t ssrc;
	uint16_t last_seq;
	uint32_t last_timestamp;
	uint32_t err_ts_counter;
	int32_t last_tsdelta;
	uint32_t last_arrival_time;
};

struct mgcp_rtp_state {
	int initialized;
	int patch_ssrc;

	uint32_t orig_ssrc;

	int seq_offset;

	int32_t  timestamp_offset;
	uint32_t packet_duration;

	struct mgcp_rtp_stream_state in_stream;
	struct mgcp_rtp_stream_state out_stream;

	/* jitter and packet loss calculation */
	int stats_initialized;
	uint16_t stats_base_seq;
	uint16_t stats_max_seq;
	uint32_t stats_ssrc;
	uint32_t stats_jitter;
	int32_t stats_transit;
	int stats_cycles;
	bool patched_first_rtp_payload; /* FIXME: drop this, see OS#2459 */
};

struct mgcp_rtp_codec {
	uint32_t rate;
	int channels;
	uint32_t frame_duration_num;
	uint32_t frame_duration_den;

	int payload_type;
	char *audio_name;
	char *subtype_name;
};

struct mgcp_rtp_end {
	/* statistics */
	unsigned int packets_rx;
	unsigned int octets_rx;
	unsigned int packets_tx;
	unsigned int octets_tx;
	unsigned int dropped_packets;
	struct in_addr addr;

	/* in network byte order */
	int rtp_port, rtcp_port;

	/* audio codec information */
	struct mgcp_rtp_codec codec;
	struct mgcp_rtp_codec alt_codec; /* TODO/XXX: make it generic */

	/* per endpoint data */
	int  frames_per_packet;
	uint32_t packet_duration_ms;
	char *fmtp_extra;
	int output_enabled;
	int force_output_ptime;

	/* RTP patching */
	int force_constant_ssrc; /* -1: always, 0: don't, 1: once */
	int force_aligned_timing;
	void *rtp_process_data;

	/* Each end has a separete socket for RTP and RTCP */
	struct osmo_fd rtp;
	struct osmo_fd rtcp;

	int local_port;
};

struct mgcp_rtp_tap {
	int enabled;
	struct sockaddr_in forward;
};

struct mgcp_lco {
	char *string;
	char *codec;
	int pkt_period_min; /* time in ms */
	int pkt_period_max; /* time in ms */
};

enum mgcp_type {
	MGCP_RTP_DEFAULT	= 0,
	MGCP_OSMUX_BSC,
	MGCP_OSMUX_BSC_NAT,
};

#include <osmocom/mgcp/osmux.h>
struct mgcp_conn;

/* MGCP connection (RTP) */
struct mgcp_conn_rtp {

	/* Backpointer to conn struct */
	struct mgcp_conn *conn;

	/* Port status */
	struct mgcp_rtp_end end;

	/* Sequence bits */
	struct mgcp_rtp_state state;

	/* taps for the rtp connection */
	struct mgcp_rtp_tap tap_in;
	struct mgcp_rtp_tap tap_out;

	/* Osmux states (optional) */
	struct {
		/* Osmux state: disabled, activating, active */
		enum osmux_state state;
		/* Allocated Osmux circuit ID for this endpoint */
		int allocated_cid;
		/* Used Osmux circuit ID for this endpoint */
		uint8_t cid;
		/* handle to batch messages */
		struct osmux_in_handle *in;
		/* handle to unbatch messages */
		struct osmux_out_handle out;
		/* statistics */
		struct {
			uint32_t chunks;
			uint32_t octets;
		} stats;
	} osmux;
};

/*! Connection type, specifies which member of the union "u" in mgcp_conn
 *  contains a useful connection description (currently only RTP) */
enum mgcp_conn_type {
	MGCP_CONN_TYPE_RTP,
};

/*! MGCP connection (untyped) */
struct mgcp_conn {
	/*!< list head */
	struct llist_head entry;

	/*!< type of the connection (union) */
	enum mgcp_conn_type type;

	/*!< mode of the connection */
	int mode;

	/*!< copy of the mode to restore the original setting (VTY) */
	int mode_orig;

	/*!< connection id to identify the conntion */
	uint32_t id;

	/*!< human readable name (vty, logging) */
	char name[256];

	/*!< union with connection description */
	union {
		struct mgcp_conn_rtp rtp;
	} u;
};


#include <osmocom/mgcp/mgcp_conn.h>

struct mgcp_endpoint {
	char *callid;
	struct mgcp_lco local_options;

	struct llist_head conns;

	/* backpointer */
	struct mgcp_config *cfg;
	struct mgcp_trunk_config *tcfg;

	enum mgcp_type type;

	/* fields for re-transmission */
	char *last_trans;
	char *last_response;
};

#define ENDPOINT_NUMBER(endp) abs((int)(endp - endp->tcfg->endpoints))

/**
 * Internal structure while parsing a request
 */
struct mgcp_parse_data {
	struct mgcp_config *cfg;
	struct mgcp_endpoint *endp;
	char *trans;
	char *save;
	int found;
};

int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct sockaddr_in *addr,
	      char *buf, int rc, struct mgcp_conn_rtp *conn_src,
	      struct mgcp_conn_rtp *conn_dst);
int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn);
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn);
void mgcp_free_rtp_port(struct mgcp_rtp_end *end);

/* For transcoding we need to manage an in and an output that are connected */
static inline int endp_back_channel(int endpoint)
{
	return endpoint + 60;
}

struct mgcp_trunk_config *mgcp_trunk_alloc(struct mgcp_config *cfg, int index);
struct mgcp_trunk_config *mgcp_trunk_num(struct mgcp_config *cfg, int index);

void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp);
uint32_t mgcp_rtp_packet_duration(struct mgcp_endpoint *endp,
				  struct mgcp_rtp_end *rtp);

/* payload processing default functions */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp, struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size);

int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_end *dst_end,
				      struct mgcp_rtp_end *src_end);

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char**audio_name,
					  const char**fmtp_extra,
					  struct mgcp_conn_rtp *conn);

/* internal RTP Annex A counting */
void mgcp_rtp_annex_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			const uint16_t seq, const int32_t transit,
			const uint32_t ssrc);

int mgcp_set_ip_tos(int fd, int tos);

enum {
	MGCP_DEST_NET = 0,
	MGCP_DEST_BTS,
};


#define MGCP_DUMMY_LOAD 0x23


/**
 * SDP related information
 */
/* Assume audio frame length of 20ms */
#define DEFAULT_RTP_AUDIO_FRAME_DUR_NUM 20
#define DEFAULT_RTP_AUDIO_FRAME_DUR_DEN 1000
#define DEFAULT_RTP_AUDIO_PACKET_DURATION_MS 20
#define DEFAULT_RTP_AUDIO_DEFAULT_RATE  8000
#define DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS 1

#define PTYPE_UNDEFINED (-1)
int mgcp_parse_sdp_data(struct mgcp_endpoint *endp, struct mgcp_rtp_end *rtp, struct mgcp_parse_data *p);
int mgcp_set_audio_info(void *ctx, struct mgcp_rtp_codec *codec,
			int payload_type, const char *audio_name);

/*! \brief get the ip-address where the mgw application is bound on
 *  \param[in] endp mgcp endpoint, that holds a copy of the VTY parameters
 *  \returns pointer to a string that contains the source ip-address */
static inline const char *mgcp_net_src_addr(struct mgcp_endpoint *endp)
{
	if (endp->cfg->net_ports.bind_addr)
		return endp->cfg->net_ports.bind_addr;
	return endp->cfg->source_addr;
}
