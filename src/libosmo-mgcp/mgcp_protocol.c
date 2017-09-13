/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/mgcp_msg.h>

struct mgcp_request {
	char *name;
	struct msgb *(*handle_request) (struct mgcp_parse_data * data);
	char *debug_name;
};

#define MGCP_REQUEST(NAME, REQ, DEBUG_NAME) \
	{ .name = NAME, .handle_request = REQ, .debug_name = DEBUG_NAME },

static struct msgb *handle_audit_endpoint(struct mgcp_parse_data *data);
static struct msgb *handle_create_con(struct mgcp_parse_data *data);
static struct msgb *handle_delete_con(struct mgcp_parse_data *data);
static struct msgb *handle_modify_con(struct mgcp_parse_data *data);
static struct msgb *handle_rsip(struct mgcp_parse_data *data);
static struct msgb *handle_noti_req(struct mgcp_parse_data *data);

/* Initalize transcoder */
static int setup_rtp_processing(struct mgcp_endpoint *endp,
				struct mgcp_conn_rtp *conn)
{
	struct mgcp_config *cfg = endp->cfg;
	struct mgcp_conn_rtp *conn_src = NULL;
	struct mgcp_conn_rtp *conn_dst = conn;
	struct mgcp_conn *_conn;

	if (endp->type != MGCP_RTP_DEFAULT) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "endpoint:%x RTP-setup: Endpoint is not configured as RTP default, stopping here!\n",
		     ENDPOINT_NUMBER(endp));
		return 0;
	}

	if (conn->conn->mode == MGCP_CONN_LOOPBACK) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "endpoint:%x RTP-setup: Endpoint is in loopback mode, stopping here!\n",
		     ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* Find the "sister" connection */
	llist_for_each_entry(_conn, &endp->conns, entry) {
		if (_conn->id != conn->conn->id) {
			conn_src = &_conn->u.rtp;
			break;
		}
	}

	return cfg->setup_rtp_processing_cb(endp, &conn_dst->end,
					    &conn_src->end);
}

/* array of function pointers for handling various
 * messages. In the future this might be binary sorted
 * for performance reasons. */
static const struct mgcp_request mgcp_requests[] = {
	MGCP_REQUEST("AUEP", handle_audit_endpoint, "AuditEndpoint")
	    MGCP_REQUEST("CRCX", handle_create_con, "CreateConnection")
	    MGCP_REQUEST("DLCX", handle_delete_con, "DeleteConnection")
	    MGCP_REQUEST("MDCX", handle_modify_con, "ModifiyConnection")
	    MGCP_REQUEST("RQNT", handle_noti_req, "NotificationRequest")

	    /* SPEC extension */
	    MGCP_REQUEST("RSIP", handle_rsip, "ReSetInProgress")
};

/* Helper function to allocate some memory for responses and retransmissions */
static struct msgb *mgcp_msgb_alloc(void)
{
	struct msgb *msg;
	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	if (!msg)
		LOGP(DLMGCP, LOGL_ERROR, "Failed to msgb for MGCP data.\n");

	return msg;
}

/* Helper function for do_retransmission() and create_resp() */
static struct msgb *do_retransmission(const struct mgcp_endpoint *endp)
{
	struct msgb *msg = mgcp_msgb_alloc();
	if (!msg)
		return NULL;

	msg->l2h = msgb_put(msg, strlen(endp->last_response));
	memcpy(msg->l2h, endp->last_response, msgb_l2len(msg));
	mgcp_disp_msg(msg->l2h, msgb_l2len(msg), "Retransmitted response");
	return msg;
}

static struct msgb *create_resp(struct mgcp_endpoint *endp, int code,
				const char *txt, const char *msg,
				const char *trans, const char *param,
				const char *sdp)
{
	int len;
	struct msgb *res;

	res = mgcp_msgb_alloc();
	if (!res)
		return NULL;

	len = snprintf((char *)res->data, 2048, "%d %s%s%s\r\n%s",
		       code, trans, txt, param ? param : "", sdp ? sdp : "");
	if (len < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to sprintf MGCP response.\n");
		msgb_free(res);
		return NULL;
	}

	res->l2h = msgb_put(res, len);
	LOGP(DLMGCP, LOGL_DEBUG, "Generated response: code=%d\n", code);
	mgcp_disp_msg(res->l2h, msgb_l2len(res), "Generated response");

	/*
	 * Remember the last transmission per endpoint.
	 */
	if (endp) {
		struct mgcp_trunk_config *tcfg = endp->tcfg;
		talloc_free(endp->last_response);
		talloc_free(endp->last_trans);
		endp->last_trans = talloc_strdup(tcfg->endpoints, trans);
		endp->last_response = talloc_strndup(tcfg->endpoints,
						     (const char *)res->l2h,
						     msgb_l2len(res));
	}

	return res;
}

static struct msgb *create_ok_resp_with_param(struct mgcp_endpoint *endp,
					      int code, const char *msg,
					      const char *trans,
					      const char *param)
{
	return create_resp(endp, code, " OK", msg, trans, param, NULL);
}

static struct msgb *create_ok_response(struct mgcp_endpoint *endp,
				       int code, const char *msg,
				       const char *trans)
{
	return create_ok_resp_with_param(endp, code, msg, trans, NULL);
}

static struct msgb *create_err_response(struct mgcp_endpoint *endp,
					int code, const char *msg,
					const char *trans)
{
	return create_resp(endp, code, " FAIL", msg, trans, NULL, NULL);
}

static int write_response_sdp(struct mgcp_endpoint *endp,
			      struct mgcp_conn_rtp *conn,
			      char *sdp_record, size_t size, const char *addr)
{
	const char *fmtp_extra;
	const char *audio_name;
	int payload_type;
	int len;
	int nchars;

	if (!conn)
		return -1;

	endp->cfg->get_net_downlink_format_cb(endp, &payload_type,
					      &audio_name, &fmtp_extra, conn);

	len = snprintf(sdp_record, size,
		       "v=0\r\n"
		       "o=- %u 23 IN IP4 %s\r\n"
		       "s=-\r\n"
		       "c=IN IP4 %s\r\n"
		       "t=0 0\r\n", conn->conn->id, addr, addr);

	if (len < 0 || len >= size)
		goto buffer_too_small;

	if (payload_type >= 0) {
		nchars = snprintf(sdp_record + len, size - len,
				  "m=audio %d RTP/AVP %d\r\n",
				  conn->end.local_port, payload_type);
		if (nchars < 0 || nchars >= size - len)
			goto buffer_too_small;

		len += nchars;

		if (audio_name && endp->tcfg->audio_send_name) {
			nchars = snprintf(sdp_record + len, size - len,
					  "a=rtpmap:%d %s\r\n",
					  payload_type, audio_name);

			if (nchars < 0 || nchars >= size - len)
				goto buffer_too_small;

			len += nchars;
		}

		if (fmtp_extra) {
			nchars = snprintf(sdp_record + len, size - len,
					  "%s\r\n", fmtp_extra);

			if (nchars < 0 || nchars >= size - len)
				goto buffer_too_small;

			len += nchars;
		}
	}
	if (conn->end.packet_duration_ms > 0 && endp->tcfg->audio_send_ptime) {
		nchars = snprintf(sdp_record + len, size - len,
				  "a=ptime:%u\r\n",
				  conn->end.packet_duration_ms);
		if (nchars < 0 || nchars >= size - len)
			goto buffer_too_small;

		len += nchars;
	}

	return len;

buffer_too_small:
	LOGP(DLMGCP, LOGL_ERROR, "SDP buffer too small: %zu (needed %d)\n",
	     size, len);
	return -1;
}

/* Format MGCP response string (with SDP attached) */
static struct msgb *create_response_with_sdp(struct mgcp_endpoint *endp,
					     struct mgcp_conn_rtp *conn,
					     const char *msg,
					     const char *trans_id)
{
	const char *addr = endp->cfg->local_ip;
	char sdp_record[4096];
	int len;
	int nchars;
	char osmux_extension[strlen("\nX-Osmux: 255") + 1];

	if (!addr)
		addr = mgcp_net_src_addr(endp);

	if (conn->osmux.state == OSMUX_STATE_NEGOTIATING) {
		sprintf(osmux_extension, "\nX-Osmux: %u", conn->osmux.cid);
		conn->osmux.state = OSMUX_STATE_ACTIVATING;
	} else {
		osmux_extension[0] = '\0';
	}

	len = snprintf(sdp_record, sizeof(sdp_record),
		       "I: %u%s\n\n", conn->conn->id, osmux_extension);
	if (len < 0)
		return NULL;

	nchars = write_response_sdp(endp, conn, sdp_record + len,
				    sizeof(sdp_record) - len - 1, addr);
	if (nchars < 0)
		return NULL;

	len += nchars;

	sdp_record[sizeof(sdp_record) - 1] = '\0';

	return create_resp(endp, 200, " OK", msg, trans_id, NULL, sdp_record);
}

/* Send out dummy packet to keep the connection open, if the connection is an
 * osmux connection, send the dummy packet via OSMUX */
static void send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	if (conn->osmux.state != OSMUX_STATE_DISABLED)
		osmux_send_dummy(endp, conn);
	else
		mgcp_send_dummy(endp, conn);
}

/* handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id) */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_parse_data pdata;
	int i, code, handled = 0;
	struct msgb *resp = NULL;
	char *data;

	if (msgb_l2len(msg) < 4) {
		LOGP(DLMGCP, LOGL_ERROR, "msg too short: %d\n", msg->len);
		return NULL;
	}

	if (mgcp_msg_terminate_nul(msg))
		return NULL;

	mgcp_disp_msg(msg->l2h, msgb_l2len(msg), "Received message");

	/* attempt to treat it as a response */
	if (sscanf((const char *)&msg->l2h[0], "%3d %*s", &code) == 1) {
		LOGP(DLMGCP, LOGL_DEBUG, "Response: Code: %d\n", code);
		return NULL;
	}

	msg->l3h = &msg->l2h[4];

	/*
	 * Check for a duplicate message and respond.
	 */
	memset(&pdata, 0, sizeof(pdata));
	pdata.cfg = cfg;
	data = mgcp_strline((char *)msg->l3h, &pdata.save);
	pdata.found = mgcp_parse_header(&pdata, data);
	if (pdata.endp && pdata.trans
	    && pdata.endp->last_trans
	    && strcmp(pdata.endp->last_trans, pdata.trans) == 0) {
		return do_retransmission(pdata.endp);
	}

	for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i) {
		if (strncmp
		    (mgcp_requests[i].name, (const char *)&msg->l2h[0],
		     4) == 0) {
			handled = 1;
			resp = mgcp_requests[i].handle_request(&pdata);
			break;
		}
	}

	if (!handled)
		LOGP(DLMGCP, LOGL_NOTICE, "MSG with type: '%.4s' not handled\n",
		     &msg->l2h[0]);

	return resp;
}

/* AUEP command handler, processes the received command */
static struct msgb *handle_audit_endpoint(struct mgcp_parse_data *p)
{
	LOGP(DLMGCP, LOGL_DEBUG, "AUEP: auditing endpoint ...\n");

	if (p->found != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "AUEP: failed to find the endpoint.\n");
		return create_err_response(NULL, 500, "AUEP", p->trans);
	} else
		return create_ok_response(p->endp, 200, "AUEP", p->trans);
}

/* Try to find a free port by attemting to bind on it. Also handle the
 * counter that points on the next free port. Since we have a pointer
 * to the next free port, binding should work on the first attemt,
 * neverless, try at least the next 200 ports before giving up */
static int allocate_port(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	int i;
	struct mgcp_rtp_end *end;
	struct mgcp_port_range *range;

	OSMO_ASSERT(conn);
	end = &conn->end;
	OSMO_ASSERT(end);

	range = &endp->cfg->net_ports;

	/* attempt to find a port */
	for (i = 0; i < 200; ++i) {
		int rc;

		if (range->last_port >= range->range_end)
			range->last_port = range->range_start;

		rc = mgcp_bind_net_rtp_port(endp, range->last_port, conn);

		range->last_port += 2;
		if (rc == 0) {
			return 0;
		}

	}

	LOGP(DLMGCP, LOGL_ERROR,
	     "Allocating a RTP/RTCP port failed 200 times 0x%x.\n",
	     ENDPOINT_NUMBER(endp));
	return -1;
}

/* Set the LCO from a string (see RFC 3435).
 * The string is stored in the 'string' field. A NULL string is handled excatlyy
 * like an empty string, the 'string' field is never NULL after this function
 * has been called. */
static void set_local_cx_options(void *ctx, struct mgcp_lco *lco,
				 const char *options)
{
	char *p_opt, *a_opt;
	char codec[9];

	talloc_free(lco->string);
	talloc_free(lco->codec);
	lco->codec = NULL;
	lco->pkt_period_min = lco->pkt_period_max = 0;
	lco->string = talloc_strdup(ctx, options ? options : "");

	p_opt = strstr(lco->string, "p:");
	if (p_opt && sscanf(p_opt, "p:%d-%d",
			    &lco->pkt_period_min, &lco->pkt_period_max) == 1)
		lco->pkt_period_max = lco->pkt_period_min;

	a_opt = strstr(lco->string, "a:");
	if (a_opt && sscanf(a_opt, "a:%8[^,]", codec) == 1)
		lco->codec = talloc_strdup(ctx, codec);

	LOGP(DLMGCP, LOGL_DEBUG,
	     "local CX options: lco->pkt_period_max: %i, lco->codec: %s\n",
	     lco->pkt_period_max, lco->codec);
}

void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp)
{
	struct mgcp_trunk_config *tcfg = endp->tcfg;

	int patch_ssrc = expect_ssrc_change && tcfg->force_constant_ssrc;

	rtp->force_aligned_timing = tcfg->force_aligned_timing;
	rtp->force_constant_ssrc = patch_ssrc ? 1 : 0;

	LOGP(DLMGCP, LOGL_DEBUG,
	     "Configuring RTP endpoint: local port %d%s%s\n",
	     ntohs(rtp->rtp_port),
	     rtp->force_aligned_timing ? ", force constant timing" : "",
	     rtp->force_constant_ssrc ? ", force constant ssrc" : "");
}

uint32_t mgcp_rtp_packet_duration(struct mgcp_endpoint *endp,
				  struct mgcp_rtp_end *rtp)
{
	int f = 0;

	/* Get the number of frames per channel and packet */
	if (rtp->frames_per_packet)
		f = rtp->frames_per_packet;
	else if (rtp->packet_duration_ms && rtp->codec.frame_duration_num) {
		int den = 1000 * rtp->codec.frame_duration_num;
		f = (rtp->packet_duration_ms * rtp->codec.frame_duration_den +
		     den / 2)
		    / den;
	}

	return rtp->codec.rate * f * rtp->codec.frame_duration_num /
	    rtp->codec.frame_duration_den;
}

static int mgcp_osmux_setup(struct mgcp_endpoint *endp, const char *line)
{
	if (!endp->cfg->osmux_init) {
		if (osmux_init(OSMUX_ROLE_BSC, endp->cfg) < 0) {
			LOGP(DLMGCP, LOGL_ERROR, "Cannot init OSMUX\n");
			return -1;
		}
		LOGP(DLMGCP, LOGL_NOTICE, "OSMUX socket has been set up\n");
	}

	return mgcp_parse_osmux_cid(line);
}

/* CRCX command handler, processes the received command */
static struct msgb *handle_create_con(struct mgcp_parse_data *p)
{
	struct mgcp_trunk_config *tcfg;
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 400;

	const char *local_options = NULL;
	const char *callid = NULL;
	const char *ci = NULL;
	const char *mode = NULL;
	char *line;
	int have_sdp = 0, osmux_cid = -1;
	struct mgcp_conn_rtp *conn = NULL;
	uint32_t conn_id;
	char conn_name[512];

	LOGP(DLMGCP, LOGL_DEBUG, "CRCX: creating new connection ...\n");

	if (p->found != 0)
		return create_err_response(NULL, 510, "CRCX", p->trans);

	/* parse CallID C: and LocalParameters L: */
	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

		switch (line[0]) {
		case 'L':
			local_options = (const char *)line + 3;
			break;
		case 'C':
			callid = (const char *)line + 3;
			break;
		case 'I':
			ci = (const char *)line + 3;
			break;
		case 'M':
			mode = (const char *)line + 3;
			break;
		case 'X':
			/* If osmoux is disabled, just skip setting it up */
			if (!p->endp->cfg->osmux)
				break;
			if (strncmp("Osmux: ", line + 2, strlen("Osmux: ")) ==
			    0)
				osmux_cid = mgcp_osmux_setup(endp, line);
			break;
		case '\0':
			have_sdp = 1;
			goto mgcp_header_done;
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "CRCX: endpoint:%x unhandled option: '%c'/%d\n",
			     ENDPOINT_NUMBER(endp), *line, *line);
			break;
		}
	}

mgcp_header_done:
	tcfg = p->endp->tcfg;

	/* Check parameters */
	if (!callid) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x insufficient parameters, missing callid\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "CRCX", p->trans);
	}

	if (!mode) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x insufficient parameters, missing mode\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "CRCX", p->trans);
	}

	if (!ci) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x insufficient parameters, missing connection id\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "CRCX", p->trans);
	}

	/* Check if we are able to accept the creation of another connection */
	if (llist_count(&endp->conns) >= 2) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x endpoint full, max. 2 connections allowed!\n",
		     ENDPOINT_NUMBER(endp));
		if (tcfg->force_realloc) {
			/* There is no more room for a connection, make some
			 * room by blindly tossing the oldest of the two two
			 * connections */
			mgcp_conn_free_oldest(&endp->conns);
		} else {
			/* There is no more room for a connection, leave
			 * everything as it is and return with an error */
			return create_err_response(endp, 400, "CRCX", p->trans);
		}
	}

	/* Check if this endpoint already serves a call, if so, check if the
	 * callids match up so that we are sure that this is our call */
	if (endp->callid && mgcp_verify_call_id(endp, callid)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x allready seized by other call (%s)\n",
		     ENDPOINT_NUMBER(endp), endp->callid);
		if (tcfg->force_realloc)
			/* This is not our call, toss everything by releasing
			 * the entire endpoint. (rude!) */
			mgcp_release_endp(endp);
		else {
			/* This is not our call, leave everything as it is and
			 * return with an error. */
			return create_err_response(endp, 400, "CRCX", p->trans);
		}
	}

	/* Set the callid, creation of another connection will only be possible
	 * when the callid matches up. (Connections are distinuished by their
	 * connection ids) */
	endp->callid = talloc_strdup(tcfg->endpoints, callid);

	/* Extract audio codec information */
	set_local_cx_options(endp->tcfg->endpoints, &endp->local_options,
			     local_options);

	if (mgcp_parse_ci(&conn_id, ci)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x insufficient parameters, missing ci (connectionIdentifier)\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "CRCX", p->trans);
	}

	/* Only accept another connection when the connection ID is different. */
	if (mgcp_conn_get_rtp(&endp->conns, conn_id)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x there is already a connection with id %u present!\n",
		     conn_id, ENDPOINT_NUMBER(endp));
		if (tcfg->force_realloc) {
			/* Ignore the existing connection by just freeing it */
			mgcp_conn_free(&endp->conns, conn_id);
		} else {
			/* There is already a connection with that ID present,
			 * leave everything as it is and return with an error. */
			return create_err_response(endp, 400, "CRCX", p->trans);
		}
	}

	snprintf(conn_name, sizeof(conn_name), "%s-%u", callid, conn_id);
	mgcp_conn_alloc(NULL, &endp->conns, conn_id, MGCP_CONN_TYPE_RTP,
			conn_name);
	conn = mgcp_conn_get_rtp(&endp->conns, conn_id);
	if (!conn) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x unable to allocate RTP connection\n",
		     ENDPOINT_NUMBER(endp));
		goto error2;

	}

	if (mgcp_parse_conn_mode(mode, endp, conn->conn) != 0) {
		error_code = 517;
		goto error2;
	}

	mgcp_rtp_end_config(endp, 0, &conn->end);

	if (allocate_port(endp, conn) != 0) {
		goto error2;
	}

	/* Annotate Osmux circuit ID and set it to negotiating state until this
	 * is fully set up from the dummy load. */
	conn->osmux.state = OSMUX_STATE_DISABLED;
	if (osmux_cid >= 0) {
		conn->osmux.cid = osmux_cid;
		conn->osmux.state = OSMUX_STATE_NEGOTIATING;
	} else if (endp->cfg->osmux == OSMUX_USAGE_ONLY) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x osmux only and no osmux offered\n",
		     ENDPOINT_NUMBER(endp));
		goto error2;
	}

	/* set up RTP media parameters */
	if (have_sdp)
		mgcp_parse_sdp_data(endp, &conn->end, p);
	else if (endp->local_options.codec)
		mgcp_set_audio_info(p->cfg, &conn->end.codec,
				    PTYPE_UNDEFINED, endp->local_options.codec);

	if (p->cfg->force_ptime) {
		conn->end.packet_duration_ms = p->cfg->force_ptime;
		conn->end.force_output_ptime = 1;
	}

	if (setup_rtp_processing(endp, conn) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "CRCX: endpoint:%x could not start RTP processing!\n",
		     ENDPOINT_NUMBER(endp));
		goto error2;
	}

	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(tcfg, ENDPOINT_NUMBER(endp),
				       MGCP_ENDP_CRCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "CRCX: endpoint:%x CRCX rejected by policy\n",
			     ENDPOINT_NUMBER(endp));
			mgcp_release_endp(endp);
			return create_err_response(endp, 400, "CRCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "CRCX: endpoint:%x Creating connection: CI: %u port: %u\n",
	     ENDPOINT_NUMBER(endp), conn->conn->id, conn->end.local_port);
	if (p->cfg->change_cb)
		p->cfg->change_cb(tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX);

	if (conn->conn->mode & MGCP_CONN_RECV_ONLY
	    && tcfg->keepalive_interval != 0) {
		send_dummy(endp, conn);
	}

	LOGP(DLMGCP, LOGL_NOTICE,
	     "CRCX: endpoint:%x connection successfully created\n",
	     ENDPOINT_NUMBER(endp));
	return create_response_with_sdp(endp, conn, "CRCX", p->trans);
error2:
	mgcp_release_endp(endp);
	LOGP(DLMGCP, LOGL_NOTICE,
	     "CRCX: endpoint:%x unable to create connection resource error\n",
	     ENDPOINT_NUMBER(endp));
	return create_err_response(endp, error_code, "CRCX", p->trans);
}

/* MDCX command handler, processes the received command */
static struct msgb *handle_modify_con(struct mgcp_parse_data *p)
{
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 500;
	int silent = 0;
	int have_sdp = 0;
	char *line;
	const char *ci = NULL;
	const char *local_options = NULL;
	const char *mode = NULL;
	struct mgcp_conn_rtp *conn = NULL;
	uint32_t conn_id;

	LOGP(DLMGCP, LOGL_DEBUG, "MDCX: modifying existing connection ...\n");

	if (p->found != 0)
		return create_err_response(NULL, 510, "MDCX", p->trans);

	if (llist_count(&endp->conns) <= 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MDCX: endpoint:%x endpoint is not holding a connection.\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "MDCX", p->trans);
	}

	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

		switch (line[0]) {
		case 'C':
			if (mgcp_verify_call_id(endp, line + 3) != 0)
				goto error3;
			break;
		case 'I':
			ci = (const char *)line + 3;
			if (mgcp_verify_ci(endp, ci) != 0)
				goto error3;
			break;
		case 'L':
			local_options = (const char *)line + 3;
			break;
		case 'M':
			mode = (const char *)line + 3;
			break;
		case 'Z':
			silent = strcmp("noanswer", line + 3) == 0;
			break;
		case '\0':
			have_sdp = 1;
			goto mgcp_header_done;
			break;
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "MDCX: endpoint:%x Unhandled MGCP option: '%c'/%d\n",
			     ENDPOINT_NUMBER(endp), line[0], line[0]);
			break;
		}
	}

mgcp_header_done:
	if (mgcp_parse_ci(&conn_id, ci)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "MDCX: endpoint:%x insufficient parameters, missing ci (connectionIdentifier)\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "MDCX", p->trans);
	}

	conn = mgcp_conn_get_rtp(&endp->conns, conn_id);
	if (!conn)
		return create_err_response(endp, 400, "MDCX", p->trans);

	if (mode) {
		if (mgcp_parse_conn_mode(mode, endp, conn->conn) != 0) {
			error_code = 517;
			goto error3;
		}
	} else
			conn->conn->mode = conn->conn->mode_orig;

	if (have_sdp)
		mgcp_parse_sdp_data(endp, &conn->end, p);

	set_local_cx_options(endp->tcfg->endpoints, &endp->local_options,
			     local_options);

	if (!have_sdp && endp->local_options.codec)
		mgcp_set_audio_info(p->cfg, &conn->end.codec,
				    PTYPE_UNDEFINED, endp->local_options.codec);

	if (setup_rtp_processing(endp, conn) != 0)
		goto error3;


	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				       MGCP_ENDP_MDCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "MDCX: endpoint:%x rejected by policy\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(endp, 400, "MDCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			LOGP(DLMGCP, LOGL_DEBUG,
			     "MDCX: endpoint:%x defered by policy\n",
			     ENDPOINT_NUMBER(endp));
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	mgcp_rtp_end_config(endp, 1, &conn->end);

	/* modify */
	LOGP(DLMGCP, LOGL_DEBUG,
	     "MDCX: endpoint:%x modified conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));
	if (p->cfg->change_cb)
		p->cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				  MGCP_ENDP_MDCX);

	if (conn->conn->mode & MGCP_CONN_RECV_ONLY &&
	    endp->tcfg->keepalive_interval != 0)
		send_dummy(endp, conn);

	if (silent)
		goto out_silent;

	LOGP(DLMGCP, LOGL_NOTICE,
	     "MDCX: endpoint:%x connection successfully modified\n",
	     ENDPOINT_NUMBER(endp));
	return create_response_with_sdp(endp, conn, "MDCX", p->trans);
error3:
	return create_err_response(endp, error_code, "MDCX", p->trans);

out_silent:
	LOGP(DLMGCP, LOGL_DEBUG, "MDCX: endpoint:%x silent exit\n",
	     ENDPOINT_NUMBER(endp));
	return NULL;
}

/* DLCX command handler, processes the received command */
static struct msgb *handle_delete_con(struct mgcp_parse_data *p)
{
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 400;
	int silent = 0;
	char *line;
	char stats[1048];
	const char *ci = NULL;
	struct mgcp_conn_rtp *conn = NULL;
	uint32_t conn_id;

	LOGP(DLMGCP, LOGL_DEBUG,
	     "DLCX: endpoint:%x deleting connection ...\n",
	     ENDPOINT_NUMBER(endp));

	if (p->found != 0)
		return create_err_response(NULL, error_code, "DLCX", p->trans);

	if (llist_count(&endp->conns) <= 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "DLCX: endpoint:%x endpoint is not holding a connection.\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "DLCX", p->trans);
	}

	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

		switch (line[0]) {
		case 'C':
			if (mgcp_verify_call_id(endp, line + 3) != 0)
				goto error3;
			break;
		case 'I':
			ci = (const char *)line + 3;
			if (mgcp_verify_ci(endp, ci) != 0)
				goto error3;
			break;
		case 'Z':
			silent = strcmp("noanswer", line + 3) == 0;
			break;
		default:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "DLCX: endpoint:%x Unhandled MGCP option: '%c'/%d\n",
			     ENDPOINT_NUMBER(endp), line[0], line[0]);
			break;
		}
	}

	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				       MGCP_ENDP_DLCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DLMGCP, LOGL_NOTICE,
			     "DLCX: endpoint:%x rejected by policy\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(endp, 400, "DLCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	/* find the connection */
	if (mgcp_parse_ci(&conn_id, ci)) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "DLCX: endpoint:%x insufficient parameters, missing ci (connectionIdentifier)\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "DLCX", p->trans);
	}

	conn = mgcp_conn_get_rtp(&endp->conns, conn_id);
	if (!conn)
		goto error3;

	/* save the statistics of the current connection */
	mgcp_format_stats(stats, sizeof(stats), conn->conn);

	/* delete connection */
	LOGP(DLMGCP, LOGL_DEBUG, "DLCX: endpoint:%x deleting conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));
	mgcp_conn_free(&endp->conns, conn_id);

	/* When all connections are closed, the endpoint will be released
	 * in order to be ready to be used by another call. */
	if (llist_count(&endp->conns) <= 0) {
		mgcp_release_endp(endp);
		LOGP(DLMGCP, LOGL_DEBUG,
		     "DLCX: endpoint:%x endpoint released\n",
		     ENDPOINT_NUMBER(endp));
	}

	if (p->cfg->change_cb)
		p->cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
				  MGCP_ENDP_DLCX);

	if (silent)
		goto out_silent;
	return create_ok_resp_with_param(endp, 250, "DLCX", p->trans, stats);

error3:
	return create_err_response(endp, error_code, "DLCX", p->trans);

out_silent:
	LOGP(DLMGCP, LOGL_DEBUG, "DLCX: endpoint:%x silent exit\n",
	     ENDPOINT_NUMBER(endp));
	return NULL;
}

/* RSIP command handler, processes the received command */
static struct msgb *handle_rsip(struct mgcp_parse_data *p)
{
	/* TODO: Also implement the resetting of a specific endpoint
	 * to make mgcp_send_reset_ep() work. Currently this will call
	 * mgcp_rsip_cb() in mgw_main.c, which sets reset_endpoints=1
	 * to make read_call_agent() reset all endpoints when called
	 * next time. In order to selectively reset endpoints some
	 * mechanism to distinguish which endpoint shall be resetted
	 * is needed */

	LOGP(DLMGCP, LOGL_DEBUG, "RSIP: resetting all endpoints ...\n");

	if (p->found != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "RSIP: failed to find the endpoint.\n");
		return NULL;
	}

	if (p->cfg->reset_cb)
		p->cfg->reset_cb(p->endp->tcfg);
	return NULL;
}

static char extract_tone(const char *line)
{
	const char *str = strstr(line, "D/");
	if (!str)
		return CHAR_MAX;

	return str[2];
}

/* This can request like DTMF detection and forward, fax detection... it
 * can also request when the notification should be send and such. We don't
 * do this right now. */
static struct msgb *handle_noti_req(struct mgcp_parse_data *p)
{
	int res = 0;
	char *line;
	char tone = CHAR_MAX;

	if (p->found != 0)
		return create_err_response(NULL, 400, "RQNT", p->trans);

	for_each_line(line, p->save) {
		switch (line[0]) {
		case 'S':
			tone = extract_tone(line);
			break;
		}
	}

	/* we didn't see a signal request with a tone */
	if (tone == CHAR_MAX)
		return create_ok_response(p->endp, 200, "RQNT", p->trans);

	if (p->cfg->rqnt_cb)
		res = p->cfg->rqnt_cb(p->endp, tone);

	return res == 0 ?
	    create_ok_response(p->endp, 200, "RQNT", p->trans) :
	    create_err_response(p->endp, res, "RQNT", p->trans);
}

/* Connection keepalive timer, will take care that dummy packets are send
 * regulary, so that NAT connections stay open */
static void mgcp_keepalive_timer_cb(void *_tcfg)
{
	struct mgcp_trunk_config *tcfg = _tcfg;
	struct mgcp_conn *conn;
	int i;

	LOGP(DLMGCP, LOGL_DEBUG, "Triggered trunk %d keepalive timer.\n",
	     tcfg->trunk_nr);

	if (tcfg->keepalive_interval <= 0)
		return;

	/* Send walk over all endpoints and send out dummy packets through
	 * every connection present on each endpoint */
	for (i = 1; i < tcfg->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &tcfg->endpoints[i];
		llist_for_each_entry(conn, &endp->conns, entry) {
			if (conn->mode == MGCP_CONN_RECV_ONLY)
				send_dummy(endp, &conn->u.rtp);
		}
	}

	LOGP(DLMGCP, LOGL_DEBUG, "Rescheduling trunk %d keepalive timer.\n",
	     tcfg->trunk_nr);
	osmo_timer_schedule(&tcfg->keepalive_timer, tcfg->keepalive_interval,
			    0);
}

void mgcp_trunk_set_keepalive(struct mgcp_trunk_config *tcfg, int interval)
{
	tcfg->keepalive_interval = interval;
	osmo_timer_setup(&tcfg->keepalive_timer, mgcp_keepalive_timer_cb, tcfg);

	if (interval <= 0)
		osmo_timer_del(&tcfg->keepalive_timer);
	else
		osmo_timer_schedule(&tcfg->keepalive_timer,
				    tcfg->keepalive_interval, 0);
}

/*! \brief allocate configuration with default values.
 *  (called once at startup by main function) */
struct mgcp_config *mgcp_config_alloc(void)
{
	struct mgcp_config *cfg;

	cfg = talloc_zero(NULL, struct mgcp_config);
	if (!cfg) {
		LOGP(DLMGCP, LOGL_FATAL, "Failed to allocate config.\n");
		return NULL;
	}

	cfg->net_ports.range_start = RTP_PORT_DEFAULT_RANGE_START;
	cfg->net_ports.range_end = RTP_PORT_DEFAULT_RANGE_END;
	cfg->net_ports.last_port = cfg->net_ports.range_start;

	cfg->source_port = 2427;
	cfg->source_addr = talloc_strdup(cfg, "0.0.0.0");
	cfg->osmux_addr = talloc_strdup(cfg, "0.0.0.0");

	cfg->rtp_processing_cb = &mgcp_rtp_processing_default;
	cfg->setup_rtp_processing_cb = &mgcp_setup_rtp_processing_default;

	cfg->get_net_downlink_format_cb = &mgcp_get_net_downlink_format_default;

	/* default trunk handling */
	cfg->trunk.cfg = cfg;
	cfg->trunk.trunk_nr = 0;
	cfg->trunk.trunk_type = MGCP_TRUNK_VIRTUAL;
	cfg->trunk.audio_name = talloc_strdup(cfg, "AMR/8000");
	cfg->trunk.audio_payload = 126;
	cfg->trunk.audio_send_ptime = 1;
	cfg->trunk.audio_send_name = 1;
	cfg->trunk.omit_rtcp = 0;
	mgcp_trunk_set_keepalive(&cfg->trunk, MGCP_KEEPALIVE_ONCE);

	INIT_LLIST_HEAD(&cfg->trunks);

	return cfg;
}

/*! \brief allocate configuration with default values.
 *  (called once at startup by VTY)
 *  \param[in] cfg mgcp configuration
 *  \param[in] nr trunk number
 *  \returns pointer to allocated trunk configuration */
struct mgcp_trunk_config *mgcp_trunk_alloc(struct mgcp_config *cfg, int nr)
{
	struct mgcp_trunk_config *trunk;

	trunk = talloc_zero(cfg, struct mgcp_trunk_config);
	if (!trunk) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	trunk->cfg = cfg;
	trunk->trunk_type = MGCP_TRUNK_E1;
	trunk->trunk_nr = nr;
	trunk->audio_name = talloc_strdup(cfg, "AMR/8000");
	trunk->audio_payload = 126;
	trunk->audio_send_ptime = 1;
	trunk->audio_send_name = 1;
	trunk->number_endpoints = 33;
	trunk->omit_rtcp = 0;
	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_ONCE);
	llist_add_tail(&trunk->entry, &cfg->trunks);
	return trunk;
}

/*! \brief get trunk configuration by trunk number (index).
 *  \param[in] cfg mgcp configuration
 *  \param[in] index trunk number
 *  \returns pointer to trunk configuration, NULL on error */
struct mgcp_trunk_config *mgcp_trunk_num(struct mgcp_config *cfg, int index)
{
	struct mgcp_trunk_config *trunk;

	llist_for_each_entry(trunk, &cfg->trunks, entry)
	    if (trunk->trunk_nr == index)
		return trunk;

	return NULL;
}

/*! \brief allocate endpoints and set default values.
 *  (called once at startup by VTY)
 *  \param[in] tcfg trunk configuration
 *  \returns 0 on success, -1 on failure */
int mgcp_endpoints_allocate(struct mgcp_trunk_config *tcfg)
{
	int i;

	/* Initialize all endpoints */
	tcfg->endpoints = _talloc_zero_array(tcfg->cfg,
					     sizeof(struct mgcp_endpoint),
					     tcfg->number_endpoints,
					     "endpoints");
	if (!tcfg->endpoints)
		return -1;

	for (i = 0; i < tcfg->number_endpoints; ++i) {
		INIT_LLIST_HEAD(&tcfg->endpoints[i].conns);
		tcfg->endpoints[i].cfg = tcfg->cfg;
		tcfg->endpoints[i].tcfg = tcfg;
	}

	return 0;
}

/*! \brief relase endpoint, all open connections are closed.
 *  \param[in] endp endpoint to release */
void mgcp_release_endp(struct mgcp_endpoint *endp)
{
	LOGP(DLMGCP, LOGL_DEBUG, "Releasing endpoint:%x\n",
	     ENDPOINT_NUMBER(endp));

	/* Normally this function should only be called wehen
	 * all connections have been removed already. In case
	 * that there are still connections open (e.g. when
	 * RSIP is executed), free them all at once. */
	mgcp_conn_free_all(&endp->conns);

	/* Reset endpoint parameters and states */
	talloc_free(endp->callid);
	endp->callid = NULL;
	talloc_free(endp->local_options.string);
	endp->local_options.string = NULL;
	talloc_free(endp->local_options.codec);
	endp->local_options.codec = NULL;
	endp->type = MGCP_RTP_DEFAULT;
}

static int send_agent(struct mgcp_config *cfg, const char *buf, int len)
{
	return write(cfg->gw_fd.bfd.fd, buf, len);
}

/*! \brief Reset all endpoints by sending RSIP message to self
 *  (called by VTY)
 *  \param[in] endp trunk endpoint
 *  \param[in] endpoint number
 *  \returns 0 on success, -1 on error */
int mgcp_send_reset_all(struct mgcp_config *cfg)
{
	int rc;

	static const char mgcp_reset[] = {
		"RSIP 1 *@mgw MGCP 1.0\r\n"
	};

	rc = send_agent(cfg, mgcp_reset, sizeof mgcp_reset - 1);
	if (rc <= 0)
		return -1;

	return 0;
}

/*! \brief Reset a single endpoint by sending RSIP message to self
 *  (called by VTY)
 *  \param[in] endp trunk endpoint
 *  \param[in] endpoint number
 *  \returns 0 on success, -1 on error */
int mgcp_send_reset_ep(struct mgcp_endpoint *endp, int endpoint)
{
	char buf[128];
	int len;
	int rc;

	len = snprintf(buf, sizeof(buf),
		       "RSIP 39 %x@mgw MGCP 1.0\r\n", endpoint);
	if (len < 0)
		return -1;

	buf[sizeof(buf) - 1] = '\0';

	rc = send_agent(endp->cfg, buf, len);
	if (rc <= 0)
		return -1;

	return 0;
}
