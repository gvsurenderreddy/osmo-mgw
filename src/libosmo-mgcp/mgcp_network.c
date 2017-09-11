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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_stat.h>
#include <osmocom/mgcp/osmux.h>

#define RTP_SEQ_MOD		(1 << 16)
#define RTP_MAX_DROPOUT		3000
#define RTP_MAX_MISORDER	100
#define RTP_BUF_SIZE		4096

enum {
	MGCP_PROTO_RTP,
	MGCP_PROTO_RTCP,
};

/* This does not need to be a precision timestamp and
 * is allowed to wrap quite fast. The returned value is
 * 1/unit seconds. */
static uint32_t get_current_ts(unsigned unit)
{
	struct timespec tp;
	uint64_t ret;

	if (!unit)
		return 0;

	memset(&tp, 0, sizeof(tp));
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		LOGP(DLMGCP, LOGL_NOTICE, "Getting the clock failed.\n");

	/* convert it to 1/unit seconds */
	ret = tp.tv_sec;
	ret *= unit;
	ret += (int64_t) tp.tv_nsec * unit / 1000 / 1000 / 1000;

	return ret;
}

/*! \brief send udp packet.
 *  \param[in] fd associated file descriptor
 *  \param[in] addr destination ip-address
 *  \param[in] port destination UDP port
 *  \param[in] buf buffer that holds the data to be send
 *  \param[in] len length of the data to be sent
 *  \returns bytes sent, -1 on error */
int mgcp_udp_send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;

	LOGP(DLMGCP, LOGL_DEBUG,
	     "sending %u bytes length packet to %s:%u ...\n",
	     len, inet_ntoa(*addr), ntohs(port));

	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

/*! \brief send RTP dummy packet (to keep NAT connection open).
 *  \param[in] endp mcgp endpoint that holds the RTP connection
 *  \param[in] conn associated RTP connection
 *  \returns bytes sent, -1 on error */
int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	static char buf[] = { MGCP_DUMMY_LOAD };
	int rc;
	int was_rtcp = 0;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:%x sending dummy packet...\n", ENDPOINT_NUMBER(endp));
	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));

	rc = mgcp_udp_send(conn->end.rtp.fd, &conn->end.addr,
			   conn->end.rtp_port, buf, 1);

	if (rc == -1)
		goto failed;

	if (endp->tcfg->omit_rtcp)
		return rc;

	was_rtcp = 1;
	rc = mgcp_udp_send(conn->end.rtcp.fd, &conn->end.addr,
			   conn->end.rtcp_port, buf, 1);

	if (rc >= 0)
		return rc;

failed:
	LOGP(DLMGCP, LOGL_ERROR,
	     "endpoint:%x Failed to send dummy %s packet.\n",
	     ENDPOINT_NUMBER(endp), was_rtcp ? "RTCP" : "RTP");

	return -1;
}

/* Compute timestamp alignment error */
static int32_t ts_aligment_error(struct mgcp_rtp_stream_state *sstate,
				 int ptime, uint32_t timestamp)
{
	int32_t timestamp_delta;

	if (ptime == 0)
		return 0;

	/* Align according to: T - Tlast = k * Tptime */
	timestamp_delta = timestamp - sstate->last_timestamp;

	return timestamp_delta % ptime;
}

/* Check timestamp and sequence number for plausibility */
static int check_rtp_timestamp(struct mgcp_endpoint *endp,
			       struct mgcp_rtp_state *state,
			       struct mgcp_rtp_stream_state *sstate,
			       struct mgcp_rtp_end *rtp_end,
			       struct sockaddr_in *addr,
			       uint16_t seq, uint32_t timestamp,
			       const char *text, int32_t * tsdelta_out)
{
	int32_t tsdelta;
	int32_t timestamp_error;

	/* Not fully intialized, skip */
	if (sstate->last_tsdelta == 0 && timestamp == sstate->last_timestamp)
		return 0;

	if (seq == sstate->last_seq) {
		if (timestamp != sstate->last_timestamp) {
			sstate->err_ts_counter += 1;
			LOGP(DLMGCP, LOGL_ERROR,
			     "The %s timestamp delta is != 0 but the sequence "
			     "number %d is the same, "
			     "TS offset: %d, SeqNo offset: %d "
			     "on 0x%x SSRC: %u timestamp: %u "
			     "from %s:%d\n",
			     text, seq,
			     state->timestamp_offset, state->seq_offset,
			     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
		return 0;
	}

	tsdelta =
	    (int32_t) (timestamp - sstate->last_timestamp) /
	    (int16_t) (seq - sstate->last_seq);

	if (tsdelta == 0) {
		/* Don't update *tsdelta_out */
		LOGP(DLMGCP, LOGL_NOTICE,
		     "The %s timestamp delta is %d "
		     "on 0x%x SSRC: %u timestamp: %u "
		     "from %s:%d\n",
		     text, tsdelta,
		     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

		return 0;
	}

	if (sstate->last_tsdelta != tsdelta) {
		if (sstate->last_tsdelta) {
			LOGP(DLMGCP, LOGL_INFO,
			     "The %s timestamp delta changes from %d to %d "
			     "on 0x%x SSRC: %u timestamp: %u from %s:%d\n",
			     text, sstate->last_tsdelta, tsdelta,
			     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
	}

	if (tsdelta_out)
		*tsdelta_out = tsdelta;

	timestamp_error =
	    ts_aligment_error(sstate, state->packet_duration, timestamp);

	if (timestamp_error) {
		sstate->err_ts_counter += 1;
		LOGP(DLMGCP, LOGL_NOTICE,
		     "The %s timestamp has an alignment error of %d "
		     "on 0x%x SSRC: %u "
		     "SeqNo delta: %d, TS delta: %d, dTS/dSeq: %d "
		     "from %s:%d. ptime: %d\n",
		     text, timestamp_error,
		     ENDPOINT_NUMBER(endp), sstate->ssrc,
		     (int16_t) (seq - sstate->last_seq),
		     (int32_t) (timestamp - sstate->last_timestamp),
		     tsdelta,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
		     state->packet_duration);
	}
	return 1;
}

/* Set the timestamp offset according to the packet duration. */
static int adjust_rtp_timestamp_offset(struct mgcp_endpoint *endp,
				       struct mgcp_rtp_state *state,
				       struct mgcp_rtp_end *rtp_end,
				       struct sockaddr_in *addr,
				       int16_t delta_seq, uint32_t in_timestamp)
{
	int32_t tsdelta = state->packet_duration;
	int timestamp_offset;
	uint32_t out_timestamp;

	if (tsdelta == 0) {
		tsdelta = state->out_stream.last_tsdelta;
		if (tsdelta != 0) {
			LOGP(DLMGCP, LOGL_NOTICE,
			     "A fixed packet duration is not available on 0x%x, "
			     "using last output timestamp delta instead: %d "
			     "from %s:%d\n",
			     ENDPOINT_NUMBER(endp), tsdelta,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		} else {
			tsdelta = rtp_end->codec.rate * 20 / 1000;
			LOGP(DLMGCP, LOGL_NOTICE,
			     "Fixed packet duration and last timestamp delta "
			     "are not available on 0x%x, "
			     "using fixed 20ms instead: %d "
			     "from %s:%d\n",
			     ENDPOINT_NUMBER(endp), tsdelta,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
	}

	out_timestamp = state->out_stream.last_timestamp + delta_seq * tsdelta;
	timestamp_offset = out_timestamp - in_timestamp;

	if (state->timestamp_offset != timestamp_offset) {
		state->timestamp_offset = timestamp_offset;

		LOGP(DLMGCP, LOGL_NOTICE,
		     "Timestamp offset change on 0x%x SSRC: %u "
		     "SeqNo delta: %d, TS offset: %d, "
		     "from %s:%d\n",
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     delta_seq, state->timestamp_offset,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}

	return timestamp_offset;
}

/* Set the timestamp offset according to the packet duration. */
static int align_rtp_timestamp_offset(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_state *state,
				      struct mgcp_rtp_end *rtp_end,
				      struct sockaddr_in *addr,
				      uint32_t timestamp)
{
	int timestamp_error = 0;
	int ptime = state->packet_duration;

	/* Align according to: T + Toffs - Tlast = k * Tptime */

	timestamp_error = ts_aligment_error(&state->out_stream, ptime,
					    timestamp +
					    state->timestamp_offset);

	if (timestamp_error) {
		state->timestamp_offset += ptime - timestamp_error;

		LOGP(DLMGCP, LOGL_NOTICE,
		     "Corrected timestamp alignment error of %d on 0x%x SSRC: %u "
		     "new TS offset: %d, "
		     "from %s:%d\n",
		     timestamp_error,
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     state->timestamp_offset, inet_ntoa(addr->sin_addr),
		     ntohs(addr->sin_port));
	}

	OSMO_ASSERT(ts_aligment_error(&state->out_stream, ptime,
				      timestamp + state->timestamp_offset) ==
		    0);

	return timestamp_error;
}

/*! \brief dummy callback to disable transcoding (see also cfg->rtp_processing_cb)
 *  \param[in] associated endpoint
 *  \param[in] destination RTP end
 *  \param[in,out] pointer to buffer with voice data
 *  \param[in] voice data length
 *  \param[in] maxmimum size of caller provided voice data buffer
 *  \returns ignores input parameters, return always 0 */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp,
				struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size)
{
	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x transcoding disabled\n",
	     ENDPOINT_NUMBER(endp));
	return 0;
}

/*! \brief dummy callback to disable transcoding (see also cfg->setup_rtp_processing_cb)
 *  \param[in] associated endpoint
 *  \param[in] destination RTP end
 *  \param[in] source RTP end
 *  \returns ignores input parameters, return always 0 */
int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_end *dst_end,
				      struct mgcp_rtp_end *src_end)
{
	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x transcoding disabled\n",
	     ENDPOINT_NUMBER(endp));
	return 0;
}

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char **audio_name,
					  const char **fmtp_extra,
					  struct mgcp_conn_rtp *conn)
{
	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:%x conn:%s mgcp_get_net_downlink_format_default()\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn->conn));

	*payload_type = conn->end.codec.payload_type;
	*audio_name = conn->end.codec.audio_name;
	*fmtp_extra = conn->end.fmtp_extra;
}

void mgcp_rtp_annex_count(struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state, const uint16_t seq,
			  const int32_t transit, const uint32_t ssrc)
{
	int32_t d;

	/* initialize or re-initialize */
	if (!state->stats_initialized || state->stats_ssrc != ssrc) {
		state->stats_initialized = 1;
		state->stats_base_seq = seq;
		state->stats_max_seq = seq - 1;
		state->stats_ssrc = ssrc;
		state->stats_jitter = 0;
		state->stats_transit = transit;
		state->stats_cycles = 0;
	} else {
		uint16_t udelta;

		/* The below takes the shape of the validation of
		 * Appendix A. Check if there is something weird with
		 * the sequence number, otherwise check for a wrap
		 * around in the sequence number.
		 * It can't wrap during the initialization so let's
		 * skip it here. The Appendix A probably doesn't have
		 * this issue because of the probation. */
		udelta = seq - state->stats_max_seq;
		if (udelta < RTP_MAX_DROPOUT) {
			if (seq < state->stats_max_seq)
				state->stats_cycles += RTP_SEQ_MOD;
		} else if (udelta <= RTP_SEQ_MOD - RTP_MAX_MISORDER) {
			LOGP(DLMGCP, LOGL_NOTICE,
			     "RTP seqno made a very large jump on 0x%x delta: %u\n",
			     ENDPOINT_NUMBER(endp), udelta);
		}
	}

	/* Calculate the jitter between the two packages. The TS should be
	 * taken closer to the read function. This was taken from the
	 * Appendix A of RFC 3550. Timestamp and arrival_time have a 1/rate
	 * resolution. */
	d = transit - state->stats_transit;
	state->stats_transit = transit;
	if (d < 0)
		d = -d;
	state->stats_jitter += d - ((state->stats_jitter + 8) >> 4);
	state->stats_max_seq = seq;
}

/* The RFC 3550 Appendix A assumes there are multiple sources but
 * some of the supported endpoints (e.g. the nanoBTS) can only handle
 * one source and this code will patch RTP header to appear as if there
 * is only one source.
 * There is also no probation period for new sources. Every RTP header
 * we receive will be seen as a switch in streams. */
void mgcp_patch_and_count(struct mgcp_endpoint *endp,
			  struct mgcp_rtp_state *state,
			  struct mgcp_rtp_end *rtp_end,
			  struct sockaddr_in *addr, char *data, int len)
{
	uint32_t arrival_time;
	int32_t transit;
	uint16_t seq;
	uint32_t timestamp, ssrc;
	struct rtp_hdr *rtp_hdr;
	int payload = rtp_end->codec.payload_type;

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *)data;
	seq = ntohs(rtp_hdr->sequence);
	timestamp = ntohl(rtp_hdr->timestamp);
	arrival_time = get_current_ts(rtp_end->codec.rate);
	ssrc = ntohl(rtp_hdr->ssrc);
	transit = arrival_time - timestamp;

	mgcp_rtp_annex_count(endp, state, seq, transit, ssrc);

	if (!state->initialized) {
		state->initialized = 1;
		state->in_stream.last_seq = seq - 1;
		state->in_stream.ssrc = state->orig_ssrc = ssrc;
		state->in_stream.last_tsdelta = 0;
		state->packet_duration =
		    mgcp_rtp_packet_duration(endp, rtp_end);
		state->out_stream = state->in_stream;
		state->out_stream.last_timestamp = timestamp;
		state->out_stream.ssrc = ssrc - 1;	/* force output SSRC change */
		LOGP(DLMGCP, LOGL_INFO,
		     "endpoint:%x initializing stream, SSRC: %u timestamp: %u "
		     "pkt-duration: %d, from %s:%d\n",
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     state->seq_offset, state->packet_duration,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		if (state->packet_duration == 0) {
			state->packet_duration =
			    rtp_end->codec.rate * 20 / 1000;
			LOGP(DLMGCP, LOGL_NOTICE,
			     "endpoint:%x fixed packet duration is not available, "
			     "using fixed 20ms instead: %d from %s:%d\n",
			     ENDPOINT_NUMBER(endp), state->packet_duration,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}
	} else if (state->in_stream.ssrc != ssrc) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "endpoint:%x SSRC changed: %u -> %u  "
		     "from %s:%d\n",
		     ENDPOINT_NUMBER(endp),
		     state->in_stream.ssrc, rtp_hdr->ssrc,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

		state->in_stream.ssrc = ssrc;
		if (rtp_end->force_constant_ssrc) {
			int16_t delta_seq;

			/* Always increment seqno by 1 */
			state->seq_offset =
			    (state->out_stream.last_seq + 1) - seq;

			/* Estimate number of packets that would have been sent */
			delta_seq =
			    (arrival_time - state->in_stream.last_arrival_time
			     + state->packet_duration / 2) /
			    state->packet_duration;

			adjust_rtp_timestamp_offset(endp, state, rtp_end, addr,
						    delta_seq, timestamp);

			state->patch_ssrc = 1;
			ssrc = state->orig_ssrc;
			if (rtp_end->force_constant_ssrc != -1)
				rtp_end->force_constant_ssrc -= 1;

			LOGP(DLMGCP, LOGL_NOTICE,
			     "endpoint:%x SSRC patching enabled, SSRC: %u "
			     "SeqNo offset: %d, TS offset: %d "
			     "from %s:%d\n",
			     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
			     state->seq_offset, state->timestamp_offset,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		}

		state->in_stream.last_tsdelta = 0;
	} else {
		/* Compute current per-packet timestamp delta */
		check_rtp_timestamp(endp, state, &state->in_stream, rtp_end,
				    addr, seq, timestamp, "input",
				    &state->in_stream.last_tsdelta);

		if (state->patch_ssrc)
			ssrc = state->orig_ssrc;
	}

	/* Save before patching */
	state->in_stream.last_timestamp = timestamp;
	state->in_stream.last_seq = seq;
	state->in_stream.last_arrival_time = arrival_time;

	if (rtp_end->force_aligned_timing &&
	    state->out_stream.ssrc == ssrc && state->packet_duration)
		/* Align the timestamp offset */
		align_rtp_timestamp_offset(endp, state, rtp_end, addr,
					   timestamp);

	/* Store the updated SSRC back to the packet */
	if (state->patch_ssrc)
		rtp_hdr->ssrc = htonl(ssrc);

	/* Apply the offset and store it back to the packet.
	 * This won't change anything if the offset is 0, so the conditional is
	 * omitted. */
	seq += state->seq_offset;
	rtp_hdr->sequence = htons(seq);
	timestamp += state->timestamp_offset;
	rtp_hdr->timestamp = htonl(timestamp);

	/* Check again, whether the timestamps are still valid */
	if (state->out_stream.ssrc == ssrc)
		check_rtp_timestamp(endp, state, &state->out_stream, rtp_end,
				    addr, seq, timestamp, "output",
				    &state->out_stream.last_tsdelta);

	/* Save output values */
	state->out_stream.last_seq = seq;
	state->out_stream.last_timestamp = timestamp;
	state->out_stream.ssrc = ssrc;

	if (payload < 0)
		return;

#if 0
	DEBUGP(DLMGCP,
	       "endpoint:%x payload hdr payload %u -> endp payload %u\n",
	       ENDPOINT_NUMBER(endp), rtp_hdr->payload_type, payload);
	rtp_hdr->payload_type = payload;
#endif
}

/* Forward data to a debug tap. This is debug function that is intended for
 * debugging the voice traffic with tools like gstreamer */
static int forward_data(int fd, struct mgcp_rtp_tap *tap, const char *buf,
			int len)
{
	if (!tap->enabled)
		return 0;

	return sendto(fd, buf, len, 0,
		      (struct sockaddr *)&tap->forward, sizeof(tap->forward));
}

/*! \brief Send RTP/RTCP data to a specified destination connection
 *  \param[in] endp associated endpoint (for configuration, logging)
 *  \param[in] is_rtp flag to specify if the packet is of type RTP or RTCP
 *  \param[in] spoofed source address (set to NULL to disable)
 *  \param[in] buf buffer that contains the RTP/RTCP data
 *  \param[in] len length of the buffer that contains the RTP/RTCP data
 *  \param[in] conn_src associated source connection
 *  \param[in] conn_dst associated destination connection
 *  \returns 0 on success, -1 on ERROR */
int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct sockaddr_in *addr,
	      char *buf, int len, struct mgcp_conn_rtp *conn_src,
	      struct mgcp_conn_rtp *conn_dst)
{
	/*! When no destination connection is available (e.g. when only one
	 *  connection in loopback mode exists), then the source connection
	 *  shall be specified as destination connection */

	struct mgcp_trunk_config *tcfg = endp->tcfg;
	struct mgcp_rtp_end *rtp_end;
	struct mgcp_rtp_state *rtp_state;
	char *dest_name;

	OSMO_ASSERT(conn_src);
	OSMO_ASSERT(conn_dst);

	if (is_rtp) {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint:%x delivering RTP packet...\n",
		     ENDPOINT_NUMBER(endp));
	} else {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint:%x delivering RTCP packet...\n",
		     ENDPOINT_NUMBER(endp));
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:%x loop:%d, mode:%d ",
	     ENDPOINT_NUMBER(endp), tcfg->audio_loop, conn_src->conn->mode);
	if (conn_src->conn->mode == MGCP_CONN_LOOPBACK)
		LOGPC(DLMGCP, LOGL_DEBUG, "(loopback)\n");
	else
		LOGPC(DLMGCP, LOGL_DEBUG, "\n");

	/* Note: In case of loopback configuration, both, the source and the
	 * destination will point to the same connection. */
	rtp_end = &conn_dst->end;
	rtp_state = &conn_src->state;
	dest_name = conn_dst->conn->name;

	if (!rtp_end->output_enabled) {
		rtp_end->dropped_packets += 1;
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint:%x output disabled, drop to %s %s "
		     "rtp_port:%u rtcp_port:%u\n",
		     ENDPOINT_NUMBER(endp),
		     dest_name,
		     inet_ntoa(rtp_end->addr),
		     ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
		    );
	} else if (is_rtp) {
		int cont;
		int nbytes = 0;
		int buflen = len;
		do {
			/* Run transcoder */
			cont = endp->cfg->rtp_processing_cb(endp, rtp_end,
							    buf, &buflen,
							    RTP_BUF_SIZE);
			if (cont < 0)
				break;

			if (addr)
				mgcp_patch_and_count(endp, rtp_state, rtp_end,
						     addr, buf, buflen);
			LOGP(DLMGCP, LOGL_DEBUG,
			     "endpoint:%x process/send to %s %s "
			     "rtp_port:%u rtcp_port:%u\n",
			     ENDPOINT_NUMBER(endp), dest_name,
			     inet_ntoa(rtp_end->addr), ntohs(rtp_end->rtp_port),
			     ntohs(rtp_end->rtcp_port)
			    );

			/* Forward a copy of the RTP data to a debug ip/port */
			forward_data(rtp_end->rtp.fd, &conn_src->tap_out,
				     buf, buflen);

			/* FIXME: HACK HACK HACK. See OS#2459.
			 * The ip.access nano3G needs the first RTP payload's first two bytes to read hex
			 * 'e400', or it will reject the RAB assignment. It seems to not harm other femto
			 * cells (as long as we patch only the first RTP payload in each stream).
			 */
			if (!rtp_state->patched_first_rtp_payload) {
				uint8_t *data = (uint8_t *) & buf[12];
				data[0] = 0xe4;
				data[1] = 0x00;
				rtp_state->patched_first_rtp_payload = true;
			}

			len = mgcp_udp_send(rtp_end->rtp.fd,
					    &rtp_end->addr,
					    rtp_end->rtp_port, buf, buflen);

			if (len <= 0)
				return len;

			conn_dst->end.packets_tx += 1;
			conn_dst->end.octets_tx += len;

			nbytes += len;
			buflen = cont;
		} while (buflen > 0);
		return nbytes;
	} else if (!tcfg->omit_rtcp) {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint:%x send to %s %s rtp_port:%u rtcp_port:%u\n",
		     ENDPOINT_NUMBER(endp),
		     dest_name,
		     inet_ntoa(rtp_end->addr),
		     ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
		    );

		len = mgcp_udp_send(rtp_end->rtcp.fd,
				    &rtp_end->addr,
				    rtp_end->rtcp_port, buf, len);

		conn_dst->end.packets_tx += 1;
		conn_dst->end.octets_tx += len;

		return len;
	}

	return 0;
}

/* Helper function for mgcp_recv(),
   Receive one RTP Packet + Originating address from file descriptor */
static int receive_from(struct mgcp_endpoint *endp, int fd,
			struct sockaddr_in *addr, char *buf, int bufsize)
{
	int rc;
	socklen_t slen = sizeof(*addr);
	struct sockaddr_in addr_sink;
	char buf_sink[RTP_BUF_SIZE];
	bool tossed = false;

	if (!addr)
		addr = &addr_sink;
	if (!buf) {
		tossed = true;
		buf = buf_sink;
		bufsize = sizeof(buf_sink);
	}

	rc = recvfrom(fd, buf, bufsize, 0, (struct sockaddr *)addr, &slen);

	LOGP(DLMGCP, LOGL_DEBUG,
	     "receiving %u bytes length packet from %s:%u ...\n",
	     rc, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

	if (rc < 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x failed to receive packet, errno: %d/%s\n",
		     ENDPOINT_NUMBER(endp), errno, strerror(errno));
		return -1;
	}

	if (tossed) {
		LOGP(DLMGCP, LOGL_ERROR, "endpoint:%x packet tossed\n",
		     ENDPOINT_NUMBER(endp));
	}

	return rc;
}

/* Receive RTP data from a specified source connection and dispatch it to a
 * destination connection. */
static int mgcp_recv(struct osmo_fd *fd, struct mgcp_conn_rtp *conn_src,
		     struct mgcp_conn_rtp *conn_dst)
{
	char buf[RTP_BUF_SIZE];
	struct sockaddr_in addr;
	struct mgcp_endpoint *endp;
	int rc, proto;

	OSMO_ASSERT(conn_src);
	OSMO_ASSERT(conn_dst);

	endp = (struct mgcp_endpoint *)fd->data;

	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x receiving RTP/RTCP packet...\n",
	     ENDPOINT_NUMBER(endp));

	rc = receive_from(endp, fd->fd, &addr, buf, sizeof(buf));
	if (rc <= 0)
		return -1;

	proto = fd == &conn_src->end.rtp ? MGCP_PROTO_RTP : MGCP_PROTO_RTCP;

	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x ", ENDPOINT_NUMBER(endp));
	LOGPC(DLMGCP, LOGL_DEBUG, "receiveing from %s %s %d\n",
	      conn_src->conn->name, inet_ntoa(addr.sin_addr),
	      ntohs(addr.sin_port));
	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x conn:%s\n", ENDPOINT_NUMBER(endp),
	     mgcp_conn_dump(conn_src->conn));

#if 0
	/* Note: Check if tha inbound RTP data comes from the same host to
	 * which we send our outgoing RTP traffic. */
	if (memcmp(&addr.sin_addr, &conn_src->end.addr, sizeof(addr.sin_addr))
	    != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x data from wrong address: %s, ",
		     ENDPOINT_NUMBER(endp), inet_ntoa(addr.sin_addr));
		LOGPC(DLMGCP, LOGL_ERROR, "expected: %s\n",
		      inet_ntoa(conn_src->end.addr));
		LOGP(DLMGCP, LOGL_ERROR, "endpoint:%x packet tossed\n");
		return -1;
	}

	/* FIXME: Make this a VTY option, this can make debugging unnecessary difficult! */
	/* Note: Usually the remote remote port of the data we receive will be
	 * the same as the remote port where we transmit outgoing RTP traffic
	 * to (set by MDCX). We use this to check the origin of the data for
	 * plausibility. */

	if (conn_src->end.rtp_port != addr.sin_port &&
	    conn_src->end.rtcp_port != addr.sin_port) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x data from wrong source port: %d, ",
		     ENDPOINT_NUMBER(endp), ntohs(addr.sin_port));
		LOGPC(DLMGCP, LOGL_ERROR,
		      "expected: %d for RTP or %d for RTCP\n",
		      ntohs(conn_src->end.rtp_port),
		      ntohs(conn_src->end.rtcp_port));
		LOGP(DLMGCP, LOGL_ERROR, "endpoint:%x packet tossed\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}
#endif

	/* Filter out dummy message */
	if (rc == 1 && buf[0] == MGCP_DUMMY_LOAD) {
		LOGP(DLMGCP, LOGL_NOTICE,
		     "endpoint:%x dummy message received\n",
		     ENDPOINT_NUMBER(endp));
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x packet tossed\n", ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* Increment RX statistics */
	conn_src->end.packets_rx += 1;
	conn_src->end.octets_rx += rc;

	/* Forward a copy of the RTP data to a debug ip/port */
	forward_data(fd->fd, &conn_src->tap_in, buf, rc);

	switch (endp->type) {
	case MGCP_RTP_DEFAULT:
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint:%x endpoint type is MGCP_RTP_DEFAULT, "
		     "using mgcp_send() to forward data directly\n",
		     ENDPOINT_NUMBER(endp));
		return mgcp_send(endp, proto == MGCP_PROTO_RTP,
				 &addr, buf, rc, conn_src, conn_dst);
	case MGCP_OSMUX_BSC_NAT:
	case MGCP_OSMUX_BSC:
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint:%x endpoint type is MGCP_OSMUX_BSC_NAT, "
		     "using osmux_xfrm_to_osmux() to forward data through OSMUX\n",
		     ENDPOINT_NUMBER(endp));
		return osmux_xfrm_to_osmux(buf, rc, conn_src);
	}

	/* If the data has not been handled/forwarded until here, it will
	 * be discarded, this should not happen, normally the MGCP type
	 * should be properly set */
	LOGP(DLMGCP, LOGL_ERROR,
	     "endpoint:%x bad MGCP type -- data discarded!\n",
	     ENDPOINT_NUMBER(endp));
	return 0;
}

/* Receive from NET and send to BTS */
static int rtp_data_net(struct osmo_fd *fd, unsigned int what)
{
	struct mgcp_conn_rtp *conn_src;
	struct mgcp_conn_rtp *conn_dst;
	struct mgcp_endpoint *endp;
	struct mgcp_conn *conn;

	endp = (struct mgcp_endpoint *)fd->data;
	OSMO_ASSERT(endp);

	/* Find the connection context to which the caller provieded file
	 * descriptor belongs to. This will be the source connection. Since
	 * this connection has been previously bound, finding it should be
	 * always successfull. */
	conn_src = mgcp_conn_get_rtp_by_fd(&endp->conns, fd);
	if (!conn_src) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x unable to find source conn - this is a bug!\n",
		     ENDPOINT_NUMBER(endp));
		receive_from(endp, fd->fd, NULL, NULL, 0);
		return -1;
	}
	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x source conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn_src->conn));

	/* Find destination connection conntext */
	if (conn_src->conn->mode == MGCP_CONN_LOOPBACK) {
		/* If we are in loopback mode, simply use the source connection
		 * as destination */
		conn_dst = conn_src;
	} else {
		/* Find the destination connection by picking the first
		 * connection that is not the source connection. If there is
		 * only the source connetion present, we will drop all incoming
		 * data. */
		conn_dst = NULL;
		llist_for_each_entry(conn, &endp->conns, entry) {
			if (conn->type == MGCP_CONN_TYPE_RTP) {
				if (&conn->u.rtp.end.rtp != fd)
					conn_dst = &conn->u.rtp;
			}
		}
	}

	/* If we fail to identify a destination connection, we just toss the
	 * packet. */
	if (!conn_dst) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x unable to find destination conn\n",
		     ENDPOINT_NUMBER(endp));
		receive_from(endp, fd->fd, NULL, NULL, 0);
		return -1;
	}

	LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x destin conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn_dst->conn));

	/* Before we try to deliver the packet, we check if the destination
	 * port and IP-Address make sense at all. If not, we will be unable
	 * to deliver the packet */
	if (strcmp(inet_ntoa(conn_dst->end.addr), "0.0.0.0") == 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x destination IP-address is invalid\n",
		     ENDPOINT_NUMBER(endp));
		receive_from(endp, fd->fd, NULL, NULL, 0);
		return -1;
	}

	if (conn_dst->end.rtp_port == 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x destination rtp port is invalid\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	return mgcp_recv(fd, conn_src, conn_dst);
}

/*! \brief set IP Type of Service parameter
 *  \param[in] fd associated file descriptor
 *  \param[in] tos dscp value
 *  \returns 0 on success, -1 on ERROR */
int mgcp_set_ip_tos(int fd, int tos)
{
	int ret;
	ret = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

	if (ret < 0)
		return -1;
	return 0;
}

/*! \brief bind RTP port to osmo_fd
 *  \param[in] source_addr source (local) address to bind on
 *  \param[in] fd associated file descriptor
 *  \param[in] port to bind on
 *  \returns 0 on success, -1 on ERROR */
int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port)
{
	struct sockaddr_in addr;
	int on = 1;

	fd->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd->fd < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "failed to create UDP port (%s:%i).\n",
		     source_addr, port);
		return -1;
	} else {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "created UDP port (%s:%i).\n", source_addr, port);
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "failed to set socket options (%s:%i).\n", source_addr,
		     port);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton(source_addr, &addr.sin_addr);

	if (bind(fd->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd->fd);
		fd->fd = -1;
		LOGP(DLMGCP, LOGL_ERROR, "failed to bind UDP port (%s:%i).\n",
		     source_addr, port);
		return -1;
	} else {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "bound UDP port (%s:%i).\n", source_addr, port);
	}

	return 0;
}

/* Bind RTP and RTCP port (helper function for mgcp_bind_net_rtp_port()) */
static int bind_rtp(struct mgcp_config *cfg, const char *source_addr,
		    struct mgcp_rtp_end *rtp_end, int endpno)
{
	/* NOTE: The port that is used for RTCP is the RTP port incremented by one
	 * (e.g. RTP-Port = 16000 ==> RTCP-Port = 16001) */

	if (mgcp_create_bind(source_addr, &rtp_end->rtp,
			     rtp_end->local_port) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x failed to create RTP port: %s:%d\n", endpno,
		     source_addr, rtp_end->local_port);
		goto cleanup0;
	}

	if (mgcp_create_bind(source_addr, &rtp_end->rtcp,
			     rtp_end->local_port + 1) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x failed to create RTCP port: %s:%d\n", endpno,
		     source_addr, rtp_end->local_port + 1);
		goto cleanup1;
	}

	/* Set Type of Service (DSCP-Value) as configured via VTY */
	mgcp_set_ip_tos(rtp_end->rtp.fd, cfg->endp_dscp);
	mgcp_set_ip_tos(rtp_end->rtcp.fd, cfg->endp_dscp);

	rtp_end->rtp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtp) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x failed to register RTP port %d\n", endpno,
		     rtp_end->local_port);
		goto cleanup2;
	}

	rtp_end->rtcp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtcp) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x failed to register RTCP port %d\n", endpno,
		     rtp_end->local_port + 1);
		goto cleanup3;
	}

	return 0;

cleanup3:
	osmo_fd_unregister(&rtp_end->rtp);
cleanup2:
	close(rtp_end->rtcp.fd);
	rtp_end->rtcp.fd = -1;
cleanup1:
	close(rtp_end->rtp.fd);
	rtp_end->rtp.fd = -1;
cleanup0:
	return -1;
}

/*! \brief bind RTP port to endpoint/connection
 *  \param[in] endp endpoint that holds the RTP connection
 *  \param[in] rtp_port port number to bind on
 *  \param[in] conn associated RTP connection
 *  \returns 0 on success, -1 on ERROR */
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn)
{
	char name[512];
	struct mgcp_rtp_end *end;

	snprintf(name, sizeof(name), "%s-%u", conn->conn->name, conn->conn->id);
	end = &conn->end;

	if (end->rtp.fd != -1 || end->rtcp.fd != -1) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x %u was already bound on conn:%s\n",
		     ENDPOINT_NUMBER(endp), rtp_port,
		     mgcp_conn_dump(conn->conn));

		/* Double bindings should never occour! Since we always allocate
		 * connections dynamically and free them when they are not
		 * needed anymore, there must be no previous binding leftover.
		 * Should there be a connection bound twice, we have a serious
		 * problem and must exit immediately! */
		OSMO_ASSERT(false);
	}

	end->local_port = rtp_port;
	end->rtp.cb = rtp_data_net;
	end->rtp.data = endp;
	end->rtcp.data = endp;
	end->rtcp.cb = rtp_data_net;

	return bind_rtp(endp->cfg, mgcp_net_src_addr(endp), end,
			ENDPOINT_NUMBER(endp));
}

/*! \brief free allocated RTP and RTCP ports.
 *  \param[in] end RTP end */
void mgcp_free_rtp_port(struct mgcp_rtp_end *end)
{
	if (end->rtp.fd != -1) {
		close(end->rtp.fd);
		end->rtp.fd = -1;
		osmo_fd_unregister(&end->rtp);
	}

	if (end->rtcp.fd != -1) {
		close(end->rtcp.fd);
		end->rtcp.fd = -1;
		osmo_fd_unregister(&end->rtcp);
	}
}
