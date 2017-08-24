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

#include <osmocom/legacy_mgcp/mgcp.h>
#include <osmocom/legacy_mgcp/mgcp_internal.h>

#include <osmocom/legacy_mgcp/osmux.h>

#warning "Make use of the rtp proxy code"


#define RTP_SEQ_MOD		(1 << 16)
#define RTP_MAX_DROPOUT		3000
#define RTP_MAX_MISORDER	100
#define RTP_BUF_SIZE		4096

enum {
	MGCP_PROTO_RTP,
	MGCP_PROTO_RTCP,
};

/**
 * This does not need to be a precision timestamp and
 * is allowed to wrap quite fast. The returned value is
 * 1/unit seconds.
 */
static uint32_t get_current_ts(unsigned unit)
{
	struct timespec tp;
	uint64_t ret;

	if (!unit)
		return 0;

	memset(&tp, 0, sizeof(tp));
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		LOGP(DLMGCP, LOGL_NOTICE,
			"Getting the clock failed.\n");

	/* convert it to 1/unit seconds */
	ret = tp.tv_sec;
	ret *= unit;
	ret += (int64_t)tp.tv_nsec * unit / 1000 / 1000 / 1000;

	return ret;
}

int mgcp_udp_send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

int mgcp_send_dummy(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn)
{
	static char buf[] = { MGCP_DUMMY_LOAD };
	int rc;
	int was_rtcp = 0;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);

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
		"Failed to send dummy %s packet: %s on: 0x%x to %s:%d\n",
		was_rtcp ? "RTCP" : "RTP",
		strerror(errno), ENDPOINT_NUMBER(endp), inet_ntoa(conn->end.addr),
		was_rtcp ? conn->end.rtcp_port : conn->end.rtp_port);

	return -1;
}

static int32_t compute_timestamp_aligment_error(struct mgcp_rtp_stream_state *sstate,
						int ptime, uint32_t timestamp)
{
	int32_t timestamp_delta;

	if (ptime == 0)
		return 0;

	/* Align according to: T - Tlast = k * Tptime */
	timestamp_delta = timestamp - sstate->last_timestamp;

	return timestamp_delta % ptime;
}

static int check_rtp_timestamp(struct mgcp_endpoint *endp,
			       struct mgcp_rtp_state *state,
			       struct mgcp_rtp_stream_state *sstate,
			       struct mgcp_rtp_end *rtp_end,
			       struct sockaddr_in *addr,
			       uint16_t seq, uint32_t timestamp,
			       const char *text, int32_t *tsdelta_out)
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
			     "from %s:%d in %d\n",
			     text, seq,
			     state->timestamp_offset, state->seq_offset,
			     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			     endp->conn_mode);
		}
		return 0;
	}

	tsdelta =
		(int32_t)(timestamp - sstate->last_timestamp) /
		(int16_t)(seq - sstate->last_seq);

	if (tsdelta == 0) {
		/* Don't update *tsdelta_out */
		LOGP(DLMGCP, LOGL_NOTICE,
		     "The %s timestamp delta is %d "
		     "on 0x%x SSRC: %u timestamp: %u "
		     "from %s:%d in %d\n",
		     text, tsdelta,
		     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
		     endp->conn_mode);

		return 0;
	}

	if (sstate->last_tsdelta != tsdelta) {
		if (sstate->last_tsdelta) {
			LOGP(DLMGCP, LOGL_INFO,
			     "The %s timestamp delta changes from %d to %d "
			     "on 0x%x SSRC: %u timestamp: %u from %s:%d in %d\n",
			     text, sstate->last_tsdelta, tsdelta,
			     ENDPOINT_NUMBER(endp), sstate->ssrc, timestamp,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			     endp->conn_mode);
		}
	}

	if (tsdelta_out)
		*tsdelta_out = tsdelta;

	timestamp_error =
		compute_timestamp_aligment_error(sstate, state->packet_duration,
						 timestamp);

	if (timestamp_error) {
		sstate->err_ts_counter += 1;
		LOGP(DLMGCP, LOGL_NOTICE,
		     "The %s timestamp has an alignment error of %d "
		     "on 0x%x SSRC: %u "
		     "SeqNo delta: %d, TS delta: %d, dTS/dSeq: %d "
		     "from %s:%d in mode %d. ptime: %d\n",
		     text, timestamp_error,
		     ENDPOINT_NUMBER(endp), sstate->ssrc,
		     (int16_t)(seq - sstate->last_seq),
		     (int32_t)(timestamp - sstate->last_timestamp),
		     tsdelta,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
		     endp->conn_mode, state->packet_duration);
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
			     "from %s:%d in %d\n",
			     ENDPOINT_NUMBER(endp), tsdelta,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			     endp->conn_mode);
		} else {
			tsdelta = rtp_end->codec.rate * 20 / 1000;
			LOGP(DLMGCP, LOGL_NOTICE,
			     "Fixed packet duration and last timestamp delta "
			     "are not available on 0x%x, "
			     "using fixed 20ms instead: %d "
			     "from %s:%d in %d\n",
			     ENDPOINT_NUMBER(endp), tsdelta,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			     endp->conn_mode);
		}
	}

	out_timestamp = state->out_stream.last_timestamp + delta_seq * tsdelta;
	timestamp_offset = out_timestamp - in_timestamp;

	if (state->timestamp_offset != timestamp_offset) {
		state->timestamp_offset = timestamp_offset;

		LOGP(DLMGCP, LOGL_NOTICE,
		     "Timestamp offset change on 0x%x SSRC: %u "
		     "SeqNo delta: %d, TS offset: %d, "
		     "from %s:%d in %d\n",
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     delta_seq, state->timestamp_offset,
		     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
		     endp->conn_mode);
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

	timestamp_error = compute_timestamp_aligment_error(
		&state->out_stream, ptime,
		timestamp + state->timestamp_offset);

	if (timestamp_error) {
		state->timestamp_offset += ptime - timestamp_error;

		LOGP(DLMGCP, LOGL_NOTICE,
		     "Corrected timestamp alignment error of %d on 0x%x SSRC: %u "
		     "new TS offset: %d, "
		     "from %s:%d in %d\n",
		     timestamp_error,
		     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
		     state->timestamp_offset, inet_ntoa(addr->sin_addr),
		     ntohs(addr->sin_port), endp->conn_mode);
	}

	OSMO_ASSERT(compute_timestamp_aligment_error(&state->out_stream, ptime,
						     timestamp + state->timestamp_offset) == 0);

	return timestamp_error;
}

int mgcp_rtp_processing_default(struct mgcp_endpoint *endp, struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size)
{
	return 0;
}

int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_end *dst_end,
				      struct mgcp_rtp_end *src_end)
{
	return 0;
}

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char**audio_name,
					  const char**fmtp_extra)
{
	struct mgcp_conn_rtp *conn_bts = NULL;

	conn_bts = mgcp_conn_get_rtp(&endp->conns, CONN_ID_BTS);
	if (!conn_bts)
		return;

	/* Use the BTS side parameters when passing the SDP data (for
	 * downlink) to the net peer.
	 */
	*payload_type = conn_bts->end.codec.payload_type;
	*audio_name = conn_bts->end.codec.audio_name;
	*fmtp_extra = conn_bts->end.fmtp_extra;
}


void mgcp_rtp_annex_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			const uint16_t seq, const int32_t transit,
			const uint32_t ssrc)
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

		/*
		 * The below takes the shape of the validation of
		 * Appendix A. Check if there is something weird with
		 * the sequence number, otherwise check for a wrap
		 * around in the sequence number.
		 * It can't wrap during the initialization so let's
		 * skip it here. The Appendix A probably doesn't have
		 * this issue because of the probation.
		 */
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

	/*
	 * Calculate the jitter between the two packages. The TS should be
	 * taken closer to the read function. This was taken from the
	 * Appendix A of RFC 3550. Timestamp and arrival_time have a 1/rate
	 * resolution.
	 */
	d = transit - state->stats_transit;
	state->stats_transit = transit;
	if (d < 0)
		d = -d;
	state->stats_jitter += d - ((state->stats_jitter + 8) >> 4);
	state->stats_max_seq = seq;
}



/**
 * The RFC 3550 Appendix A assumes there are multiple sources but
 * some of the supported endpoints (e.g. the nanoBTS) can only handle
 * one source and this code will patch RTP header to appear as if there
 * is only one source.
 * There is also no probation period for new sources. Every RTP header
 * we receive will be seen as a switch in streams.
 */
void mgcp_patch_and_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			  struct mgcp_rtp_end *rtp_end, struct sockaddr_in *addr,
			  char *data, int len)
{
	uint32_t arrival_time;
	int32_t transit;
	uint16_t seq;
	uint32_t timestamp, ssrc;
	struct rtp_hdr *rtp_hdr;
	int payload = rtp_end->codec.payload_type;

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *) data;
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
		state->packet_duration = mgcp_rtp_packet_duration(endp, rtp_end);
		state->out_stream = state->in_stream;
		state->out_stream.last_timestamp = timestamp;
		state->out_stream.ssrc = ssrc - 1; /* force output SSRC change */
		LOGP(DLMGCP, LOGL_INFO,
			"Initializing stream on 0x%x SSRC: %u timestamp: %u "
			"pkt-duration: %d, from %s:%d in %d\n",
			ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
			state->seq_offset, state->packet_duration,
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			endp->conn_mode);
		if (state->packet_duration == 0) {
			state->packet_duration = rtp_end->codec.rate * 20 / 1000;
			LOGP(DLMGCP, LOGL_NOTICE,
			     "Fixed packet duration is not available on 0x%x, "
			     "using fixed 20ms instead: %d from %s:%d in %d\n",
			     ENDPOINT_NUMBER(endp), state->packet_duration,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			     endp->conn_mode);
		}
	} else if (state->in_stream.ssrc != ssrc) {
		LOGP(DLMGCP, LOGL_NOTICE,
			"The SSRC changed on 0x%x: %u -> %u  "
			"from %s:%d in %d\n",
			ENDPOINT_NUMBER(endp),
			state->in_stream.ssrc, rtp_hdr->ssrc,
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			endp->conn_mode);

		state->in_stream.ssrc = ssrc;
		if (rtp_end->force_constant_ssrc) {
			int16_t delta_seq;

			/* Always increment seqno by 1 */
			state->seq_offset =
				(state->out_stream.last_seq + 1) - seq;

			/* Estimate number of packets that would have been sent */
			delta_seq =
				(arrival_time - state->in_stream.last_arrival_time
				 + state->packet_duration/2) /
				state->packet_duration;

			adjust_rtp_timestamp_offset(endp, state, rtp_end, addr,
						    delta_seq, timestamp);

			state->patch_ssrc = 1;
			ssrc = state->orig_ssrc;
			if (rtp_end->force_constant_ssrc != -1)
				rtp_end->force_constant_ssrc -= 1;

			LOGP(DLMGCP, LOGL_NOTICE,
			     "SSRC patching enabled on 0x%x SSRC: %u "
			     "SeqNo offset: %d, TS offset: %d "
			     "from %s:%d in %d\n",
			     ENDPOINT_NUMBER(endp), state->in_stream.ssrc,
			     state->seq_offset, state->timestamp_offset,
			     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			     endp->conn_mode);
		}

		state->in_stream.last_tsdelta = 0;
	} else {
		/* Compute current per-packet timestamp delta */
		check_rtp_timestamp(endp, state, &state->in_stream, rtp_end, addr,
				    seq, timestamp, "input",
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
		align_rtp_timestamp_offset(endp, state, rtp_end, addr, timestamp);

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
	DEBUGP(DLMGCP, "Payload hdr payload %u -> endp payload %u\n",
	       rtp_hdr->payload_type, payload);
	rtp_hdr->payload_type = payload;
#endif
}

/*
 * The below code is for dispatching. We have a dedicated port for
 * the data coming from the net and one to discover the BTS.
 */
static int forward_data(int fd, struct mgcp_rtp_tap *tap, const char *buf, int len)
{
	if (!tap->enabled)
		return 0;

	return sendto(fd, buf, len, 0,
		      (struct sockaddr *)&tap->forward, sizeof(tap->forward));
}

int mgcp_send(struct mgcp_endpoint *endp, int is_rtp, struct sockaddr_in *addr,
	      char *buf, int rc, uint32_t conn_src_id, uint32_t conn_dst_id)
{
	struct mgcp_trunk_config *tcfg = endp->tcfg;
	struct mgcp_rtp_end *rtp_end;
	struct mgcp_rtp_state *rtp_state;
	struct mgcp_conn_rtp *conn_src;
	struct mgcp_conn_rtp *conn_dst;
	char *dest_name;

	conn_src = mgcp_conn_get_rtp(&endp->conns, conn_src_id);
	conn_dst = mgcp_conn_get_rtp(&endp->conns, conn_dst_id);
	if (!conn_src || !conn_dst)
		return -1;

	LOGP(DLMGCP, LOGL_DEBUG, "endpoint %x: src_conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn_src->conn));
	LOGP(DLMGCP, LOGL_DEBUG, "endpoint %x: dst_conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn_dst->conn));
	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint %x: loop:%d, mode:%d (== loopback: %d)\n",
	     ENDPOINT_NUMBER(endp), tcfg->audio_loop, endp->conn_mode,
	     endp->conn_mode == MGCP_CONN_LOOPBACK);

	if (endp->conn_mode != MGCP_CONN_LOOPBACK) {
		rtp_end = &conn_dst->end;
		rtp_state = &conn_src->state;
		dest_name = conn_dst->conn->name;
	} else {
		rtp_end = &conn_src->end;
		rtp_state = &conn_dst->state;
		dest_name = conn_src->conn->name;
	}

	if (!rtp_end->output_enabled) {
		rtp_end->dropped_packets += 1;
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint %x: output disabled, drop to %s %s rtp_port:%u rtcp_port:%u\n",
		     ENDPOINT_NUMBER(endp),
		     dest_name,
		     inet_ntoa(rtp_end->addr),
		     ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
		    );
	} else if (is_rtp) {
		int cont;
		int nbytes = 0;
		int len = rc;
		do {
			cont = endp->cfg->rtp_processing_cb(endp, rtp_end,
							    buf, &len,
							    RTP_BUF_SIZE);
			if (cont < 0)
				break;

			mgcp_patch_and_count(endp, rtp_state, rtp_end, addr,
					     buf, len);
			LOGP(DLMGCP, LOGL_DEBUG,
			     "endpoint %x: process/send to %s %s rtp_port:%u rtcp_port:%u\n",
			     ENDPOINT_NUMBER(endp), dest_name,
			     inet_ntoa(rtp_end->addr), ntohs(rtp_end->rtp_port),
			     ntohs(rtp_end->rtcp_port)
			    );
			forward_data(rtp_end->rtp.fd, &conn_dst->tap_out,
				     buf, len);

			if (!rtp_state->patched_first_rtp_payload) {
				uint8_t *data = (uint8_t *) & buf[12];
				osmo_hexparse("e400", data, 2);
				rtp_state->patched_first_rtp_payload = true;
			}

			rc = mgcp_udp_send(rtp_end->rtp.fd,
					   &rtp_end->addr,
					   rtp_end->rtp_port, buf, len);

			if (rc <= 0)
				return rc;
			nbytes += rc;
			len = cont;
		} while (len > 0);
		return nbytes;
	} else if (!tcfg->omit_rtcp) {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "endpoint %x: send to %s %s rtp_port:%u rtcp_port:%u\n",
		     ENDPOINT_NUMBER(endp),
		     dest_name,
		     inet_ntoa(rtp_end->addr),
		     ntohs(rtp_end->rtp_port), ntohs(rtp_end->rtcp_port)
		    );

		return mgcp_udp_send(rtp_end->rtcp.fd,
				     &rtp_end->addr,
				     rtp_end->rtcp_port, buf, rc);
	}

	return 0;
}

static int receive_from(struct mgcp_endpoint *endp, int fd, struct sockaddr_in *addr,
			char *buf, int bufsize)
{
	int rc;
	socklen_t slen = sizeof(*addr);

	rc = recvfrom(fd, buf, bufsize, 0,
			    (struct sockaddr *) addr, &slen);
	if (rc < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to receive message on: 0x%x errno: %d/%s\n",
			ENDPOINT_NUMBER(endp), errno, strerror(errno));
		return -1;
	}

	/* do not forward aynthing... maybe there is a packet from the bts */
	if (!endp->allocated)
		return -1;

	#warning "Slight spec violation. With connection mode recvonly we should attempt to forward."

	return rc;
}

static int rtp_data_net(struct osmo_fd *fd, unsigned int what)
{
	char buf[RTP_BUF_SIZE];
	struct sockaddr_in addr;
	struct mgcp_endpoint *endp;
	int rc, proto;
	struct mgcp_conn_rtp *conn_net = NULL;
	struct mgcp_conn_rtp *conn_bts = NULL;

	endp = (struct mgcp_endpoint *) fd->data;

	conn_bts = mgcp_conn_get_rtp(&endp->conns, CONN_ID_BTS);
	conn_net = mgcp_conn_get_rtp(&endp->conns, CONN_ID_NET);
	if (!conn_bts || !conn_net)
		return -1;

	rc = receive_from(endp, fd->fd, &addr, buf, sizeof(buf));
	if (rc <= 0)
		return -1;

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint %x",
	     ENDPOINT_NUMBER(endp));
	LOGPC(DLMGCP, LOGL_DEBUG,
	      " from net %s %d",
	      inet_ntoa(addr.sin_addr),
	      ntohs(addr.sin_port));
	LOGPC(DLMGCP, LOGL_DEBUG,
	      " conn[1].u.rtp.end %s %d %d",
	      inet_ntoa(conn_net->end.addr),
	      ntohs(conn_net->end.rtp_port),
	      ntohs(conn_net->end.rtcp_port));
	LOGPC(DLMGCP, LOGL_DEBUG,
	      " conn[0].u.rtp.end %s %d %d\n",
	      inet_ntoa(conn_bts->end.addr),
	      ntohs(conn_bts->end.rtp_port),
	      ntohs(conn_bts->end.rtcp_port)
	     );

	if (memcmp(&addr.sin_addr, &conn_net->end.addr, sizeof(addr.sin_addr)) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
			"rtp_data_net: Endpoint 0x%x data from wrong address %s vs. ",
			ENDPOINT_NUMBER(endp), inet_ntoa(addr.sin_addr));
		LOGPC(DLMGCP, LOGL_ERROR,
			"%s\n", inet_ntoa(conn_net->end.addr));
		return -1;
	}

	switch(endp->type) {
	case MGCP_RTP_DEFAULT:
	case MGCP_OSMUX_BSC:
	case MGCP_OSMUX_BSC_NAT:
		break;
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "rtp_data_net: Endpoint %x data from %s %d\n",
	     ENDPOINT_NUMBER(endp),
	     inet_ntoa(addr.sin_addr),
	     ntohs(addr.sin_port));

	/* throw away the dummy message */
	if (rc == 1 && buf[0] == MGCP_DUMMY_LOAD) {
		LOGP(DLMGCP, LOGL_NOTICE, "Filtered dummy from network on 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return 0;
	}

	proto = fd == &conn_net->end.rtp ? MGCP_PROTO_RTP : MGCP_PROTO_RTCP;
	conn_net->end.packets += 1;
	conn_net->end.octets += rc;

	forward_data(fd->fd, &conn_net->tap_in, buf, rc);

	switch (endp->type) {
	case MGCP_RTP_DEFAULT:
		return mgcp_send(endp, proto == MGCP_PROTO_RTP,
				 &addr, buf, rc, CONN_ID_NET, CONN_ID_BTS);
	case MGCP_OSMUX_BSC_NAT:
		return osmux_xfrm_to_osmux(MGCP_DEST_BTS, buf, rc, endp);
	case MGCP_OSMUX_BSC:	/* Should not happen */
		break;
	}

	LOGP(DLMGCP, LOGL_ERROR, "Bad MGCP type %u on endpoint %u\n",
	     endp->type, ENDPOINT_NUMBER(endp));
	return 0;
}

static void discover_bts(struct mgcp_endpoint *endp, int proto, struct sockaddr_in *addr)
{
	struct mgcp_config *cfg = endp->cfg;
	struct mgcp_conn_rtp *conn_bts = NULL;

	conn_bts = mgcp_conn_get_rtp(&endp->conns, CONN_ID_BTS);
	if (!conn_bts)
		return;

	if (proto == MGCP_PROTO_RTP && conn_bts->end.rtp_port == 0) {
		if (!cfg->bts_ip ||
		    memcmp(&addr->sin_addr,
			   &cfg->bts_in, sizeof(cfg->bts_in)) == 0 ||
		    memcmp(&addr->sin_addr,
			   &conn_bts->end.addr, sizeof(conn_bts->end.addr)) == 0) {

			conn_bts->end.rtp_port = addr->sin_port;
			conn_bts->end.addr = addr->sin_addr;

			LOGP(DLMGCP, LOGL_NOTICE,
				"Found BTS for endpoint: 0x%x on port: %d/%d of %s\n",
				ENDPOINT_NUMBER(endp), ntohs(conn_bts->end.rtp_port),
				ntohs(conn_bts->end.rtcp_port), inet_ntoa(addr->sin_addr));
		}
	} else if (proto == MGCP_PROTO_RTCP && conn_bts->end.rtcp_port == 0) {
		if (memcmp(&conn_bts->end.addr, &addr->sin_addr,
				sizeof(conn_bts->end.addr)) == 0) {
			conn_bts->end.rtcp_port = addr->sin_port;
		}
	}
}

static int rtp_data_bts(struct osmo_fd *fd, unsigned int what)
{
	char buf[RTP_BUF_SIZE];
	struct sockaddr_in addr;
	struct mgcp_endpoint *endp;
	int rc, proto;
	struct mgcp_conn_rtp *conn_bts = NULL;

	endp = (struct mgcp_endpoint *) fd->data;

	conn_bts = mgcp_conn_get_rtp(&endp->conns, CONN_ID_BTS);
	if (!conn_bts)
		return -1;

	rc = receive_from(endp, fd->fd, &addr, buf, sizeof(buf));
	if (rc <= 0)
		return -1;

	proto = fd == &conn_bts->end.rtp ? MGCP_PROTO_RTP : MGCP_PROTO_RTCP;

	/* We have no idea who called us, maybe it is the BTS. */
	/* it was the BTS... */
	discover_bts(endp, proto, &addr);

	if (memcmp(&conn_bts->end.addr, &addr.sin_addr, sizeof(addr.sin_addr)) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
			"rtp_data_bts: Data from wrong bts %s on 0x%x\n",
			inet_ntoa(addr.sin_addr), ENDPOINT_NUMBER(endp));
		return -1;
	}

	if (conn_bts->end.rtp_port != addr.sin_port &&
	    conn_bts->end.rtcp_port != addr.sin_port) {
		LOGP(DLMGCP, LOGL_ERROR,
			"rtp_data_bts: ata from wrong bts source port %d on 0x%x\n",
			ntohs(addr.sin_port), ENDPOINT_NUMBER(endp));
		return -1;
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "rtp_data_bts: Endpoint %x data from %s %d\n",
	     ENDPOINT_NUMBER(endp),
	     inet_ntoa(addr.sin_addr),
	     ntohs(addr.sin_port));

	/* throw away the dummy message */
	if (rc == 1 && buf[0] == MGCP_DUMMY_LOAD) {
		LOGP(DLMGCP, LOGL_NOTICE, "Filtered dummy from bts on 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* do this before the loop handling */
	conn_bts->end.packets += 1;
	conn_bts->end.octets += rc;

	forward_data(fd->fd, &conn_bts->tap_in, buf, rc);

	switch (endp->type) {
	case MGCP_RTP_DEFAULT:
		LOGP(DLMGCP, LOGL_DEBUG,
		     "rtp_data_bts: Endpoint %x MGCP_RTP_DEFAULT\n",
		     ENDPOINT_NUMBER(endp));
		return mgcp_send(endp, proto == MGCP_PROTO_RTP,
				 &addr, buf, rc, CONN_ID_BTS, CONN_ID_NET);
	case MGCP_OSMUX_BSC:
		/* OSMUX translation: BTS -> BSC */
		return osmux_xfrm_to_osmux(MGCP_DEST_NET, buf, rc, endp);
	case MGCP_OSMUX_BSC_NAT:
		break;	/* Should not happen */
	}

	LOGP(DLMGCP, LOGL_ERROR, "Bad MGCP type %u on endpoint %u\n",
	     endp->type, ENDPOINT_NUMBER(endp));
	return 0;
}

int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port)
{
	struct sockaddr_in addr;
	int on = 1;

	printf("mgcp_create_bind()\n");

	fd->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd->fd < 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to create UDP port (%s:%i).\n",
		     source_addr, port);
		return -1;
	} else {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "Successfully created UDP port (%s:%i).\n", source_addr,
		     port);
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Failed to set socket options (%s:%i).\n", source_addr,
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
		LOGP(DLMGCP, LOGL_ERROR, "Failed to bind UDP port (%s:%i).\n",
		     source_addr, port);
		return -1;
	} else {
		LOGP(DLMGCP, LOGL_DEBUG,
		     "Successfully bound UDP port (%s:%i).\n", source_addr,
		     port);
	}

	return 0;
}

int mgcp_set_ip_tos(int fd, int tos)
{
	int ret;
	ret = setsockopt(fd, IPPROTO_IP, IP_TOS,
			 &tos, sizeof(tos));
	return ret != 0;
}

static int bind_rtp(struct mgcp_config *cfg, const char *source_addr,
			struct mgcp_rtp_end *rtp_end, int endpno)
{
	if (mgcp_create_bind(source_addr, &rtp_end->rtp,
			     rtp_end->local_port) != 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to create RTP port: %s:%d on 0x%x\n",
		       source_addr, rtp_end->local_port, endpno);
		goto cleanup0;
	}

	if (mgcp_create_bind(source_addr, &rtp_end->rtcp,
			     rtp_end->local_port + 1) != 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to create RTCP port: %s:%d on 0x%x\n",
		       source_addr, rtp_end->local_port + 1, endpno);
		goto cleanup1;
	}

	mgcp_set_ip_tos(rtp_end->rtp.fd, cfg->endp_dscp);
	mgcp_set_ip_tos(rtp_end->rtcp.fd, cfg->endp_dscp);

	rtp_end->rtp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtp) != 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to register RTP port %d on 0x%x\n",
			rtp_end->local_port, endpno);
		goto cleanup2;
	}

	rtp_end->rtcp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtcp) != 0) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to register RTCP port %d on 0x%x\n",
			rtp_end->local_port + 1, endpno);
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

static int int_bind(const char *port,
		    struct mgcp_rtp_end *end, int (*cb)(struct osmo_fd *, unsigned),
		    struct mgcp_endpoint *_endp,
		    const char *source_addr, int rtp_port)
{
	if (end->rtp.fd != -1 || end->rtcp.fd != -1) {
		LOGP(DLMGCP, LOGL_ERROR, "Previous %s was still bound on %d\n",
			port, ENDPOINT_NUMBER(_endp));
		mgcp_free_rtp_port(end);
	}

	end->local_port = rtp_port;
	end->rtp.cb = cb;
	end->rtp.data = _endp;
	end->rtcp.data = _endp;
	end->rtcp.cb = cb;
	return bind_rtp(_endp->cfg, source_addr, end, ENDPOINT_NUMBER(_endp));
}

int mgcp_bind_bts_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn)
{
	return int_bind("bts-port", &conn->end,
			rtp_data_bts, endp,
			mgcp_bts_src_addr(endp), rtp_port);
}

int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port,
			   struct mgcp_conn_rtp *conn)
{
	return int_bind("net-port", &conn->end,
			rtp_data_net, endp,
			mgcp_net_src_addr(endp), rtp_port);
}

int mgcp_free_rtp_port(struct mgcp_rtp_end *end)
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

	return 0;
}

void mgcp_state_calc_loss(struct mgcp_rtp_state *state,
			struct mgcp_rtp_end *end, uint32_t *expected,
			int *loss)
{
	*expected = state->stats_cycles + state->stats_max_seq;
	*expected = *expected - state->stats_base_seq + 1;

	if (!state->stats_initialized) {
		*expected = 0;
		*loss = 0;
		return;
	}

	/*
	 * Make sure the sign is correct and use the biggest
	 * positive/negative number that fits.
	 */
	*loss = *expected - end->packets;
	if (*expected < end->packets) {
		if (*loss > 0)
			*loss = INT_MIN;
	} else {
		if (*loss < 0)
			*loss = INT_MAX;
	}
}

uint32_t mgcp_state_calc_jitter(struct mgcp_rtp_state *state)
{
	if (!state->stats_initialized)
		return 0;
	return state->stats_jitter >> 4;
}
