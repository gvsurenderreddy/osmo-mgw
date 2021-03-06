/*
 * Some SDP file parsing...
 *
 * (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2014 by On-Waves
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

#include <osmocom/core/msgb.h>
#include <osmocom/mgcp/mgcp.h>
#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_msg.h>

#include <errno.h>

struct sdp_rtp_map {
	/* the type */
	int payload_type;
	/* null, static or later dynamic codec name */
	char *codec_name;
	/* A pointer to the original line for later parsing */
	char *map_line;

	int rate;
	int channels;
};

/*! Set codec configuration depending on payload type and codec name.
 *  \param[in] ctx talloc context.
 *  \param[out] codec configuration (caller provided memory).
 *  \param[in] payload_type codec type id (e.g. 3 for GSM, -1 when undefined).
 *  \param[in] audio_name audio codec name (e.g. "GSM/8000/1").
 *  \returns 0 on success, -1 on failure. */
int mgcp_set_audio_info(void *ctx, struct mgcp_rtp_codec *codec,
			int payload_type, const char *audio_name)
{
	int rate = codec->rate;
	int channels = codec->channels;
	char audio_codec[64];

	talloc_free(codec->subtype_name);
	codec->subtype_name = NULL;
	talloc_free(codec->audio_name);
	codec->audio_name = NULL;

	if (payload_type != PTYPE_UNDEFINED)
		codec->payload_type = payload_type;

	if (!audio_name) {
		switch (payload_type) {
		case 0:
			audio_name = "PCMU/8000/1";
			break;
		case 3:
			audio_name = "GSM/8000/1";
			break;
		case 8:
			audio_name = "PCMA/8000/1";
			break;
		case 18:
			audio_name = "G729/8000/1";
			break;
		default:
			/* Payload type is unknown, don't change rate and
			 * channels. */
			/* TODO: return value? */
			return 0;
		}
	}

	if (sscanf(audio_name, "%63[^/]/%d/%d",
		   audio_codec, &rate, &channels) < 1)
		return -EINVAL;

	codec->rate = rate;
	codec->channels = channels;
	codec->subtype_name = talloc_strdup(ctx, audio_codec);
	codec->audio_name = talloc_strdup(ctx, audio_name);

	if (!strcmp(audio_codec, "G729")) {
		codec->frame_duration_num = 10;
		codec->frame_duration_den = 1000;
	} else {
		codec->frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM;
		codec->frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN;
	}

	if (payload_type < 0) {
		payload_type = 96;
		if (rate == 8000 && channels == 1) {
			if (!strcmp(audio_codec, "GSM"))
				payload_type = 3;
			else if (!strcmp(audio_codec, "PCMA"))
				payload_type = 8;
			else if (!strcmp(audio_codec, "PCMU"))
				payload_type = 0;
			else if (!strcmp(audio_codec, "G729"))
				payload_type = 18;
		}

		codec->payload_type = payload_type;
	}

	if (channels != 1)
		LOGP(DLMGCP, LOGL_NOTICE,
		     "Channels != 1 in SDP: '%s'\n", audio_name);

	return 0;
}

static void codecs_initialize(void *ctx, struct sdp_rtp_map *codecs, int used)
{
	int i;

	for (i = 0; i < used; ++i) {
		switch (codecs[i].payload_type) {
		case 0:
			codecs[i].codec_name = "PCMU";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		case 3:
			codecs[i].codec_name = "GSM";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		case 8:
			codecs[i].codec_name = "PCMA";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		case 18:
			codecs[i].codec_name = "G729";
			codecs[i].rate = 8000;
			codecs[i].channels = 1;
			break;
		}
	}
}

static void codecs_update(void *ctx, struct sdp_rtp_map *codecs, int used,
			  int payload, const char *audio_name)
{
	int i;

	for (i = 0; i < used; ++i) {
		char audio_codec[64];
		int rate = -1;
		int channels = -1;
		if (codecs[i].payload_type != payload)
			continue;
		if (sscanf(audio_name, "%63[^/]/%d/%d",
			   audio_codec, &rate, &channels) < 1) {
			LOGP(DLMGCP, LOGL_ERROR, "Failed to parse '%s'\n",
			     audio_name);
			continue;
		}

		codecs[i].map_line = talloc_strdup(ctx, audio_name);
		codecs[i].codec_name = talloc_strdup(ctx, audio_codec);
		codecs[i].rate = rate;
		codecs[i].channels = channels;
		return;
	}

	LOGP(DLMGCP, LOGL_ERROR, "Unconfigured PT(%d) with %s\n", payload,
	     audio_name);
}

/* Check if the codec matches what is set up in the trunk config */
static int is_codec_compatible(const struct mgcp_endpoint *endp,
			       const struct sdp_rtp_map *codec)
{
	char *codec_str;
	char audio_codec[64];

	if (!codec->codec_name)
		return 0;

	/* GSM, GSM/8000 and GSM/8000/1 should all be compatible...
	 * let's go by name first. */
	codec_str = endp->tcfg->audio_name;
	if (sscanf(codec_str, "%63[^/]/%*d/%*d", audio_codec) < 1)
		return 0;

	return strcasecmp(audio_codec, codec->codec_name) == 0;
}

/*! Analyze SDP input string.
 *  \param[in] endp trunk endpoint.
 *  \param[out] conn associated rtp connection.
 *  \param[out] caller provided memory to store the parsing results.
 *  \returns 0 on success, -1 on failure.
 *
 *  Note: In conn (conn->end) the function returns the packet duration,
 *  the rtp port and the rtcp port */
int mgcp_parse_sdp_data(const struct mgcp_endpoint *endp,
			struct mgcp_conn_rtp *conn,
			struct mgcp_parse_data *p)
{
	struct sdp_rtp_map codecs[10];
	int codecs_used = 0;
	char *line;
	int maxptime = -1;
	int i;
	int codecs_assigned = 0;
	void *tmp_ctx = talloc_new(NULL);
	struct mgcp_rtp_end *rtp;

	int payload;
	int ptime, ptime2 = 0;
	char audio_name[64];
	int port, rc;
	char ipv4[16];

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);
	OSMO_ASSERT(p);

	rtp = &conn->end;
	memset(&codecs, 0, sizeof(codecs));

	for_each_line(line, p->save) {
		switch (line[0]) {
		case 'o':
		case 's':
		case 't':
		case 'v':
			/* skip these SDP attributes */
			break;
		case 'a':
			if (sscanf(line, "a=rtpmap:%d %63s",
				   &payload, audio_name) == 2) {
				codecs_update(tmp_ctx, codecs,
					      codecs_used, payload, audio_name);
			} else
			    if (sscanf
				(line, "a=ptime:%d-%d", &ptime, &ptime2) >= 1) {
				if (ptime2 > 0 && ptime2 != ptime)
					rtp->packet_duration_ms = 0;
				else
					rtp->packet_duration_ms = ptime;
			} else if (sscanf(line, "a=maxptime:%d", &ptime2)
				   == 1) {
				maxptime = ptime2;
			}
			break;
		case 'm':
			rc = sscanf(line,
				    "m=audio %d RTP/AVP %d %d %d %d %d %d %d %d %d %d",
				    &port, &codecs[0].payload_type,
				    &codecs[1].payload_type,
				    &codecs[2].payload_type,
				    &codecs[3].payload_type,
				    &codecs[4].payload_type,
				    &codecs[5].payload_type,
				    &codecs[6].payload_type,
				    &codecs[7].payload_type,
				    &codecs[8].payload_type,
				    &codecs[9].payload_type);
			if (rc >= 2) {
				rtp->rtp_port = htons(port);
				rtp->rtcp_port = htons(port + 1);
				codecs_used = rc - 1;
				codecs_initialize(tmp_ctx, codecs, codecs_used);
			}
			break;
		case 'c':

			if (sscanf(line, "c=IN IP4 %15s", ipv4) == 1) {
				inet_aton(ipv4, &rtp->addr);
			}
			break;
		default:
			if (p->endp)
				LOGP(DLMGCP, LOGL_NOTICE,
				     "Unhandled SDP option: '%c'/%d on 0x%x\n",
				     line[0], line[0],
				     ENDPOINT_NUMBER(p->endp));
			else
				LOGP(DLMGCP, LOGL_NOTICE,
				     "Unhandled SDP option: '%c'/%d\n",
				     line[0], line[0]);
			break;
		}
	}

	/* Now select the primary and alt_codec */
	for (i = 0; i < codecs_used && codecs_assigned < 2; ++i) {
		struct mgcp_rtp_codec *codec = codecs_assigned == 0 ?
		    &rtp->codec : &rtp->alt_codec;

		if (endp->tcfg->no_audio_transcoding &&
		    !is_codec_compatible(endp, &codecs[i])) {
			LOGP(DLMGCP, LOGL_NOTICE, "Skipping codec %s\n",
			     codecs[i].codec_name);
			continue;
		}

		mgcp_set_audio_info(p->cfg, codec,
				    codecs[i].payload_type, codecs[i].map_line);
		codecs_assigned += 1;
	}

	if (codecs_assigned > 0) {
		/* TODO/XXX: Store this per codec and derive it on use */
		if (maxptime >= 0 && maxptime * rtp->codec.frame_duration_den >
		    rtp->codec.frame_duration_num * 1500) {
			/* more than 1 frame */
			rtp->packet_duration_ms = 0;
		}

		LOGP(DLMGCP, LOGL_NOTICE,
		     "Got media info via SDP: port %d, payload %d (%s), "
		     "duration %d, addr %s\n",
		     ntohs(rtp->rtp_port), rtp->codec.payload_type,
		     rtp->codec.subtype_name ? rtp->
		     codec.subtype_name : "unknown", rtp->packet_duration_ms,
		     inet_ntoa(rtp->addr));
	}

	talloc_free(tmp_ctx);
	return codecs_assigned > 0;
}

/*! Generate SDP response string.
 *  \param[in] endp trunk endpoint.
 *  \param[in] conn associated rtp connection.
 *  \param[out] sdp msg buffer to append resulting SDP string data.
 *  \param[in] addr IPV4 address string (e.g. 192.168.100.1).
 *  \returns 0 on success, -1 on failure. */
int mgcp_write_response_sdp(const struct mgcp_endpoint *endp,
			    const struct mgcp_conn_rtp *conn, struct msgb *sdp,
			    const char *addr)
{
	const char *fmtp_extra;
	const char *audio_name;
	int payload_type;
	int rc;

	OSMO_ASSERT(endp);
	OSMO_ASSERT(conn);
	OSMO_ASSERT(sdp);
	OSMO_ASSERT(addr);

	/* FIXME: constify endp and conn args in get_net_donwlink_format_cb() */
	endp->cfg->get_net_downlink_format_cb((struct mgcp_endpoint *)endp,
					      &payload_type, &audio_name,
					      &fmtp_extra,
					      (struct mgcp_conn_rtp *)conn);

	rc = msgb_printf(sdp,
			 "v=0\r\n"
			 "o=- %s 23 IN IP4 %s\r\n"
			 "s=-\r\n"
			 "c=IN IP4 %s\r\n"
			 "t=0 0\r\n", conn->conn->id, addr, addr);

	if (rc < 0)
		goto buffer_too_small;

	if (payload_type >= 0) {
		rc = msgb_printf(sdp, "m=audio %d RTP/AVP %d\r\n",
				 conn->end.local_port, payload_type);
		if (rc < 0)
			goto buffer_too_small;

		if (audio_name && endp->tcfg->audio_send_name) {
			rc = msgb_printf(sdp, "a=rtpmap:%d %s\r\n",
					 payload_type, audio_name);

			if (rc < 0)
				goto buffer_too_small;
		}

		if (fmtp_extra) {
			rc = msgb_printf(sdp, "%s\r\n", fmtp_extra);

			if (rc < 0)
				goto buffer_too_small;
		}
	}
	if (conn->end.packet_duration_ms > 0 && endp->tcfg->audio_send_ptime) {
		rc = msgb_printf(sdp, "a=ptime:%u\r\n",
				 conn->end.packet_duration_ms);
		if (rc < 0)
			goto buffer_too_small;
	}

	return 0;

buffer_too_small:
	LOGP(DLMGCP, LOGL_ERROR, "SDP messagebuffer too small\n");
	return -1;
}
