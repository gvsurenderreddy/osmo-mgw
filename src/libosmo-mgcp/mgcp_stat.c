/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The statistics generator */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/mgcp/mgcp_stat.h>
#include <limits.h>

/* Helper function for mgcp_format_stats_rtp() to calculate packet loss */
void calc_loss(struct mgcp_rtp_state *state,
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
	*loss = *expected - end->packets_rx;
	if (*expected < end->packets_rx) {
		if (*loss > 0)
			*loss = INT_MIN;
	} else {
		if (*loss < 0)
			*loss = INT_MAX;
	}
}

/* Helper function for mgcp_format_stats_rtp() to calculate jitter */
uint32_t calc_jitter(struct mgcp_rtp_state *state)
{
	if (!state->stats_initialized)
		return 0;
	return state->stats_jitter >> 4;
}

/* Generate statistics for an RTP connection */
static void mgcp_format_stats_rtp(char *str, size_t str_len,
				  struct mgcp_conn_rtp *conn)
{
	uint32_t expected, jitter;
	int ploss;
	int nchars;

	calc_loss(&conn->state, &conn->end, &expected, &ploss);
	jitter = calc_jitter(&conn->state);

	nchars = snprintf(str, str_len,
			  "\r\nP: PS=%u, OS=%u, PR=%u, OR=%u, PL=%d, JI=%u",
			  conn->end.packets_tx, conn->end.octets_tx,
			  conn->end.packets_rx, conn->end.octets_rx,
			  ploss, jitter);
	if (nchars < 0 || nchars >= str_len)
		goto truncate;

	str += nchars;
	str_len -= nchars;

	/* Error Counter */
	nchars = snprintf(str, str_len,
			  "\r\nX-Osmo-CP: EC TI=%u, TO=%u",
			  conn->state.in_stream.err_ts_counter,
			  conn->state.out_stream.err_ts_counter);
	if (nchars < 0 || nchars >= str_len)
		goto truncate;

	str += nchars;
	str_len -= nchars;

	if (conn->osmux.state == OSMUX_STATE_ENABLED) {
		snprintf(str, str_len,
			 "\r\nX-Osmux-ST: CR=%u, BR=%u",
			 conn->osmux.stats.chunks, conn->osmux.stats.octets);
	}

truncate:
	str[str_len - 1] = '\0';
}

/*! \brief format statistics into an mgcp parameter string
 *  \param[out] str resulting string
 *  \param[in] str_len length of the string buffer
 *  \param[in] conn connection to evaluate */
void mgcp_format_stats(char *str, size_t str_len, struct mgcp_conn *conn)
{
	memset(str, 0, str_len);
	if (!conn)
		return;

	/* NOTE: At the moment we only support generating statistics for
	 * RTP connections. However, in the future we may also want to
	 * generate statistics for other connection types as well. Lets
	 * keep this option open: */
	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		mgcp_format_stats_rtp(str, str_len, &conn->u.rtp);
		break;
	default:
		break;
	}
}
