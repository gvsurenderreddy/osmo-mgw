/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* Message parser/generator utilities */

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

#include <limits.h>

#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_msg.h>

/*! \brief Display an mgcp message on the log output.
 *  \param[in] message mgcp message string
 *  \param[in] len message mgcp message string length
 *  \param[in] preamble string to display in logtext in front of each line */
void mgcp_disp_msg(unsigned char *message, unsigned int len, char *preamble)
{
	unsigned char line[80];
	unsigned char *ptr;
	unsigned int consumed = 0;
	unsigned int consumed_line = 0;
	unsigned int line_count = 0;

	if (!log_check_level(DLMGCP, LOGL_DEBUG))
		return;

	while (1) {
		memset(line, 0, sizeof(line));
		ptr = line;
		consumed_line = 0;
		do {
			if (*message != '\n' && *message != '\r') {
				*ptr = *message;
				ptr++;
			}
			message++;
			consumed++;
			consumed_line++;
		} while (*message != '\n' && consumed < len
			 && consumed_line < sizeof(line));

		if (strlen((const char *)line)) {
			LOGP(DLMGCP, LOGL_DEBUG, "%s: line #%02u: %s\n",
			     preamble, line_count, line);
			line_count++;
		}

		if (consumed >= len)
			return;
	}
}

/*! \brief Parse connection mode.
 *  \param[in] mode as string (recvonly, sendrecv, sendonly or loopback)
 *  \param[in] endp pointer to endpoint (only used for log output)
 *  \param[out] associated connection to be modified accordingly
 *  \returns 0 on success, -1 on error */
int mgcp_parse_conn_mode(const char *mode, struct mgcp_endpoint *endp,
			 struct mgcp_conn *conn)
{
	int ret = 0;

	if (!mode)
		return -1;
	if (!conn)
		return -1;
	if (!endp)
		return -1;

	if (strcmp(mode, "recvonly") == 0)
		conn->mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(mode, "sendrecv") == 0)
		conn->mode = MGCP_CONN_RECV_SEND;
	else if (strcmp(mode, "sendonly") == 0)
		conn->mode = MGCP_CONN_SEND_ONLY;
	else if (strcmp(mode, "loopback") == 0)
		conn->mode = MGCP_CONN_LOOPBACK;
	else {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x unknown connection mode: '%s'\n",
		     ENDPOINT_NUMBER(endp), mode);
		ret = -1;
	}

	/* Special handling für RTP connections */
	if (conn->type == MGCP_CONN_TYPE_RTP) {
		conn->u.rtp.end.output_enabled =
		    conn->mode & MGCP_CONN_SEND_ONLY ? 1 : 0;
	}

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:%x conn:%s\n",
	     ENDPOINT_NUMBER(endp), mgcp_conn_dump(conn));

	LOGP(DLMGCP, LOGL_DEBUG,
	     "endpoint:%x connection mode '%s' %d\n",
	     ENDPOINT_NUMBER(endp), mode, conn->mode);

	/* Special handling für RTP connections */
	if (conn->type == MGCP_CONN_TYPE_RTP) {
		LOGP(DLMGCP, LOGL_DEBUG, "endpoint:%x output_enabled %d\n",
		     ENDPOINT_NUMBER(endp), conn->u.rtp.end.output_enabled);
	}

	/* The VTY might change the connection mode at any time, so we have
	 * to hold a copy of the original connection mode */
	conn->mode_orig = conn->mode;

	return ret;
}

/* We have a null terminated string with the endpoint name here. We only
 * support two kinds. Simple ones as seen on the BSC level and the ones
 * seen on the trunk side. (helper function for find_endpoint()) */
static struct mgcp_endpoint *find_e1_endpoint(struct mgcp_config *cfg,
					      const char *mgcp)
{
	char *rest = NULL;
	struct mgcp_trunk_config *tcfg;
	int trunk, endp;

	trunk = strtoul(mgcp + 6, &rest, 10);
	if (rest == NULL || rest[0] != '/' || trunk < 1) {
		LOGP(DLMGCP, LOGL_ERROR, "Wrong trunk name '%s'\n", mgcp);
		return NULL;
	}

	endp = strtoul(rest + 1, &rest, 10);
	if (rest == NULL || rest[0] != '@') {
		LOGP(DLMGCP, LOGL_ERROR, "Wrong endpoint name '%s'\n", mgcp);
		return NULL;
	}

	/* signalling is on timeslot 1 */
	if (endp == 1)
		return NULL;

	tcfg = mgcp_trunk_num(cfg, trunk);
	if (!tcfg) {
		LOGP(DLMGCP, LOGL_ERROR, "The trunk %d is not declared.\n",
		     trunk);
		return NULL;
	}

	if (!tcfg->endpoints) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Endpoints of trunk %d not allocated.\n", trunk);
		return NULL;
	}

	if (endp < 1 || endp >= tcfg->number_endpoints) {
		LOGP(DLMGCP, LOGL_ERROR, "Failed to find endpoint '%s'\n",
		     mgcp);
		return NULL;
	}

	return &tcfg->endpoints[endp];
}

/* Search the endpoint pool for the endpoint that had been selected via the
 * MGCP message (helper function for mgcp_analyze_header()) */
static struct mgcp_endpoint *find_endpoint(struct mgcp_config *cfg,
					   const char *mgcp)
{
	char *endptr = NULL;
	unsigned int gw = INT_MAX;

	if (strncmp(mgcp, "ds/e1", 5) == 0)
		return find_e1_endpoint(cfg, mgcp);

	gw = strtoul(mgcp, &endptr, 16);
	if (gw > 0 && gw < cfg->trunk.number_endpoints && endptr[0] == '@')
		return &cfg->trunk.endpoints[gw];

	LOGP(DLMGCP, LOGL_ERROR, "Not able to find the endpoint: '%s'\n", mgcp);
	return NULL;
}

/*! \brief Analyze and parse the the hader of an MGCP messeage string.
 *  \param[out] pdata caller provided memory to store the parsing results
 *  \param[in] data mgcp message string
 *  \returns when the status line was complete and transaction_id and
 *  endp out parameters are set, -1 on error */
int mgcp_parse_header(struct mgcp_parse_data *pdata, char *data)
{
	int i = 0;
	char *elem, *save = NULL;

	/*! This function will parse the header part of the received
	 *  MGCP message. The parsing results are stored in pdata.
	 *  The function will also automatically search the pool with
	 *  available endpoints in order to find an endpoint that matches
	 *  the endpoint string in in the header */

	OSMO_ASSERT(data);
	pdata->trans = "000000";

	for (elem = strtok_r(data, " ", &save); elem;
	     elem = strtok_r(NULL, " ", &save)) {
		switch (i) {
		case 0:
			pdata->trans = elem;
			break;
		case 1:
			pdata->endp = find_endpoint(pdata->cfg, elem);
			if (!pdata->endp) {
				LOGP(DLMGCP, LOGL_ERROR,
				     "Unable to find Endpoint `%s'\n", elem);
				return -1;
			}
			break;
		case 2:
			if (strcmp("MGCP", elem)) {
				LOGP(DLMGCP, LOGL_ERROR,
				     "MGCP header parsing error\n");
				return -1;
			}
			break;
		case 3:
			if (strcmp("1.0", elem)) {
				LOGP(DLMGCP, LOGL_ERROR, "MGCP version `%s' "
				     "not supported\n", elem);
				return -1;
			}
			break;
		}
		i++;
	}

	if (i != 4) {
		LOGP(DLMGCP, LOGL_ERROR, "MGCP status line too short.\n");
		pdata->trans = "000000";
		pdata->endp = NULL;
		return -1;
	}

	return 0;
}

/*! \brief Extract OSMUX CID from an MGCP parameter line (string)
 *  \param[in] line single parameter line from the MGCP message
 *  \returns OSMUX CID, -1 on error */
int mgcp_parse_osmux_cid(const char *line)
{
	int osmux_cid;

	if (sscanf(line + 2, "Osmux: %u", &osmux_cid) != 1)
		return -1;

	if (osmux_cid > OSMUX_CID_MAX) {
		LOGP(DLMGCP, LOGL_ERROR, "Osmux ID too large: %u > %u\n",
		     osmux_cid, OSMUX_CID_MAX);
		return -1;
	}
	LOGP(DLMGCP, LOGL_DEBUG, "bsc-nat offered Osmux CID %u\n", osmux_cid);

	return osmux_cid;
}

/*! \brief Check MGCP parameter line (string) for plausibility
 *  \param[in] endp pointer to endpoint (only used for log output)
 *  \param[in] line single parameter line from the MGCP message
 *  \returns 1 when line seems plausible, 0 on error */
int mgcp_check_param(const struct mgcp_endpoint *endp, const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] != '\0' && line_len < 2) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "Wrong MGCP option format: '%s' on 0x%x\n",
		     line, ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* FIXME: A couple more checks wouldn't hurt... */

	return 1;
}

/*! \brief Check if the specified callid seems plausible
  * \param[in] endp pointer to endpoint
  * \param{in] callid to verify
  * \returns 1 when callid seems plausible, 0 on error */
int mgcp_verify_call_id(struct mgcp_endpoint *endp, const char *callid)
{

	/*! This function compares the supplied callid with the called that is
	 *  stored in the endpoint structure. */

	if (strcmp(endp->callid, callid) != 0) {
		LOGP(DLMGCP, LOGL_ERROR,
		     "endpoint:%x CallIDs does not match '%s' != '%s'\n",
		     ENDPOINT_NUMBER(endp), endp->callid, callid);
		return -1;
	}

	return 0;
}

/*! \brief Check if the specified connection id seems plausible
  * \param[in] endp pointer to endpoint
  * \param{in] connection id to verify
  * \returns 1 when connection id seems plausible, 0 on error */
int mgcp_verify_ci(struct mgcp_endpoint *endp, const char *ci)
{
	uint32_t id = strtoul(ci, NULL, 10);

	if (mgcp_conn_get(&endp->conns, id))
		return 0;

	LOGP(DLMGCP, LOGL_ERROR,
	     "endpoint:%x No connection found under ConnectionIdentifier %u\n",
	     ENDPOINT_NUMBER(endp), id);

	return -1;
}
