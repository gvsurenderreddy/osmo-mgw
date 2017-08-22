/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* Message parser/generator */

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
#if 0

static inline char *strline_r(char *str, char **saveptr)
{
	char *result;

	if (str)
		*saveptr = str;

	result = *saveptr;

	if (*saveptr != NULL) {
		*saveptr = strpbrk(*saveptr, "\r\n");

		if (*saveptr != NULL) {
			char *eos = *saveptr;

			if ((*saveptr)[0] == '\r' && (*saveptr)[1] == '\n')
				(*saveptr)++;
			(*saveptr)++;
			if ((*saveptr)[0] == '\0')
				*saveptr = NULL;

			*eos = '\0';
		}
	}

	return result;
}



/**
 * @returns 0 when the status line was complete and transaction_id and
 * endp out parameters are set.
 */
static int mgcp_parse_header(struct mgcp_parse_data *pdata, char *data)
{
	int i = 0;
	char *elem, *save = NULL;
	
	OSMO_ASSERT(data);
	pdata->trans = "000000";


	printf("========================> mgcp_analyze_header() data=%s\n", data);
	
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
#endif
