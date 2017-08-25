/* Message connection list handling */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/legacy_mgcp/mgcp_conn.h>

/*! \brief allocate a new connection list entry
 *  \param[in] ctx talloc context
 *  \param[in] conns list with connections
 *  \param[in] id identification number of the connection
 *  \param[in] type connection type (e.g. MGCP_CONN_TYPE_RTP)
 *  \returns pointer to allocated connection, NULL on error */
struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct llist_head *conns,
				  uint32_t id, enum mgcp_conn_type type,
				  char *name)
{
	struct mgcp_conn *conn;
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL);
	OSMO_ASSERT(strlen(name) < sizeof(conn->name));

	/* Do not allow more then two connections */
	if (llist_count(conns) >= 2)
		return NULL;

	/* Prevent duplicate connection IDs */
	if (mgcp_conn_get(conns, id))
		return NULL;

	/* Create new connection and add it to the list */
	conn = talloc_zero(ctx, struct mgcp_conn);
	if (!conn)
		return NULL;
	conn->type = type;
	conn->id = id;
	conn->u.rtp.conn = conn;
	strcpy(conn->name, name);
	llist_add(&conn->entry, conns);

	return conn;
}

/*! \brief find a connection by its ID
 *  \param[in] conns list with connections
 *  \param[in] id identification number of the connection
 *  \returns pointer to allocated connection, NULL if not found */
struct mgcp_conn *mgcp_conn_get(struct llist_head *conns, uint32_t id)
{
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL);

	struct mgcp_conn *conn;

	llist_for_each_entry(conn, conns, entry) {
		if (conn->id == id)
			return conn;
	}

	return NULL;
}

/*! \brief find a connection by its ID and type
 *  \param[in] conns list with connections
 *  \param[in] id identification number of the connection
 *  \returns pointer to allocated connection, NULL if not found */
struct mgcp_conn_rtp *mgcp_conn_get_rtp(struct llist_head *conns, uint32_t id)
{
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL);

	struct mgcp_conn *conn;

	conn = mgcp_conn_get(conns, id);
	if (!conn)
		return NULL;

	if (conn->type == MGCP_CONN_TYPE_RTP)
		return &conn->u.rtp;

	/* FIXME: This exit() will end the program when
	 * should we ever try to access a non existant
	 * connection. Remove this exit() when we are
	 * confident about the connection handling */
	exit(1);

	return NULL;
}

/*! \brief free a connection by its ID
 *  \param[in] conns list with connections
 *  \param[in] id identification number of the connection */
void mgcp_conn_free(struct llist_head *conns, uint32_t id)
{
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL);

	struct mgcp_conn *conn;

	conn = mgcp_conn_get(conns, id);
	if (!conn)
		return;

	llist_del(&conn->entry);
	talloc_free(conn);
}

/*! \brief free all connections at once
 *  \param[in] conns list with connections */
void mgcp_conn_free_all(struct llist_head *conns)
{
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL);

	struct mgcp_conn *conn;
	struct mgcp_conn *conn_tmp;

	/* Drop all items in the list */
	llist_for_each_entry_safe(conn, conn_tmp, conns, entry) {
		llist_del(&conn->entry);
		talloc_free(conn);
	}

	return;
}

/*! \brief dump basic connection information to human readble string
 *  \param[in] conn to dump
 *  \returns human readble string */
char *mgcp_conn_dump(struct mgcp_conn *conn)
{
	static char str[256];

	if (!conn) {
		snprintf(str, sizeof(str), "(null connection)");
		return str;
	}

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		/* Dump RTP connection */
		snprintf(str, sizeof(str), "(name: %s, type:rtp, id:%u, addr:%s, "
			 "rtp_port:%u rtcp_port:%u, rx:%u, tx:%u)",
			 conn->name,
			 conn->id,
			 inet_ntoa(conn->u.rtp.end.addr),
			 ntohs(conn->u.rtp.end.rtp_port),
			 ntohs(conn->u.rtp.end.rtcp_port),
			 conn->u.rtp.end.packets_rx,
			 conn->u.rtp.end.packets_tx);
		break;

	default:
		/* Should not happen, we should be able to dump
		 * every possible connection type. */
		snprintf(str, sizeof(str), "(unknown connection type)");
		break;
	}

	return str;
}
