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
				  uint32_t id, enum mgcp_conn_type type)
{
	struct mgcp_conn *conn;
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL)

	/* Prevent duplicate connection IDs */
	if (mgcp_conn_get(conns, id))
		return NULL;

	/* Create new connection and add it to the list */
	conn = talloc_zero(ctx, struct mgcp_conn);
	if (!conn)
		return NULL;
	conn->type = type;
	conn->id = id;
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
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL)

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
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL)

	struct mgcp_conn *conn;

	conn = mgcp_conn_get(conns, id);
	if (!conn)
		return NULL;

	if (conn->type == MGCP_CONN_TYPE_RTP)
		return &conn->u.rtp;
	exit(1);
	return NULL;
}

/*! \brief free a connection by its ID
 *  \param[in] conns list with connections
 *  \param[in] id identification number of the connection */
void mgcp_conn_free(struct llist_head *conns, uint32_t id)
{
	OSMO_ASSERT(conns);
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL)

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
	OSMO_ASSERT(conns->next != NULL && conns->prev != NULL)

	struct mgcp_conn *conn;
	struct mgcp_conn *conn_tmp;

	/* Drop all items in the list */
	llist_for_each_entry_safe(conn, conn_tmp, conns, entry) {
		llist_del(&conn->entry);
		talloc_free(conn);
	}

	return;
}
