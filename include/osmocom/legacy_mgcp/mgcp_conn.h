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

#pragma once

#include <osmocom/legacy_mgcp/mgcp_internal.h>
#include <osmocom/core/linuxlist.h>
#include <inttypes.h>

struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct llist_head *conns,
				  uint32_t id, enum mgcp_conn_type type,
				  char *name);
struct mgcp_conn *mgcp_conn_get(struct llist_head *conns, uint32_t id);
struct mgcp_conn_rtp *mgcp_conn_get_rtp(struct llist_head *conns, uint32_t id);
void mgcp_conn_free(struct llist_head *conns, uint32_t id);
void mgcp_conn_free_all(struct llist_head *conns);
char *mgcp_conn_dump(struct mgcp_conn *conn);
