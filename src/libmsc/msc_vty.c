/* MSC interface to quagga VTY */
/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 * Based on OpenBSC interface to quagga VTY (libmsc/vty_interface_layer3.c)
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
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

/* NOTE: I would have liked to call this the MSC_NODE instead of the MSC_NODE,
 * but MSC_NODE already exists to configure a remote MSC for osmo-bsc. */

#include "../../bscconfig.h"

#include <inttypes.h>

#include <osmocom/vty/command.h>
#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <openbsc/vty.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/vlr.h>

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

DEFUN(cfg_msc, cfg_msc_cmd,
      "msc", "Configure MSC options")
{
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_assign_tmsi, cfg_msc_assign_tmsi_cmd,
      "assign-tmsi",
      "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->vlr->cfg.assign_tmsi = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_no_assign_tmsi, cfg_msc_no_assign_tmsi_cmd,
      "no assign-tmsi",
      NO_STR "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->vlr->cfg.assign_tmsi = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_instance_a,
      cfg_msc_cs7_instance_a_cmd,
      "cs7-instance-a <0-15>",
      "Set SS7 to be used by the A-Interface.\n" "SS7 instance reference number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->a.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_instance_iu,
      cfg_msc_cs7_instance_iu_cmd,
      "cs7-instance-iu <0-15>",
      "Set SS7 to be used by the Iu-Interface.\n" "SS7 instance reference number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->iu.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
}

static int config_write_msc(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "msc%s", VTY_NEWLINE);
	vty_out(vty, " %sassign-tmsi%s",
		gsmnet->vlr->cfg.assign_tmsi? "" : "no ", VTY_NEWLINE);

	vty_out(vty, " cs7-instance-a %u%s", gsmnet->a.cs7_instance,
		VTY_NEWLINE);
	vty_out(vty, " cs7-instance-iu %u%s", gsmnet->iu.cs7_instance,
		VTY_NEWLINE);

	mgcpgw_client_config_write(vty, " ");
#ifdef BUILD_IU
	ranap_iu_vty_config_write(vty, " ");
#endif

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "network%s", VTY_NEWLINE);
	vty_out(vty, " network country code %u%s", gsmnet->country_code, VTY_NEWLINE);
	vty_out(vty, " mobile network code %u%s", gsmnet->network_code, VTY_NEWLINE);
	vty_out(vty, " short name %s%s", gsmnet->name_short, VTY_NEWLINE);
	vty_out(vty, " long name %s%s", gsmnet->name_long, VTY_NEWLINE);
	vty_out(vty, " auth policy %s%s", gsm_auth_policy_name(gsmnet->auth_policy), VTY_NEWLINE);
	vty_out(vty, " location updating reject cause %u%s",
		gsmnet->reject_cause, VTY_NEWLINE);
	vty_out(vty, " encryption a5 %u%s", gsmnet->a5_encryption, VTY_NEWLINE);
	vty_out(vty, " rrlp mode %s%s", rrlp_mode_name(gsmnet->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, " mm info %u%s", gsmnet->send_mm_info, VTY_NEWLINE);
	if (gsmnet->tz.override != 0) {
		if (gsmnet->tz.dst)
			vty_out(vty, " timezone %d %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, gsmnet->tz.dst,
				VTY_NEWLINE);
		else
			vty_out(vty, " timezone %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, VTY_NEWLINE);
	}
	if (gsmnet->t3212 == 0)
		vty_out(vty, " no periodic location update%s", VTY_NEWLINE);
	else
		vty_out(vty, " periodic location update %u%s",
			gsmnet->t3212 * 6, VTY_NEWLINE);

	return CMD_SUCCESS;
}

void msc_vty_init(struct gsm_network *msc_network)
{
	common_cs_vty_init(msc_network, config_write_net);

	install_element(CONFIG_NODE, &cfg_msc_cmd);
	install_node(&msc_node, config_write_msc);
	vty_install_default(MSC_NODE);
	install_element(MSC_NODE, &cfg_msc_assign_tmsi_cmd);
	install_element(MSC_NODE, &cfg_msc_no_assign_tmsi_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_instance_a_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_instance_iu_cmd);

	mgcpgw_client_vty_init(MSC_NODE, &msc_network->mgcpgw.conf);
#ifdef BUILD_IU
	ranap_iu_vty_init(MSC_NODE, &msc_network->iu.rab_assign_addr_enc);
#endif
}
