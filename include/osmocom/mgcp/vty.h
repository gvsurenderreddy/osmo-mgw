#ifndef OPENBSC_VTY_H
#define OPENBSC_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

struct gsm_network;
struct vty;

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *);

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base);

extern struct cmd_element cfg_description_cmd;
extern struct cmd_element cfg_no_description_cmd;

enum mgcp_vty_node {
	MGCP_NODE = _LAST_OSMOVTY_NODE + 1,
	TRUNK_NODE,
};

struct log_info;
int bsc_vty_init(struct gsm_network *network);
int bsc_vty_init_extra(void);

void msc_vty_init(struct gsm_network *msc_network);

struct gsm_network *gsmnet_from_vty(struct vty *vty);

#endif
