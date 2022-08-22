/* wsengine/wsengine.h
 *
 * Copyright (C) 2022 Jack Bernard
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSENGINE_WSENGINE_H
#define __WSENGINE_WSENGINE_H

#include <file.h>
#include <wiretap/wtap_opttypes.h>
#include <wsutil/json_dumper.h>
#include <wsengine/read_cmd.h>

#define WSE_MODE_DUMP_VERSION "dump-version"
#define WSE_MODE_READ_FILE "read-file"
#define WSE_MODE_WRITE_FILE "write-file"
#define WSE_MODE_DUMP_FILETYPES "dump-filetypes"

#define WSE_DISSECT_FLAG_NULL       0x00u
#define WSE_DISSECT_FLAG_BYTES      0x01u
#define WSE_DISSECT_FLAG_COLUMNS    0x02u
#define WSE_DISSECT_FLAG_PROTO_TREE 0x04u
#define WSE_DISSECT_FLAG_COLOR      0x08u

typedef void (*wse_dissect_func_t)(epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data);

cf_status_t wse_cf_open(const char *fname, unsigned int type, gboolean is_tempfile, int *err);
int wse_load_cap_file(void);
int wse_retap(void);
int wse_filter(const char *dftext, guint8 **result);
frame_data *wse_get_frame(guint32 framenum);
enum dissect_request_status {
  DISSECT_REQUEST_SUCCESS,
  DISSECT_REQUEST_NO_SUCH_FRAME,
  DISSECT_REQUEST_READ_ERROR
};
enum dissect_request_status
wse_dissect_request(guint32 framenum, guint32 frame_ref_num,
                       guint32 prev_dis_num, wtap_rec *rec, Buffer *buf,
                       column_info *cinfo, guint32 dissect_flags,
                       wse_dissect_func_t cb, void *data,
                       int *err, gchar **err_info);
wtap_block_t wse_get_modified_block(const frame_data *fd);
wtap_block_t wse_get_packet_block(const frame_data *fd);
int wse_set_modified_block(frame_data *fd, wtap_block_t new_block);
const char *wse_version(void);

int wse_dump_version(cmd_reader_t cr);
int wse_read_file(cmd_reader_t cr);
int wse_write_file(cmd_reader_t cr);
int wse_dump_filetypes(cmd_reader_t cr);

#endif /* __WSENGINE_WSENGINE_H */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
