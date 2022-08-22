/* wsengine/read_cmd.h
 *
 * Copyright (C) 2022 Jack Bernard
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSENGINE_READ_CMD_H
#define __WSENGINE_READ_CMD_H

#include <wsutil/wsjson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmd_reader_s *cmd_reader_t;

typedef enum {
    CMD_ITEM_UNDEFINED,
    CMD_ITEM_OBJECT,
    CMD_ITEM_ARRAY,
    CMD_ITEM_STRING,
    CMD_ITEM_NUMBER,
    CMD_ITEM_BOOL,
    CMD_ITEM_NULL
} cmd_item_types;

typedef struct {
    cmd_reader_t cr;
    jsmntok_t *tok;
} cmd_item_t, cmd_obj_t, cmd_array_t;

typedef struct {
    const cmd_item_t* parent;
    jsmntok_t *tok;
    int idx;
} cmd_obj_iter_t, cmd_array_iter_t;

cmd_reader_t cmd_reader_new(void);
void cmd_reader_free(cmd_reader_t cr);
gboolean read_cmd(cmd_reader_t cr, cmd_obj_t *cmd);

int cmd_obj_size(const cmd_obj_t* obj);
gboolean cmd_obj_get(const cmd_obj_t* obj, const char* name, cmd_item_t* value);
gboolean cmd_obj_get_obj(const cmd_obj_t* obj, const char* name, cmd_obj_t* value);
gboolean cmd_obj_get_array(const cmd_obj_t* obj, const char* name, cmd_array_t* value);
gboolean cmd_obj_get_string(const cmd_obj_t* obj, const char* name, const char** value);
gboolean cmd_obj_get_bytes(const cmd_obj_t* obj, const char* name, const guint8** value, int* length);
gboolean cmd_obj_get_int(const cmd_obj_t* obj, const char* name, gint64* value);
gboolean cmd_obj_get_uint(const cmd_obj_t* obj, const char* name, guint64* value);
gboolean cmd_obj_get_double(const cmd_obj_t* obj, const char* name, gdouble* value);
gboolean cmd_obj_get_bool(const cmd_obj_t* obj, const char* name, gboolean* value);

int cmd_array_length(const cmd_array_t* array);
gboolean cmd_array_get(const cmd_array_t* array, int index, cmd_item_t* value);
gboolean cmd_array_get_obj(const cmd_array_t* array, int index, cmd_obj_t* value);
gboolean cmd_array_get_array(const cmd_array_t* array, int index, cmd_array_t* value);
gboolean cmd_array_get_string(const cmd_array_t* array, int index, const char** value);
gboolean cmd_array_get_bytes(const cmd_array_t* array, int index, const guint8** value, int* length);
gboolean cmd_array_get_int(const cmd_array_t* array, int index, gint64* value);
gboolean cmd_array_get_uint(const cmd_array_t* array, int index, guint64* value);
gboolean cmd_array_get_double(const cmd_array_t* array, int index, gdouble* value);
gboolean cmd_array_get_bool(const cmd_array_t* array, int index, gboolean* value);

cmd_item_types cmd_item_type(const cmd_item_t* item);
gboolean cmd_item_is_null(const cmd_item_t* item);
const cmd_obj_t* cmd_item_get_obj(const cmd_item_t* item);
const cmd_array_t* cmd_item_get_array(const cmd_item_t* item);
const char* cmd_item_get_string(const cmd_item_t* item);
const guint8* cmd_item_get_bytes(const cmd_item_t* item, int* length);
gint64 cmd_item_get_int(const cmd_item_t* item);
guint64 cmd_item_get_uint(const cmd_item_t* item);
gdouble cmd_item_get_double(const cmd_item_t* item);
gboolean cmd_item_get_bool(const cmd_item_t* item);

void cmd_obj_iter(const cmd_obj_t* obj, cmd_obj_iter_t* iter);
gboolean cmd_obj_next(cmd_obj_iter_t* iter, const char** name, cmd_item_t* item);

void cmd_array_iter(const cmd_array_t* array, cmd_array_iter_t* iter);
gboolean cmd_array_next(cmd_array_iter_t* iter, cmd_item_t* item);

#ifdef __cplusplus
}
#endif

#endif /* __WSENGINE_READ_CMD_H */

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
