/* wsengine/dump_utils.h
 *
 * Copyright (C) 2022 Jack Bernard
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSENGINE_DUMP_UTILS_H
#define __WSENGINE_DUMP_UTILS_H

#include <wsutil/json_dumper.h>
#include <wsutil/inet_addr.h>

void json_dumper_value_null(json_dumper* dumper);

void json_dumper_value_bool(json_dumper* dumper, gboolean value);

void json_dumper_value_true(json_dumper* dumper);

void json_dumper_value_false(json_dumper* dumper);

void json_dumper_value_int(json_dumper* dumper, gint64 value);

void json_dumper_value_uint(json_dumper* dumper, guint64 value);

void json_dumper_value_stringn(json_dumper* dumper, const char* value, size_t len);

void json_dumper_value_bytes(json_dumper* dumper, const guchar* value, size_t len);

void json_dumper_value_gbytes(json_dumper* dumper, GBytes* value);

void json_dumper_value_ipv4(json_dumper* dumper, const ws_in4_addr* value);

void json_dumper_value_ipv6(json_dumper* dumper, const ws_in6_addr* value);

#endif /* __WSENGINE_DUMP_UTILS_H */

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
