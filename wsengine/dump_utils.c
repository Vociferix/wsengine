#include <wsengine/dump_utils.h>

void json_dumper_value_null(json_dumper* dumper) {
    json_dumper_value_anyf(dumper, "null");
}

void json_dumper_value_bool(json_dumper* dumper, gboolean value) {
    if (value)
        json_dumper_value_true(dumper);
    else
        json_dumper_value_false(dumper);
}

void json_dumper_value_true(json_dumper* dumper) {
    json_dumper_value_anyf(dumper, "true");
}

void json_dumper_value_false(json_dumper* dumper) {
    json_dumper_value_anyf(dumper, "false");
}

void json_dumper_value_int(json_dumper* dumper, gint64 value) {
    json_dumper_value_anyf(dumper, "%" G_GINT64_FORMAT, value);
}

void json_dumper_value_uint(json_dumper* dumper, guint64 value) {
    json_dumper_value_anyf(dumper, "%" G_GUINT64_FORMAT, value);
}

void json_dumper_value_stringn(json_dumper* dumper, const char* value, size_t len) {
    gchar* tmp = g_strndup(value, len);
    json_dumper_value_string(dumper, tmp);
    g_free(tmp);
}

void json_dumper_value_bytes(json_dumper* dumper, const guchar* value, size_t len) {
    json_dumper_begin_base64(dumper);
    json_dumper_write_base64(dumper, value, len);
    json_dumper_end_base64(dumper);
}

void json_dumper_value_gbytes(json_dumper* dumper, GBytes* value) {
    const guchar* data;
    gsize len;
    data = (const guchar*)g_bytes_get_data(value, &len);
    json_dumper_value_bytes(dumper, data, len);
}

void json_dumper_value_ipv4(json_dumper* dumper, const ws_in4_addr* value) {
    gchar addr_buf[WS_INET_ADDRSTRLEN];
    json_dumper_value_string(dumper, ws_inet_ntop4(value, addr_buf, sizeof(addr_buf)));
}

void json_dumper_value_ipv6(json_dumper* dumper, const ws_in6_addr* value) {
    gchar addr_buf[WS_INET6_ADDRSTRLEN];
    json_dumper_value_string(dumper, ws_inet_ntop6(value, addr_buf, sizeof(addr_buf)));
}
