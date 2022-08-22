#include <glib.h>

#include <wsengine/read_cmd.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>

#define INIT_BUFFER_SIZE (16 * 1024)

struct cmd_reader_s {
    gchar* buf;
    jsmntok_t* tokens;
    int buf_len;
    int tokens_alloc;
};

cmd_reader_t
cmd_reader_new(void) {
    cmd_reader_t cr = (cmd_reader_t)g_malloc(sizeof(struct cmd_reader_s));
    if (cr != NULL) {
        cr->buf = (gchar*)g_malloc0(INIT_BUFFER_SIZE * sizeof(gchar));
        if (cr->buf == NULL) {
            g_free(cr);
            cr = NULL;
        } else {
            cr->buf_len = INIT_BUFFER_SIZE;
            cr->tokens = NULL;
            cr->tokens_alloc = 0;
        }
    }
    return cr;
}

void cmd_reader_free(cmd_reader_t cr) {
    if (cr == NULL) return;

    if (cr->buf != NULL) {
        g_free(cr->buf);
        cr->buf_len = 0;
    }

    if (cr->tokens != NULL) {
        g_free(cr->tokens);
        cr->tokens_alloc = 0;
    }
}

static gboolean read_line(cmd_reader_t cr) {
    int pos = 0;
    while (TRUE) {
        if (pos + 1 == cr->buf_len) {
            int new_len = cr->buf_len * 2;
            cr->buf = (gchar*)g_realloc(cr->buf, new_len * sizeof(gchar));
            if (cr->buf == NULL) {
                cr->buf_len = 0;
                return FALSE;
            }
            memset(cr->buf + cr->buf_len, 0, new_len - cr->buf_len);
            cr->buf_len = new_len;
        }

        if (fgets(cr->buf, cr->buf_len, stdin) == NULL) {
            return FALSE;
        }

        gchar last = cr->buf[cr->buf_len - 2];
        if (last == '\0' || last == '\n') {
            return TRUE;
        }

        pos = cr->buf_len - 1;
    }
    return FALSE;
}

gboolean
read_cmd(cmd_reader_t cr, cmd_obj_t *cmd) {
    if (!read_line(cr)) {
        return FALSE;
    }

    int num_tokens = json_parse(cr->buf, NULL, 0);
    if (num_tokens <= 0) {
        return FALSE;
    }

    if (cr->tokens_alloc < num_tokens) {
        if (cr->tokens == NULL) {
            cr->tokens = (jsmntok_t*)g_malloc(num_tokens * sizeof(jsmntok_t));
        } else {
            cr->tokens = (jsmntok_t*)g_realloc(cr->tokens, num_tokens * sizeof(jsmntok_t));
        }
        if (cr->tokens == NULL) {
            cr->tokens_alloc = 0;
            return FALSE;
        } else {
            cr->tokens_alloc = num_tokens;
        }
    }

    if (json_parse(cr->buf, cr->tokens, cr->tokens_alloc) <= 0) {
        return FALSE;
    }

    if (cmd != NULL) {
        cmd->cr = cr;
        cmd->tok = cr->tokens;
    }
    return TRUE;
}

static
jsmntok_t *json_get_next_object(jsmntok_t *cur)
{
    int i;
    jsmntok_t *next = cur+1;

    for (i = 0; i < cur->size; i++) {
        next = json_get_next_object(next);
    }
    return next;
}

static const char* decode_string(char* str) {
    if (str[-1] == '\0') return str;

    char* dst = str;
    const char* src = str;
    char c;

    while (TRUE) {
        c = *src;
        if (c == '\"') {
            break;
        } else if (c == '\\') {
            c = *++src;
            switch (c) {
                case 'b':
                    *dst = '\b';
                    break;
                case 'f':
                    *dst = '\f';
                    break;
                case 'n':
                    *dst = '\n';
                    break;
                case 'r':
                    *dst = '\r';
                    break;
                case 't':
                    *dst = '\t';
                    break;
                case '\"':
                    *dst = '\"';
                    break;
                case '\\':
                    *dst = '\\';
                    break;
                default:
                    *dst = c;
                    break;
            }
        } else {
            *dst = c;
        }
        ++dst;
        ++src;
    }
    *dst = '\0';
    str[-1] = '\0';
    return str;
}

static char parse_b64_char(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c >= 'a' && c <= 'z') {
        return (c - 'a') + 26;
    } else if (c >= '0' && c <= '9') {
        return (c - '0') + 52;
    } else if (c == '+') {
        return 62;
    } else if (c == '/') {
        return 63;
    } else {
        return -1;
    }
}

/* base64 decode */
static const guint8* decode_bytes(char* str, int* len) {
    if (str[-1] == '\0') return str;

    const guint8* ret = (const guint8*)str;
    guint8* dst = (guint8*)str;
    const char* src = str;
    guint32 val = 0;

    char triple[] = {0, 0, 0, 0};

    while (TRUE) {
        triple[0] = parse_b64_char(*src++);
        if (triple[0] < 0) break;
        triple[1] = parse_b64_char(*src++);
        if (triple[1] < 0) break;
        triple[2] = parse_b64_char(*src++);
        if (triple[2] < 0) break;
        triple[3] = parse_b64_char(*src++);
        if (triple[3] < 0) break;

        val = (((guint32)triple[0]) << 18) | (((guint32)triple[1]) << 12) | (((guint32)triple[2]) << 6) | (guint32)triple[3];
        *dst++ = (val >> 16) & 0xFF;
        *dst++ = (val >> 8) & 0xFF;
        *dst++ = val & 0xFF;

        memset(triple, 0, sizeof(triple));
    }

    if (triple[0] >= 0 && triple[1] >= 0) {
        if (triple[2] < 0) {
            *dst++ = (((guint8)triple[0] & 0x3F) << 2) | (((guint8)triple[1] >> 4) & 0x03);
        } else if (triple[3] < 0) {
            *dst++ = (((guint8)triple[0] & 0x3F) << 2) | (((guint8)triple[1] >> 4) & 0x03);
            *dst++ = (((guint8)triple[1] & 0xF) << 4) | (((guint8)triple[2] >> 2) & 0x0F);
        }
    }

    if (len != NULL) {
        *len = dst - ret;
    }
    str[-1] = '\0';
    return ret;
}

static gboolean cmd_parse_int(const cmd_item_t* item, gint64* value) {
    char first = item->cr->buf[item->tok->start];
    if (item->tok->type == JSMN_PRIMITIVE && first != 't' && first != 'f' && first != 'n') {
        gint64 val = g_ascii_strtoll(&item->cr->buf[item->tok->start], NULL, 10);
        if (errno != 0) {
            errno = 0;
            gdouble dval = g_ascii_strtod(&item->cr->buf[item->tok->start], NULL);
            if (errno != 0) {
                return FALSE;
            }
            val = (gint64)dval;
        }
        if (value != NULL) {
            *value = val;
        }
        return TRUE;
    }
    return FALSE;
}

static gboolean cmd_parse_uint(const cmd_item_t* item, guint64* value) {
    char first = item->cr->buf[item->tok->start];
    if (item->tok->type == JSMN_PRIMITIVE && first != 't' && first != 'f' && first != 'n') {
        guint64 val = g_ascii_strtoull(&item->cr->buf[item->tok->start], NULL, 10);
        if (errno != 0) {
            errno = 0;
            gdouble dval = g_ascii_strtod(&item->cr->buf[item->tok->start], NULL);
            if (errno != 0) {
                return FALSE;
            }
            val = (guint64)dval;
        }
        if (value != NULL) {
            *value = val;
        }
        return TRUE;
    }
    return FALSE;
}

static gboolean cmd_parse_double(const cmd_item_t* item, gdouble* value) {
    char first = item->cr->buf[item->tok->start];
    if (item->tok->type == JSMN_PRIMITIVE && first != 't' && first != 'f' && first != 'n') {
        gdouble val = g_ascii_strtod(&item->cr->buf[item->tok->start], NULL);
        if (errno != 0) {
            return FALSE;
        }
        if (value != NULL) {
            *value = val;
        }
        return TRUE;
    }
    return FALSE;
}

static gboolean cmd_parse_bool(const cmd_item_t* item, gboolean* value) {
    if (item->tok->type == JSMN_PRIMITIVE) {
        if (strncmp(&item->cr->buf[item->tok->start], "true", 4) == 0) {
            if (value != NULL) {
                *value = TRUE;
            }
            return TRUE;
        } else if (strncmp(&item->cr->buf[item->tok->start], "false", 5) == 0) {
            if (value != NULL) {
                *value = FALSE;
            }
            return TRUE;
        }
    }
    return FALSE;
}

void
cmd_obj_iter(const cmd_obj_t* obj, cmd_obj_iter_t* iter) {
    assert(obj->tok->type == JSMN_OBJECT);
    iter->parent = obj;
    iter->tok = NULL;
    iter->idx = 0;
}

gboolean
cmd_obj_next(cmd_obj_iter_t* iter, const char** name, cmd_item_t* item) {
    if (iter->idx >= iter->parent->tok->size) return FALSE;

    if (iter->tok == NULL) {
        iter->tok = iter->parent->tok + 1;
    } else {
        iter->tok = json_get_next_object(item->tok);
    }

    if (name != NULL) {
        *name = decode_string(&iter->parent->cr->buf[iter->tok->start]);
    }

    if (item != NULL) {
        item->cr = iter->parent->cr;
        item->tok = iter->tok + 1;
    }

    iter->idx++;
    return TRUE;
}

void
cmd_array_iter(const cmd_array_t* array, cmd_array_iter_t* iter) {
    if (array != NULL && iter != NULL) {
        assert(array->tok->type == JSMN_ARRAY);
        iter->parent = array;
        iter->tok = NULL;
        iter->idx = 0;
    }
}

gboolean
cmd_array_next(cmd_array_iter_t* iter, cmd_item_t* item) {
    if (iter->idx >= iter->parent->tok->size) return FALSE;

    if (iter->tok == NULL) {
        iter->tok = iter->parent->tok + 1;
    } else {
        iter->tok = json_get_next_object(item->tok);
    }

    if (item != NULL) {
        item->cr = iter->parent->cr;
        item->tok = iter->tok;
    }

    iter->idx++;
    return TRUE;
}

int cmd_obj_size(const cmd_obj_t* obj) {
    return obj->tok->size;
}

gboolean cmd_obj_get(const cmd_obj_t* obj, const char* name, cmd_item_t* value) {
    cmd_obj_iter_t iter;
    cmd_obj_iter(obj, &iter);
    const char* key;
    while (cmd_obj_next(&iter, &key, value)) {
        if (strcmp(key, name) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

gboolean cmd_obj_get_obj(const cmd_obj_t* obj, const char* name, cmd_obj_t* value) {
    cmd_obj_t tmp;
    if (value == NULL) {
        value = &tmp;
    }
    return cmd_obj_get(obj, name, value) && value->tok->type == JSMN_OBJECT;
}

gboolean cmd_obj_get_array(const cmd_obj_t* obj, const char* name, cmd_array_t* value) {
    cmd_array_t tmp;
    if (value == NULL) {
        value = &tmp;
    }
    return cmd_obj_get(obj, name, value) && value->tok->type == JSMN_ARRAY;
}

gboolean cmd_obj_get_string(const cmd_obj_t* obj, const char* name, const char** value) {
    cmd_item_t tmp;
    if (cmd_obj_get(obj, name, &tmp) && tmp.tok->type == JSMN_STRING) {
        if (value != NULL) {
            *value = decode_string(&tmp.cr->buf[tmp.tok->start]);
        }
        return TRUE;
    }
    return FALSE;
}

gboolean cmd_obj_get_bytes(const cmd_obj_t* obj, const char* name, const guint8** value, int* length) {
    cmd_item_t tmp;
    if (cmd_obj_get(obj, name, &tmp) && tmp.tok->type == JSMN_STRING) {
        const guint8* val;
        if (value != NULL || length != NULL) {
            val = decode_bytes(&tmp.cr->buf[tmp.tok->start], length);
        }
        if (value != NULL) {
            *value = val;
        }
        return TRUE;
    }
    return FALSE;
}

gboolean cmd_obj_get_int(const cmd_obj_t* obj, const char* name, gint64* value) {
    cmd_item_t tmp;
    return cmd_obj_get(obj, name, &tmp) && cmd_parse_int(&tmp, value);
}

gboolean cmd_obj_get_uint(const cmd_obj_t* obj, const char* name, guint64* value) {
    cmd_item_t tmp;
    return cmd_obj_get(obj, name, &tmp) && cmd_parse_uint(&tmp, value);
}

gboolean cmd_obj_get_double(const cmd_obj_t* obj, const char* name, gdouble* value) {
    cmd_item_t tmp;
    return cmd_obj_get(obj, name, &tmp) && cmd_parse_double(&tmp, value);
}

gboolean cmd_obj_get_bool(const cmd_obj_t* obj, const char* name, gboolean* value) {
    cmd_item_t tmp;
    return cmd_obj_get(obj, name, &tmp) && cmd_parse_bool(&tmp, value);
}

int cmd_array_length(const cmd_array_t* array) {
    return array->tok->size;
}

gboolean cmd_array_get(const cmd_array_t* array, int index, cmd_item_t* value) {
    if (array->tok->size <= index) {
        return FALSE;
    }
    cmd_array_iter_t iter;
    cmd_array_iter(array, &iter);
    for (int i = 0; i < index; ++i) {
        if (!cmd_array_next(&iter, NULL)) {
            return FALSE;
        }
    }
    return cmd_array_next(&iter, value);
}

gboolean cmd_array_get_obj(const cmd_array_t* array, int index, cmd_obj_t* value) {
    cmd_obj_t tmp;
    if (value == NULL) {
        value = &tmp;
    }
    return cmd_array_get(array, index, value) && value->tok->type == JSMN_OBJECT;
}

gboolean cmd_array_get_array(const cmd_array_t* array, int index, cmd_array_t* value) {
    cmd_array_t tmp;
    if (value == NULL) {
        value = &tmp;
    }
    return cmd_array_get(array, index, value) && value->tok->type == JSMN_ARRAY;
}

gboolean cmd_array_get_string(const cmd_array_t* array, int index, const char** value) {
    cmd_item_t tmp;
    if (cmd_array_get(array, index, &tmp) && tmp.tok->type == JSMN_STRING) {
        if (value != NULL) {
            *value = decode_string(&tmp.cr->buf[tmp.tok->start]);
        }
        return TRUE;
    }
    return FALSE;
}

gboolean cmd_array_get_bytes(const cmd_array_t* array, int index, const guint8** value, int* length) {
    cmd_item_t tmp;
    if (cmd_array_get(array, index, &tmp) && tmp.tok->type == JSMN_STRING) {
        const guint8* val;
        if (value != NULL || length != NULL) {
            val = decode_bytes(&tmp.cr->buf[tmp.tok->start], length);
        }
        if (value != NULL) {
            *value = val;
        }
        return TRUE;
    }
    return FALSE;
}

gboolean cmd_array_get_int(const cmd_array_t* array, int index, gint64* value) {
    cmd_item_t tmp;
    return cmd_array_get(array, index, &tmp) && cmd_parse_int(&tmp, value);
}

gboolean cmd_array_get_uint(const cmd_array_t* array, int index, guint64* value) {
    cmd_item_t tmp;
    return cmd_array_get(array, index, &tmp) && cmd_parse_uint(&tmp, value);
}

gboolean cmd_array_get_double(const cmd_array_t* array, int index, gdouble* value) {
    cmd_item_t tmp;
    return cmd_array_get(array, index, &tmp) && cmd_parse_double(&tmp, value);
}

gboolean cmd_array_get_bool(const cmd_array_t* array, int index, gboolean* value) {
    cmd_item_t tmp;
    return cmd_array_get(array, index, &tmp) && cmd_parse_bool(&tmp, value);
}

cmd_item_types cmd_item_type(const cmd_item_t* item) {
    switch (item->tok->type) {
        case JSMN_OBJECT:
            return CMD_ITEM_OBJECT;
        case JSMN_ARRAY:
            return CMD_ITEM_ARRAY;
        case JSMN_STRING:
            return CMD_ITEM_STRING;
        case JSMN_PRIMITIVE:
            break;
        default:
            return CMD_ITEM_UNDEFINED;
    }

    switch (item->cr->buf[item->tok->start]) {
        case 't':
        case 'f':
            return CMD_ITEM_BOOL;
        case 'n':
            return CMD_ITEM_NULL;
        default:
            break;
    }

    return CMD_ITEM_NUMBER;
}

gboolean cmd_item_is_null(const cmd_item_t* item) {
    return item->tok->type == JSMN_PRIMITIVE && strncmp(&item->cr->buf[item->tok->start], "null", 4) == 0;
}

const cmd_obj_t* cmd_item_get_obj(const cmd_item_t* item) {
    return item->tok->type == JSMN_OBJECT ? item : NULL;
}

const cmd_array_t* cmd_item_get_array(const cmd_item_t* item) {
    return item->tok->type == JSMN_ARRAY ? item : NULL;
}

const char* cmd_item_get_string(const cmd_item_t* item) {
    if (item->tok->type != JSMN_STRING) return NULL;
    return decode_string(&item->cr->buf[item->tok->start]);
}

const guint8* cmd_item_get_bytes(const cmd_item_t* item, int* length) {
    if (item->tok->type != JSMN_STRING) return NULL;
    return decode_bytes(&item->cr->buf[item->tok->start], length);
}

gint64 cmd_item_get_int(const cmd_item_t* item) {
    gint64 val;
    if (!cmd_parse_int(item, &val)) {
        val = 0;
    }
    return val;
}

guint64 cmd_item_get_uint(const cmd_item_t* item) {
    guint64 val;
    if (!cmd_parse_uint(item, &val)) {
        val = 0;
    }
    return val;
}

gdouble cmd_item_get_double(const cmd_item_t* item) {
    gdouble val;
    if (!cmd_parse_double(item, &val)) {
        val = 0;
    }
    return val;
}

gboolean cmd_item_get_bool(const cmd_item_t* item) {
    gboolean val;
    if (!cmd_parse_bool(item, &val)) {
        val = FALSE;
    }
    return val;
}

