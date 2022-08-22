#include <wsengine/wsengine.h>

#include <wiretap/wtap.h>

int wse_dump_filetypes(cmd_reader_t cr _U_) {
    const char* name;
    const char* descr;
    gboolean writable;
    gboolean can_compress;
    GSList* exts;
    int ft = 0;
    json_dumper dumper;

    while (TRUE) {
        name = wtap_file_type_subtype_name(ft);
        if (name == NULL) {
            break;
        }
        descr = wtap_file_type_subtype_description(ft);
        writable = wtap_dump_can_open(ft);
        can_compress = wtap_dump_can_compress(ft);
        exts = wtap_get_file_extensions_list(ft, FALSE);

        memset(&dumper, 0, sizeof(json_dumper));
        dumper.output_file = stdout;
        json_dumper_begin_object(&dumper);

        json_dumper_set_member_name(&dumper, "id");
        json_dumper_value_anyf(&dumper, "%d", ft);

        json_dumper_set_member_name(&dumper, "name");
        json_dumper_value_string(&dumper, name);

        json_dumper_set_member_name(&dumper, "description");
        if (descr == NULL) {
            json_dumper_value_anyf(&dumper, "null");
        } else {
            json_dumper_value_string(&dumper, descr);
        }

        json_dumper_set_member_name(&dumper, "writable");
        json_dumper_value_anyf(&dumper, writable ? "true" : "false");

        json_dumper_set_member_name(&dumper, "compressible");
        json_dumper_value_anyf(&dumper, can_compress ? "true" : "false");

        json_dumper_set_member_name(&dumper, "extensions");
        json_dumper_begin_array(&dumper);
        while (exts != NULL) {
            if (exts->data != NULL) {
                json_dumper_value_string(&dumper, (const gchar*)exts->data);
            }
            exts = exts->next;
        }
        json_dumper_end_array(&dumper);

        json_dumper_end_object(&dumper);
        json_dumper_finish(&dumper);

        ++ft;
    }

    return 0;
}
