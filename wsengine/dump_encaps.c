#include <wsengine/wsengine.h>

#include <wiretap/wtap.h>

int wse_dump_encaps(cmd_reader_t cr _U_) {
    int num_encap_types;
    const char* name;
    const char* descr;
    json_dumper dumper;

    num_encap_types = wtap_get_num_encap_types();

    for (int encap = -1; encap < num_encap_types; ++encap) {
        name = wtap_encap_name(encap);
        descr = wtap_encap_description(encap);

        memset(&dumper, 0, sizeof(json_dumper));
        dumper.output_file = stdout;
        json_dumper_begin_object(&dumper);

        json_dumper_set_member_name(&dumper, "id");
        json_dumper_value_anyf(&dumper, "%d", encap);

        json_dumper_set_member_name(&dumper, "name");
        if (name == NULL) {
            json_dumper_value_anyf(&dumper, "null");
        } else {
            json_dumper_value_string(&dumper, name);
        }

        json_dumper_set_member_name(&dumper, "description");
        if (descr == NULL) {
            json_dumper_value_anyf(&dumper, "null");
        } else {
            json_dumper_value_string(&dumper, descr);
        }

        json_dumper_end_object(&dumper);
        json_dumper_finish(&dumper);
    }

    return 0;
}
