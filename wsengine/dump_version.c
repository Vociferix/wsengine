#include <wsengine/wsengine.h>
#include <ui/version_info.h>

int wse_dump_version(cmd_reader_t cr _U_) {
    int major, minor, micro;
    json_dumper dumper;
    memset(&dumper, 0, sizeof(json_dumper));
    dumper.output_file = stdout;
    get_ws_version_number(&major, &minor, &micro);
    json_dumper_begin_object(&dumper);
    json_dumper_set_member_name(&dumper, "major");
    json_dumper_value_anyf(&dumper, "%d", major);
    json_dumper_set_member_name(&dumper, "minor");
    json_dumper_value_anyf(&dumper, "%d", minor);
    json_dumper_set_member_name(&dumper, "micro");
    json_dumper_value_anyf(&dumper, "%d", micro);
    json_dumper_end_object(&dumper);
    json_dumper_finish(&dumper);
    return 0;
}
