#include <wsengine/wsengine.h>

#include <wiretap/wtap.h>

static gboolean encode_idb(json_dumper* dumper, wtap_block_t idb);
static gboolean encode_record(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf);
static gboolean encode_packet(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf);
static gboolean encode_ft_specific(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf);
static gboolean encode_syscall(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf);
static gboolean encode_systemd_journal_export(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf);
static gboolean encode_custom_block(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf);
static gboolean encode_nokia_phdr(json_dumper* dumper, struct nokia_phdr* phdr);
static gboolean encode_eth_phdr(json_dumper* dumper, struct eth_phdr* phdr);
static gboolean encode_dte_dce_phdr(json_dumper* dumper, struct dte_dce_phdr* phdr);
static gboolean encode_isdn_phdr(json_dumper* dumper, struct isdn_phdr* phdr);
static gboolean encode_atm_phdr(json_dumper* dumper, struct atm_phdr* phdr);
static gboolean encode_ascend_phdr(json_dumper* dumper, struct ascend_phdr* phdr);
static gboolean encode_p2p_phdr(json_dumper* dumper, struct p2p_phdr* phdr);
static gboolean encode_ieee_802_11_phdr(json_dumper* dumper, struct ieee_802_11_phdr* phdr);
static gboolean encode_cosine_phdr(json_dumper* dumper, struct cosine_phdr* phdr);
static gboolean encode_irda_phdr(json_dumper* dumper, struct irda_phdr* phdr);
static gboolean encode_nettl_phdr(json_dumper* dumper, struct nettl_phdr* phdr);
static gboolean encode_mpt2_phdr(json_dumper* dumper, struct mtp2_phdr* phdr);
static gboolean encode_k12_phdr(json_dumper* dumper, struct k12_phdr* phdr);
static gboolean encode_lapd_phdr(json_dumper* dumper, struct lapd_phdr* phdr);
static gboolean encode_erf_phdr(json_dumper* dumper, struct erf_mc_phdr* phdr);
static gboolean encode_sita_phdr(json_dumper* dumper, struct sita_phdr* phdr);
static gboolean encode_bthci_phdr(json_dumper* dumper, struct bthci_phdr* phdr);
static gboolean encode_btmon_phdr(json_dumper* dumper, struct btmon_phdr* phdr);
static gboolean encode_l1event_phdr(json_dumper* dumper, struct l1event_phdr* phdr);
static gboolean encode_i2c_phdr(json_dumper* dumper, struct i2c_phdr* phdr);
static gboolean encode_gsm_um_phdr(json_dumper* dumper, struct gsm_um_phdr* phdr);
static gboolean encode_nstr_phdr(json_dumper* dumper, struct nstr_phdr* phdr);
static gboolean encode_llcp_phdr(json_dumper* dumper, struct llcp_phdr* phdr);
static gboolean encode_logcat_phdr(json_dumper* dumper, struct logcat_phdr* phdr);
static gboolean encode_netmon_phdr(json_dumper* dumper, struct netmon_phdr* phdr);
static gboolean encode_ber_phdr(json_dumper* dumper, struct ber_phdr* phdr);

int
wse_read_file(cmd_reader_t cr) {
    cmd_obj_t cmd;
    cmd_item_t item;
    const char* filepath = NULL;
    wtap* wth;
    wtap_rec rec;
    Buffer buf;
    gint64 data_offset;
    int filetype = WTAP_TYPE_AUTO;
    gchar* err_info;
    int err = 0;
    json_dumper dumper;
    wtap_block_t idb;

    if (!read_cmd(cr, &cmd) ||
        !cmd_obj_get(&cmd, "file", &item)) {
        fprintf(stderr, "wsengine: invalid command - expected \"file\" option\n");
        return 1;
    }

    switch (cmd_item_type(&item)) {
        case CMD_ITEM_NULL:
            filepath = "-";
            break;
        case CMD_ITEM_STRING:
            filepath = cmd_item_get_string(&item);
            break;
        default:
            fprintf(stderr, "wsengine: invalid \"file\" option\n");
            return 1;
    }

    if (cmd_obj_get(&cmd, "filetype", &item)) {
        switch (cmd_item_type(&item)) {
            case CMD_ITEM_NUMBER:
                filetype = cmd_item_get_int(&item);
                break;
            case CMD_ITEM_STRING:
                filetype = wtap_name_to_file_type_subtype(cmd_item_get_string(&item));
                break;
            case CMD_ITEM_NULL:
                break;
            default:
                fprintf(stderr, "wsengine: invalid \"filetype\" option\n");
                return 1;
        }
    }

    wth = wtap_open_offline(filepath, filetype, &err, &err_info, FALSE);
    if (wth == NULL) {
        if (strcmp(filepath, "-") == 0) {
            fprintf(stderr, "wsengine: failed to read capture file from stdin\n");
        } else {
            fprintf(stderr, "wsengine: failed to open file \"%s\"\n", filepath);
        }
        return 1;
    }

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    while (wtap_read(wth, &rec, &buf, &err, &err_info, &data_offset)) {
        while (TRUE) {
            idb = wtap_get_next_interface_description(wth);
            if (idb == NULL) break;
            memset(&dumper, 0, sizeof(json_dumper));
            dumper.output_file = stdout;
            json_dumper_begin_object(&dumper);
            json_dumper_set_member_name(&dumper, "iface");
            if (!encode_idb(&dumper, idb)) {
                err = 1;
                break;
            }
            json_dumper_end_object(&dumper);
            json_dumper_finish(&dumper);
        }
        if (err != 0) break;

        memset(&dumper, 0, sizeof(json_dumper));
        dumper.output_file = stdout;
        json_dumper_begin_object(&dumper);
        json_dumper_set_member_name(&dumper, "record");
        if (!encode_record(&dumper, wth, &rec, &buf)) {
            err = 1;
            break;
        }
        json_dumper_end_object(&dumper);
        json_dumper_finish(&dumper);

        wtap_rec_reset(&rec);
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    return err;
}

static gboolean
encode_idb(json_dumper* dumper, wtap_block_t idb) {
    wtapng_if_descr_mandatory_t* mandatory = wtap_block_get_mandatory_data(idb);
    const char* encap_name = wtap_encap_name(mandatory->wtap_encap);

    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "encap");
    if (encap_name == NULL) {
        json_dumper_value_anyf(dumper, "null");
    } else {
        json_dumper_value_string(dumper, encap_name);
    }

    json_dumper_set_member_name(dumper, "time_units_per_second");
    json_dumper_value_anyf(dumper, "%" G_GUINT64_FORMAT, mandatory->time_units_per_second);

    json_dumper_set_member_name(dumper, "tsprec");
    switch (mandatory->tsprecision) {
        case WTAP_TSPREC_PER_PACKET:
            json_dumper_value_string(dumper, "per-packet");
            break;
        case WTAP_TSPREC_SEC:
            json_dumper_value_string(dumper, "sec");
            break;
        case WTAP_TSPREC_DSEC:
            json_dumper_value_string(dumper, "dsec");
            break;
        case WTAP_TSPREC_CSEC:
            json_dumper_value_string(dumper, "csec");
            break;
        case WTAP_TSPREC_MSEC:
            json_dumper_value_string(dumper, "msec");
            break;
        case WTAP_TSPREC_USEC:
            json_dumper_value_string(dumper, "usec");
            break;
        case WTAP_TSPREC_NSEC:
            json_dumper_value_string(dumper, "nsec");
            break;
        default:
            json_dumper_value_anyf(dumper, "null");
            break;
    }

    json_dumper_set_member_name(dumper, "snaplen");
    json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, mandatory->snap_len);

    // TODO: mandatory->interface_statistics

    // TODO: IDB options

    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_record(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf) {
    gboolean ret = TRUE;

    json_dumper_begin_object(dumper);

    if ((rec->presence_flags & WTAP_HAS_TS) != 0) {
        json_dumper_set_member_name(dumper, "ts");
        json_dumper_begin_object(dumper);
        json_dumper_set_member_name(dumper, "secs");
        json_dumper_value_anyf(dumper, "%" G_GINT64_FORMAT, (gint64)rec->ts.secs);
        json_dumper_set_member_name(dumper, "nsecs");
        json_dumper_value_anyf(dumper, "%i", rec->ts.nsecs);
        json_dumper_end_object(dumper);

        json_dumper_set_member_name(dumper, "tsprec");
        switch (rec->tsprec) {
            case WTAP_TSPREC_PER_PACKET:
                json_dumper_value_string(dumper, "per-packet");
                break;
            case WTAP_TSPREC_SEC:
                json_dumper_value_string(dumper, "sec");
                break;
            case WTAP_TSPREC_DSEC:
                json_dumper_value_string(dumper, "dsec");
                break;
            case WTAP_TSPREC_CSEC:
                json_dumper_value_string(dumper, "csec");
                break;
            case WTAP_TSPREC_MSEC:
                json_dumper_value_string(dumper, "msec");
                break;
            case WTAP_TSPREC_USEC:
                json_dumper_value_string(dumper, "usec");
                break;
            case WTAP_TSPREC_NSEC:
                json_dumper_value_string(dumper, "nsec");
                break;
            default:
                json_dumper_value_anyf(dumper, "null");
                break;
        }
    } else {
        json_dumper_set_member_name(dumper, "ts");
        json_dumper_value_anyf(dumper, "null");
        json_dumper_set_member_name(dumper, "tsprec");
        json_dumper_value_anyf(dumper, "null");
    }

    json_dumper_set_member_name(dumper, "has_caplen");
    if ((rec->presence_flags & WTAP_HAS_CAP_LEN) != 0) {
        json_dumper_value_anyf(dumper, "true");
    } else {
        json_dumper_value_anyf(dumper, "false");
    }

    json_dumper_set_member_name(dumper, "has_iface_id");
    if ((rec->presence_flags & WTAP_HAS_INTERFACE_ID) != 0) {
        json_dumper_value_anyf(dumper, "true");
    } else {
        json_dumper_value_anyf(dumper, "false");
    }

    json_dumper_set_member_name(dumper, "type");
    switch (rec->rec_type) {
        case REC_TYPE_PACKET:
            json_dumper_value_string(dumper, "packet");
            json_dumper_set_member_name(dumper, "header");
            ret = encode_packet(dumper, wth, rec, buf);
            break;
        case REC_TYPE_FT_SPECIFIC_EVENT:
            json_dumper_value_string(dumper, "ft-specific-event");
            json_dumper_set_member_name(dumper, "header");
            ret = encode_ft_specific(dumper, wth, rec, buf);
            break;
        case REC_TYPE_FT_SPECIFIC_REPORT:
            json_dumper_value_string(dumper, "ft-specific-report");
            json_dumper_set_member_name(dumper, "header");
            ret = encode_ft_specific(dumper, wth, rec, buf);
            break;
        case REC_TYPE_SYSCALL:
            json_dumper_value_string(dumper, "syscall");
            json_dumper_set_member_name(dumper, "header");
            ret = encode_syscall(dumper, wth, rec, buf);
            break;
        case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
            json_dumper_value_string(dumper, "systemd-journal-export");
            json_dumper_set_member_name(dumper, "header");
            ret = encode_systemd_journal_export(dumper, wth, rec, buf);
            break;
        case REC_TYPE_CUSTOM_BLOCK:
            json_dumper_value_string(dumper, "custom-block");
            json_dumper_set_member_name(dumper, "header");
            ret = encode_custom_block(dumper, wth, rec, buf);
            break;
        default:
            fprintf(stderr, "wsengine: encountered invalid record\n");
            ret = 1;
            break;
    }

    json_dumper_end_object(dumper);

    return ret;
}

static gboolean
encode_packet(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf) {
    gboolean ret = FALSE;
    wtap_packet_header* hdr = &rec->rec_header.packet_header;
    const char* encap_name = wtap_encap_name(hdr->pkt_encap);
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "len");
    json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, hdr->len);
    json_dumper_set_member_name(dumper, "iface_id");
    if ((rec->presence_flags & WTAP_HAS_INTERFACE_ID) != 0) {
        json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, hdr->interface_id);
    } else {
        json_dumper_value_anyf(dumper, "null");
    }
    json_dumper_set_member_name(dumper, "encap");
    if (encap_name == NULL) {
        json_dumper_value_anyf(dumper, "%i", hdr->pkt_encap);
    } else {
        json_dumper_value_string(dumper, encap_name);
    }
    json_dumper_set_member_name(dumper, "encap_header");
    switch (hdr->pkt_encap) {
        case WTAP_ENCAP_ETHERNET:
            if (wtap_file_type_subtype(wth) == wtap_name_to_file_type_subtype("nokiapcap")) {
                ret = encode_nokia_phdr(dumper, &hdr->pseudo_header.nokia);
            } else {
                ret = encode_eth_phdr(dumper, &hdr->pseudo_header.eth);
            }
            break;
        case WTAP_ENCAP_LAPB:
        case WTAP_ENCAP_FRELAY_WITH_PHDR:
            ret = encode_dte_dce_phdr(dumper, &hdr->pseudo_header.dte_dce);
            break;
        case WTAP_ENCAP_ISDN:
            ret = encode_isdn_phdr(dumper, &hdr->pseudo_header.isdn);
            break;
        case WTAP_ENCAP_ATM_RFC1483:
        case WTAP_ENCAP_LINUX_ATM_CLIP:
        case WTAP_ENCAP_ATM_PDUS:
        case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
            ret = encode_atm_phdr(dumper, &hdr->pseudo_header.atm);
            break;
        case WTAP_ENCAP_ASCEND:
            ret = encode_ascend_phdr(dumper, &hdr->pseudo_header.ascend);
            break;
        case WTAP_ENCAP_PPP_WITH_PHDR:
        case WTAP_ENCAP_SDLC:
        case WTAP_ENCAP_CHDLC_WITH_PHDR:
        case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
            ret = encode_p2p_phdr(dumper, &hdr->pseudo_header.p2p);
            break;
        case WTAP_ENCAP_IEEE_802_11:
        case WTAP_ENCAP_IEEE_802_11_PRISM:
        case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        case WTAP_ENCAP_IEEE_802_11_RADIOTAP:
        case WTAP_ENCAP_IEEE_802_11_AVS:
        case WTAP_ENCAP_IEEE_802_11_NETMON:
            ret = encode_ieee_802_11_phdr(dumper, &hdr->pseudo_header.ieee_802_11);
            break;
        case WTAP_ENCAP_COSINE:
            ret = encode_cosine_phdr(dumper, &hdr->pseudo_header.cosine);
            break;
        case WTAP_ENCAP_IRDA:
            ret = encode_irda_phdr(dumper, &hdr->pseudo_header.irda);
            break;
        case WTAP_ENCAP_NETTL_RAW_ICMP:
        case WTAP_ENCAP_NETTL_RAW_ICMPV6:
        case WTAP_ENCAP_NETTL_RAW_IP:
        case WTAP_ENCAP_NETTL_ETHERNET:
        case WTAP_ENCAP_NETTL_TOKEN_RING:
        case WTAP_ENCAP_NETTL_FDDI:
        case WTAP_ENCAP_NETTL_UNKNOWN:
        case WTAP_ENCAP_NETTL_X25:
        case WTAP_ENCAP_NETTL_RAW_TELNET:
            ret = encode_nettl_phdr(dumper, &hdr->pseudo_header.nettl);
            break;
        case WTAP_ENCAP_MTP2_WITH_PHDR:
            ret = encode_mpt2_phdr(dumper, &hdr->pseudo_header.mtp2);
            break;
        case WTAP_ENCAP_K12:
            ret = encode_k12_phdr(dumper, &hdr->pseudo_header.k12);
            break;
        case WTAP_ENCAP_LINUX_LAPD:
            ret = encode_lapd_phdr(dumper, &hdr->pseudo_header.lapd);
            break;
        case WTAP_ENCAP_ERF:
            ret = encode_erf_phdr(dumper, &hdr->pseudo_header.erf);
            break;
        case WTAP_ENCAP_SITA:
            ret = encode_sita_phdr(dumper, &hdr->pseudo_header.sita);
            break;
        case WTAP_ENCAP_BLUETOOTH_HCI:
            ret = encode_bthci_phdr(dumper, &hdr->pseudo_header.bthci);
            break;
        case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
            ret = encode_btmon_phdr(dumper, &hdr->pseudo_header.btmon);
            break;
        case WTAP_ENCAP_LAYER1_EVENT:
            ret = encode_l1event_phdr(dumper, &hdr->pseudo_header.l1event);
            break;
        case WTAP_ENCAP_I2C_LINUX:
            ret = encode_i2c_phdr(dumper, &hdr->pseudo_header.i2c);
            break;
        case WTAP_ENCAP_GSM_UM:
            ret = encode_gsm_um_phdr(dumper, &hdr->pseudo_header.gsm_um);
            break;
        case WTAP_ENCAP_NSTRACE_1_0:
        case WTAP_ENCAP_NSTRACE_2_0:
        case WTAP_ENCAP_NSTRACE_3_0:
        case WTAP_ENCAP_NSTRACE_3_5:
            ret = encode_nstr_phdr(dumper, &hdr->pseudo_header.nstr);
            break;
        case WTAP_ENCAP_NFC_LLCP:
            ret = encode_llcp_phdr(dumper, &hdr->pseudo_header.llcp);
            break;
        case WTAP_ENCAP_LOGCAT:
            ret = encode_logcat_phdr(dumper, &hdr->pseudo_header.logcat);
            break;
        case WTAP_ENCAP_NETMON_HEADER:
            ret = encode_netmon_phdr(dumper, &hdr->pseudo_header.netmon);
            break;
        case WTAP_ENCAP_BER:
            ret = encode_ber_phdr(dumper, &hdr->pseudo_header.ber);
            break;
        default:
            json_dumper_value_anyf(dumper, "null");
            break;
    }
    json_dumper_set_member_name(dumper, "data");
    json_dumper_begin_base64(dumper);
    json_dumper_write_base64(dumper, buf->data, hdr->caplen);
    json_dumper_end_base64(dumper);
    json_dumper_end_object(dumper);
    return ret;
}

static gboolean
encode_ft_specific(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf) {
    wtap_ft_specific_header* hdr = &rec->rec_header.ft_specific_header;
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "type");
    json_dumper_value_anyf(dumper, "%" G_GUINT64_FORMAT, (guint64)hdr->record_type);
    json_dumper_set_member_name(dumper, "data");
    json_dumper_begin_base64(dumper);
    json_dumper_write_base64(dumper, buf->data, hdr->record_len);
    json_dumper_end_base64(dumper);
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_syscall(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf) {
    wtap_syscall_header* hdr = &rec->rec_header.syscall_header;
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "type");
    json_dumper_value_anyf(dumper, "%" G_GUINT64_FORMAT, (guint64)hdr->record_type);
    json_dumper_set_member_name(dumper, "byte_order");
    switch (hdr->byte_order) {
        case G_BIG_ENDIAN:
            json_dumper_value_string(dumper, "big");
            break;
        case G_LITTLE_ENDIAN:
            json_dumper_value_string(dumper, "little");
            break;
        case G_PDP_ENDIAN:
            json_dumper_value_string(dumper, "pdp");
            break;
        default:
            json_dumper_value_anyf(dumper, "%i", hdr->byte_order);
            break;
    }
    json_dumper_set_member_name(dumper, "thread_id");
    json_dumper_value_anyf(dumper, "%" G_GUINT64_FORMAT, hdr->thread_id);
    json_dumper_set_member_name(dumper, "event_filelen");
    json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, hdr->event_filelen);
    json_dumper_set_member_name(dumper, "event_type");
    json_dumper_value_anyf(dumper, "%" G_GUINT16_FORMAT, hdr->event_type);
    json_dumper_set_member_name(dumper, "nparams");
    json_dumper_value_anyf(dumper, "%", G_GUINT32_FORMAT, hdr->nparams);
    json_dumper_set_member_name(dumper, "cpu_id");
    json_dumper_value_anyf(dumper, "%" G_GUINT16_FORMAT, hdr->cpu_id);
    json_dumper_set_member_name(dumper, "data");
    json_dumper_begin_base64(dumper);
    json_dumper_write_base64(dumper, buf->data, hdr->event_len);
    json_dumper_end_base64(dumper);
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_systemd_journal_export(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf) {
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "data");
    json_dumper_begin_base64(dumper);
    json_dumper_write_base64(dumper, buf->data, rec->rec_header.systemd_journal_export_header.record_len);
    json_dumper_end_base64(dumper);
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_custom_block(json_dumper* dumper, wtap* wth, wtap_rec* rec, Buffer* buf) {
    guint32 nflx_type;
    guint32 skipped;
    wtap_custom_block_header* hdr = &rec->rec_header.custom_block_header;
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "pen");
    json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, hdr->pen);
    json_dumper_set_member_name(dumper, "copy_allowed");
    json_dumper_value_anyf(dumper, hdr->copy_allowed ? "true" : "false");
    if (hdr->pen == PEN_NFLX) {
        json_dumper_set_member_name(dumper, "nflx");
        json_dumper_begin_object(dumper);
        json_dumper_set_member_name(dumper, "type");
        nflx_type = hdr->custom_data_header.nflx_custom_data_header.type;
        skipped = hdr->custom_data_header.nflx_custom_data_header.skipped;
        switch (hdr->custom_data_header.nflx_custom_data_header.type) {
            case BBLOG_TYPE_EVENT_BLOCK:
                json_dumper_value_string(dumper, "event");
                break;
            case BBLOG_TYPE_SKIPPED_BLOCK:
                json_dumper_value_string(dumper, "skipped");
                break;
            default:
                json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, nflx_type);
                json_dumper_set_member_name(dumper, "skipped");
                json_dumper_value_anyf(dumper, "%" G_GUINT32_FORMAT, skipped);
                break;
        }
        json_dumper_end_object(dumper);
    }
    json_dumper_set_member_name(dumper, "data");
    json_dumper_begin_base64(dumper);
    json_dumper_write_base64(dumper, buf->data, hdr->length);
    json_dumper_end_base64(dumper);
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_nokia_phdr(json_dumper* dumper, struct nokia_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_eth_phdr(json_dumper* dumper, struct eth_phdr* phdr) {
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "fcs_len");
    if (phdr->fcs_len < 0) {
        json_dumper_value_anyf(dumper, "null");
    } else {
        json_dumper_value_anyf(dumper, "%i", phdr->fcs_len);
    }
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_dte_dce_phdr(json_dumper* dumper, struct dte_dce_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_isdn_phdr(json_dumper* dumper, struct isdn_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_atm_phdr(json_dumper* dumper, struct atm_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_ascend_phdr(json_dumper* dumper, struct ascend_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_p2p_phdr(json_dumper* dumper, struct p2p_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_ieee_802_11_phdr(json_dumper* dumper, struct ieee_802_11_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_cosine_phdr(json_dumper* dumper, struct cosine_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_irda_phdr(json_dumper* dumper, struct irda_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_nettl_phdr(json_dumper* dumper, struct nettl_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_mpt2_phdr(json_dumper* dumper, struct mtp2_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_k12_phdr(json_dumper* dumper, struct k12_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_lapd_phdr(json_dumper* dumper, struct lapd_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_erf_phdr(json_dumper* dumper, struct erf_mc_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_sita_phdr(json_dumper* dumper, struct sita_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_bthci_phdr(json_dumper* dumper, struct bthci_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_btmon_phdr(json_dumper* dumper, struct btmon_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_l1event_phdr(json_dumper* dumper, struct l1event_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_i2c_phdr(json_dumper* dumper, struct i2c_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_gsm_um_phdr(json_dumper* dumper, struct gsm_um_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_nstr_phdr(json_dumper* dumper, struct nstr_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_llcp_phdr(json_dumper* dumper, struct llcp_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_logcat_phdr(json_dumper* dumper, struct logcat_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_netmon_phdr(json_dumper* dumper, struct netmon_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

static gboolean
encode_ber_phdr(json_dumper* dumper, struct ber_phdr* phdr) {
    json_dumper_begin_object(dumper);
    // TODO
    json_dumper_end_object(dumper);
    return TRUE;
}

