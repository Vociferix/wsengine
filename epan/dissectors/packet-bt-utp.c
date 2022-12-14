/* packet-bt-utp.c
 * Routines for BT-UTP dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

void proto_register_bt_utp(void);
void proto_reg_handoff_bt_utp(void);

enum {
  ST_DATA  = 0,
  ST_FIN   = 1,
  ST_STATE = 2,
  ST_RESET = 3,
  ST_SYN   = 4,
  ST_NUM_STATES
};

/* V0 hdr: "flags"; V1 hdr: "type" */
static const value_string bt_utp_type_vals[] = {
  { ST_DATA,  "Data"  },
  { ST_FIN,   "Fin"   },
  { ST_STATE, "State" },
  { ST_RESET, "Reset" },
  { ST_SYN,   "Syn"   },
  { 0, NULL }
};

enum {
  EXT_NO_EXTENSION    = 0,
  EXT_SELECTIVE_ACKS  = 1,
  EXT_EXTENSION_BITS  = 2,
  EXT_NUM_EXT
};

static const value_string bt_utp_extension_type_vals[] = {
  { EXT_NO_EXTENSION,   "No Extension" },
  { EXT_SELECTIVE_ACKS, "Selective ACKs" },
  { EXT_EXTENSION_BITS, "Extension bits" },
  { 0, NULL }
};

static int proto_bt_utp = -1;

/* ---  "Original" uTP Header ("version 0" ?) --------------

See utp.cpp source code @ https://github.com/bittorrent/libutp

-- Fixed Header --
0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| connection_id                                                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_seconds                                             |
+---------------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size      | ext           | flags         | seq_nr [ho]   |
+---------------+---------------+---------------+---------------+
| seq_nr [lo]   | ack_nr                        |
+---------------+---------------+---------------+

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....

*/

/* --- Version 1 Header ----------------

Specifications: BEP-0029
http://www.bittorrent.org/beps/bep_0029.html

-- Fixed Header --
Fields Types
0       4       8               16              24              32
+-------+-------+---------------+---------------+---------------+
| type  | ver   | extension     | connection_id                 |
+-------+-------+---------------+---------------+---------------+
| timestamp_microseconds                                        |
+---------------+---------------+---------------+---------------+
| timestamp_difference_microseconds                             |
+---------------+---------------+---------------+---------------+
| wnd_size                                                      |
+---------------+---------------+---------------+---------------+
| seq_nr                        | ack_nr                        |
+---------------+---------------+---------------+---------------+

-- Extension Field(s) --
0               8               16
+---------------+---------------+---------------+---------------+
| extension     | len           | bitmask
+---------------+---------------+---------------+---------------+
                                |
+---------------+---------------+....
*/

#define V0_FIXED_HDR_SIZE 23
#define V1_FIXED_HDR_SIZE 20

/* Very early versions of libutp (still used by Transmission) set the max
 * recv window size to 0x00380000, versions from 2013 and later set it to
 * 0x00100000, and some other clients use 0x00040000. This is one of the
 * few possible sources of heuristics.
 */

#define V1_MAX_WINDOW_SIZE 0x380000U

static dissector_handle_t bt_utp_handle;

static int hf_bt_utp_ver = -1;
static int hf_bt_utp_type = -1;
static int hf_bt_utp_flags = -1;
static int hf_bt_utp_extension = -1;
static int hf_bt_utp_next_extension_type = -1;
static int hf_bt_utp_extension_len = -1;
static int hf_bt_utp_extension_bitmask = -1;
static int hf_bt_utp_extension_unknown = -1;
static int hf_bt_utp_connection_id_v0 = -1;
static int hf_bt_utp_connection_id_v1 = -1;
static int hf_bt_utp_timestamp_sec = -1;
static int hf_bt_utp_timestamp_us = -1;
static int hf_bt_utp_timestamp_diff_us = -1;
static int hf_bt_utp_wnd_size_v0 = -1;
static int hf_bt_utp_wnd_size_v1 = -1;
static int hf_bt_utp_seq_nr = -1;
static int hf_bt_utp_ack_nr = -1;
static int hf_bt_utp_data = -1;

static gint ett_bt_utp = -1;
static gint ett_bt_utp_extension = -1;

static gboolean enable_version0 = FALSE;
static guint max_window_size = V1_MAX_WINDOW_SIZE;

static gint
get_utp_version(tvbuff_t *tvb) {
  guint8  v0_flags;
  guint8  v1_ver_type, ext, ext_len;
  guint32 window;
  guint   len, offset = 0;
  gint    ver = -1;

  /* Simple heuristics inspired by code from utp.cpp */

  len = tvb_captured_length(tvb);

  /* Version 1? */
  if (len < V1_FIXED_HDR_SIZE) {
    return -1;
  }

  v1_ver_type = tvb_get_guint8(tvb, 0);
  ext = tvb_get_guint8(tvb, 1);
  if (((v1_ver_type & 0x0f) == 1) && ((v1_ver_type>>4) < ST_NUM_STATES) &&
      (ext < EXT_NUM_EXT)) {
    window = tvb_get_guint32(tvb, 12, ENC_BIG_ENDIAN);
    if (window > max_window_size) {
      return -1;
    }
    ver = 1;
    offset = V1_FIXED_HDR_SIZE;
  } else if (enable_version0) {
    /* Version 0? */
    if (len < V0_FIXED_HDR_SIZE) {
      return -1;
    }
    v0_flags = tvb_get_guint8(tvb, 18);
    ext = tvb_get_guint8(tvb, 17);
    if ((v0_flags < ST_NUM_STATES) && (ext < EXT_NUM_EXT)) {
      ver = 0;
      offset = V0_FIXED_HDR_SIZE;
    }
  }

  if (ver < 0) {
    return ver;
  }

  /* In V0 we could use the microseconds value as a heuristic, because
   * it was tv_usec, but in the modern V1 we cannot, because it is
   * computed by converting a time_t into a 64 bit quantity of microseconds
   * and then taking the lower 32 bits, so all possible values are likely.
   */
  /* If we have an extension, then check the next two bytes,
   * the first of which is another extension type (likely NO_EXTENSION)
   * and the second of which is a length, which must be at least 4.
   */
  if (ext != EXT_NO_EXTENSION) {
    if (len < offset + 2) {
      return -1;
    }
    ext = tvb_get_guint8(tvb, offset);
    ext_len = tvb_get_guint8(tvb, offset+1);
    if (ext >= EXT_NUM_EXT || ext_len < 4) {
      return -1;
    }
  }

  return ver;
}

static int
dissect_utp_header_v0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
    /* "Original" (V0) */
  proto_tree_add_item(tree, hf_bt_utp_connection_id_v0, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_wnd_size_v0, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);

  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, " Type: %s", val_to_str(tvb_get_guint8(tvb, offset), bt_utp_type_vals, "Unknown %d"));
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

static int
dissect_utp_header_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  /* V1 */
  proto_tree_add_item(tree, hf_bt_utp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_bt_utp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  col_append_fstr(pinfo->cinfo, COL_INFO, " Type: %s", val_to_str((tvb_get_guint8(tvb, offset) >> 4), bt_utp_type_vals, "Unknown %d"));
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  *extension_type = tvb_get_guint8(tvb, offset);
  offset += 1;
  proto_tree_add_item(tree, hf_bt_utp_connection_id_v1, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_timestamp_diff_us, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_wnd_size_v1, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bt_utp_seq_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_bt_utp_ack_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

static int
dissect_utp_extension(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, guint8 *extension_type)
{
  proto_item *ti;
  proto_tree *ext_tree;
  guint8 extension_length;
  /* display the extension tree */

  while(*extension_type != EXT_NO_EXTENSION && offset < (int)tvb_reported_length(tvb))
  {
    switch(*extension_type){
      case EXT_SELECTIVE_ACKS: /* 1 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Selective ACKs, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, ENC_NA);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
        break;
      }
      case EXT_EXTENSION_BITS: /* 2 */
      {
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Extension Bits, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_bitmask, tvb, offset, extension_length, ENC_NA);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
        break;
      }
      default:
        ti = proto_tree_add_item(tree, hf_bt_utp_extension, tvb, offset, -1, ENC_NA);
        ext_tree = proto_item_add_subtree(ti, ett_bt_utp_extension);

        proto_tree_add_item(ext_tree, hf_bt_utp_next_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        *extension_type = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_length = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " Unknown, Len=%d", extension_length);
        offset += 1;

        proto_tree_add_item(ext_tree, hf_bt_utp_extension_unknown, tvb, offset, extension_length, ENC_NA);
        offset += extension_length;
        proto_item_set_len(ti, 1 + 1 + extension_length);
      break;
    }
  }

  return offset;
}

static int
dissect_bt_utp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint version;
  version = get_utp_version(tvb);

  /* try dissecting */
  if (version >= 0)
  {
    conversation_t *conversation;
    guint len_tvb;
    proto_tree *sub_tree = NULL;
    proto_item *ti;
    gint offset = 0;
    guint8 extension_type;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, bt_utp_handle);

    /* set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-uTP");
    /* set the info column */
    col_set_str( pinfo->cinfo, COL_INFO, "uTorrent Transport Protocol" );

    len_tvb = tvb_reported_length(tvb);

    /* Determine header version */

    if (version == 0) {
      ti = proto_tree_add_protocol_format(tree, proto_bt_utp, tvb, 0, -1,
                                          "uTorrent Transport Protocol V0");
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
      offset = dissect_utp_header_v0(tvb, pinfo, sub_tree, offset, &extension_type);
    } else {
      ti = proto_tree_add_item(tree, proto_bt_utp, tvb, 0, -1, ENC_NA);
      sub_tree = proto_item_add_subtree(ti, ett_bt_utp);
      offset = dissect_utp_header_v1(tvb, pinfo, sub_tree, offset, &extension_type);
    }

    offset = dissect_utp_extension(tvb, pinfo, sub_tree, offset, &extension_type);

    len_tvb = tvb_captured_length_remaining(tvb, offset);
    if(len_tvb > 0)
      proto_tree_add_item(sub_tree, hf_bt_utp_data, tvb, offset, len_tvb, ENC_NA);

    return offset+len_tvb;
  }
  return 0;
}

void
proto_register_bt_utp(void)
{
  static hf_register_info hf[] = {
    { &hf_bt_utp_ver,
      { "Version", "bt-utp.ver",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL }
    },
    { &hf_bt_utp_flags,
      { "Flags", "bt-utp.flags",
      FT_UINT8, BASE_DEC,  VALS(bt_utp_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_type,
      { "Type", "bt-utp.type",
      FT_UINT8, BASE_DEC,  VALS(bt_utp_type_vals), 0xF0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension,
      { "Extension", "bt-utp.extension",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_next_extension_type,
      { "Next Extension Type", "bt-utp.next_extension_type",
      FT_UINT8, BASE_DEC, VALS(bt_utp_extension_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_len,
      { "Extension Length", "bt-utp.extension_len",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_bitmask,
      { "Extension Bitmask", "bt-utp.extension_bitmask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_extension_unknown,
      { "Extension Unknown", "bt-utp.extension_unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_connection_id_v0,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_connection_id_v1,
      { "Connection ID", "bt-utp.connection_id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_sec,
      { "Timestamp seconds", "bt-utp.timestamp_sec",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_us,
      { "Timestamp Microseconds", "bt-utp.timestamp_us",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_timestamp_diff_us,
      { "Timestamp Difference Microseconds", "bt-utp.timestamp_diff_us",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_wnd_size_v0,
      { "Window Size", "bt-utp.wnd_size",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "V0 receive window size, in multiples of 350 bytes", HFILL }
    },
    { &hf_bt_utp_wnd_size_v1,
      { "Window Size", "bt-utp.wnd_size",
      FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_seq_nr,
      { "Sequence number", "bt-utp.seq_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_ack_nr,
      { "ACK number", "bt-utp.ack_nr",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_utp_data,
      { "Data", "bt-utp.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = { &ett_bt_utp, &ett_bt_utp_extension };

  module_t *bt_utp_module;

  /* Register protocol */
  proto_bt_utp = proto_register_protocol ("uTorrent Transport Protocol", "BT-uTP", "bt-utp");

  bt_utp_module = prefs_register_protocol(proto_bt_utp, NULL);
  prefs_register_obsolete_preference(bt_utp_module, "enable");
  prefs_register_bool_preference(bt_utp_module,
      "enable_version0",
      "Dissect prerelease (version 0) packets",
      "Whether the dissector should attempt to dissect packets with the "
      "obsolete format (version 0) that predates BEP 29 (22-Jun-2009)",
      &enable_version0);
  prefs_register_uint_preference(bt_utp_module,
      "max_window_size",
      "Maximum window size (in hex)",
      "Maximum receive window size allowed by the dissector. Early clients "
      "(and a few modern ones) set this value to 0x380000 (the default), "
      "later ones use smaller values like 0x100000 and 0x40000. A higher "
      "value can detect nonstandard packets, but at the cost of false "
      "positives.",
      16, &max_window_size);

  proto_register_field_array(proto_bt_utp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bt_utp(void)
{
  /* disabled by default since heuristic is weak */
  /* XXX: The heuristic is stronger now, but might still get false positives
   * on packets with lots of zero bytes. Needs more testing before enabling
   * by default.
   */
  heur_dissector_add("udp", dissect_bt_utp, "BitTorrent UTP over UDP", "bt_utp_udp", proto_bt_utp, HEURISTIC_DISABLE);

  bt_utp_handle = create_dissector_handle(dissect_bt_utp, proto_bt_utp);
  dissector_add_for_decode_as_with_preference("udp.port", bt_utp_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

