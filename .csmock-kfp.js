{
    "defects": [
        {
            "checker": "COMPILER_WARNING",
            "language": "c/c++",
            "tool": "gcc",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.5/src/resource/ubr.c",
                    "line": 735,
                    "column": 55,
                    "event": "warning[-Warray-bounds=]",
                    "message": "array subscript 5 is outside array bounds of 'struct kv_vector_t[5]'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  735 |                 vvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "      |                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.5/src/resource/ubr.c",
                    "line": 0,
                    "event": "scope_hint",
                    "message": "In function '_init_common'",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.5/src/resource/ubr.c",
                    "line": 5863,
                    "column": 22,
                    "event": "note",
                    "message": "at offset 80 into object 'vvalue' of size 80",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 5863 |         kv_vector_t  vvalue[VVALUE_SINGLE_CNT];",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "      |                      ^~~~~~",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  733|   \tif (VVALUE_FLAGS(vvalue) & KV_ALIGN) {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  734|   \t\tassert(vvalue_size >= (VVALUE_IDX_DATA_ALIGNED + idx));",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  735|-> \t\tvvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  736|   \t} else {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  737|   \t\tassert(vvalue_size >= (VVALUE_IDX_DATA + idx));",
                    "verbosity_level": 1
                }
            ]
        }
    ]
}
