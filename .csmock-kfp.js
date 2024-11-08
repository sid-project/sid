{
    "scan": {
        "analyzer-version-clang": "19.1.0",
        "analyzer-version-cppcheck": "2.16.0",
        "analyzer-version-gcc": "14.2.1",
        "enabled-plugins": "clang, cppcheck, gcc",
        "exit-code": 0,
        "host": "fed.virt",
        "known-false-positives": ".csmock-kfp.js",
        "mock-config": "default",
        "project-name": "sid-0.0.6-1.fc41",
        "store-results-to": "/root/rpmbuild/SRPMS/sid-csmock-results.tar.xz",
        "time-created": "2024-11-08 10:31:40",
        "time-finished": "2024-11-08 10:34:18",
        "tool": "csmock",
        "tool-args": "'/usr/bin/csmock' '--known-false-positives' '.csmock-kfp.js' '--cppcheck-add-flag=--check-level=exhaustive' '-o' 'sid-csmock-results.tar.xz' '-r' 'default' '--tools' 'clang,cppcheck,gcc' './sid-0.0.6-1.fc41.src.rpm'",
        "tool-version": "csmock-3.7.1-1.fc41"
    },
    "defects": [
        {
            "checker": "CLANG_WARNING",
            "language": "c/c++",
            "tool": "clang",
            "hash_v1": "dd1f9ed25489877d3960a2caa3ef5b351d6cdeb6",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 512,
                    "column": 20,
                    "event": "warning[core.NonNullParamChecker]",
                    "message": "Null pointer passed to 1st parameter expecting 'nonnull'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 811,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'args' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 811,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 814,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming the condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 814,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 814,
                    "column": 63,
                    "event": "note",
                    "message": "Assuming field 'key' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/include/internal/util.h",
                    "line": 76,
                    "column": 34,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_EMPTY'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 814,
                    "column": 63,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/include/internal/util.h",
                    "line": 76,
                    "column": 34,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_EMPTY'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 814,
                    "column": 63,
                    "event": "note",
                    "message": "Assuming the condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/include/internal/util.h",
                    "line": 76,
                    "column": 42,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_EMPTY'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/include/internal/util.h",
                    "line": 74,
                    "column": 34,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_END'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 814,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 822,
                    "column": 2,
                    "event": "note",
                    "message": "Value assigned to 'c_archive_key'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 826,
                    "column": 74,
                    "event": "note",
                    "message": "Assuming 'c_archive_key' is equal to NULL",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 829,
                    "column": 11,
                    "event": "note",
                    "message": "Calling '_unset_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 788,
                    "column": 2,
                    "event": "note",
                    "message": "Control jumps to 'case SID_KVS_BACKEND_HASH:'  at line 789",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 790,
                    "column": 8,
                    "event": "note",
                    "message": "Value assigned to 'relay.archive_arg.has_archive', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 790,
                    "column": 8,
                    "event": "note",
                    "message": "Value assigned to 'relay.archive_arg.kv_store_value', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 791,
                    "column": 4,
                    "event": "note",
                    "message": " Execution continues on line 798",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 798,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'r' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 798,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 798,
                    "column": 15,
                    "event": "note",
                    "message": "Assuming field 'ret_code' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 798,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 801,
                    "column": 2,
                    "event": "note",
                    "message": "Returning without writing to 'kv_store->backend', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 829,
                    "column": 11,
                    "event": "note",
                    "message": "Returning from '_unset_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 829,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 832,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming field 'has_archive' is true",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 832,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '&&' is true",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 832,
                    "column": 39,
                    "event": "note",
                    "message": "Assuming field 'kv_store_value' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 832,
                    "column": 2,
                    "event": "note",
                    "message": "Taking true branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 839,
                    "column": 23,
                    "event": "note",
                    "message": "Passing null pointer value via 2nd parameter 'key'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 838,
                    "column": 12,
                    "event": "note",
                    "message": "Calling '_set_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 508,
                    "column": 2,
                    "event": "note",
                    "message": "Control jumps to 'case SID_KVS_BACKEND_HASH:'  at line 509",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 512,
                    "column": 20,
                    "event": "note",
                    "message": "Null pointer passed to 1st parameter expecting 'nonnull'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  510|   \t\t\tr = hash_update(kv_store->ht,",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  511|   \t\t\t                key,",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  512|-> \t\t\t                strlen(key) + 1,",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  513|   \t\t\t                (void **) kv_store_value,",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  514|   \t\t\t                kv_store_value_size,",
                    "verbosity_level": 1
                }
            ]
        },
        {
            "checker": "COMPILER_WARNING",
            "language": "c/c++",
            "tool": "gcc",
            "hash_v1": "ff0a12a77b437e87894902eb408f554917c5e381",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/ubr.c",
                    "line": 827,
                    "column": 55,
                    "event": "warning[-Warray-bounds=]",
                    "message": "array subscript 5 is outside array bounds of 'struct kv_vector_t[5]'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  827 |                 vvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};",
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
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/ubr.c",
                    "line": 0,
                    "event": "scope_hint",
                    "message": "In function '_init_common'",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/ubr.c",
                    "line": 6895,
                    "column": 22,
                    "event": "note",
                    "message": "at offset 80 into object 'vvalue' of size 80",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 6895 |         kv_vector_t  vvalue[VVALUE_SINGLE_CNT];",
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
                    "message": "  825|   \tif (VVALUE_FLAGS(vvalue) & SID_KV_FL_ALIGN) {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  826|   \t\tassert(vvalue_size >= VVALUE_IDX_DATA_ALIGNED + idx);",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  827|-> \t\tvvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  828|   \t} else {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  829|   \t\tassert(vvalue_size >= VVALUE_IDX_DATA + idx);",
                    "verbosity_level": 1
                }
            ]
        }
    ]
}
