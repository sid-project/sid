{
    "scan": {
        "analyzer-version-clang": "19.1.4",
        "analyzer-version-cppcheck": "2.16.0",
        "analyzer-version-gcc": "14.2.1",
        "enabled-plugins": "clang, cppcheck, gcc",
        "exit-code": 0,
        "host": "fed.virt",
        "mock-config": "default",
        "project-name": "sid-0.0.6-1.fc41",
        "store-results-to": "/root/rpmbuild/SRPMS/csmock-results",
        "time-created": "2024-12-03 15:56:50",
        "time-finished": "2024-12-03 15:59:12",
        "tool": "csmock",
        "tool-args": "'/usr/bin/csmock' '--cppcheck-add-flag=--check-level=exhaustive' '-r' 'default' '--tools' 'clang,cppcheck,gcc' 'sid-0.0.6-1.fc41.src.rpm' '-o' 'csmock-results'",
        "tool-version": "csmock-3.8.0-1.fc41"
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
                    "line": 804,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'args' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 804,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 807,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming the condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 807,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 807,
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
                    "line": 807,
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
                    "line": 807,
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
                    "line": 807,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 813,
                    "column": 2,
                    "event": "note",
                    "message": "Value assigned to 'c_archive_key'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 817,
                    "column": 74,
                    "event": "note",
                    "message": "Assuming 'c_archive_key' is equal to NULL",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 820,
                    "column": 11,
                    "event": "note",
                    "message": "Calling '_unset_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 781,
                    "column": 2,
                    "event": "note",
                    "message": "Control jumps to 'case SID_KVS_BACKEND_HASH:'  at line 782",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 783,
                    "column": 8,
                    "event": "note",
                    "message": "Value assigned to 'relay.archive_arg.has_archive', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 783,
                    "column": 8,
                    "event": "note",
                    "message": "Value assigned to 'relay.archive_arg.kv_store_value', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 784,
                    "column": 4,
                    "event": "note",
                    "message": " Execution continues on line 791",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 791,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'r' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 791,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 791,
                    "column": 15,
                    "event": "note",
                    "message": "Assuming field 'ret_code' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 791,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 794,
                    "column": 2,
                    "event": "note",
                    "message": "Returning without writing to 'kv_store->backend', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 820,
                    "column": 11,
                    "event": "note",
                    "message": "Returning from '_unset_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 820,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 823,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming field 'has_archive' is true",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 823,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '&&' is true",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 823,
                    "column": 39,
                    "event": "note",
                    "message": "Assuming field 'kv_store_value' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 823,
                    "column": 2,
                    "event": "note",
                    "message": "Taking true branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 830,
                    "column": 23,
                    "event": "note",
                    "message": "Passing null pointer value via 2nd parameter 'key'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/kvs.c",
                    "line": 829,
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
                    "line": 845,
                    "column": 55,
                    "event": "warning[-Warray-bounds=]",
                    "message": "array subscript 5 is outside array bounds of 'struct kv_vector_t[5]'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  845 |                 vvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};",
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
                    "line": 7310,
                    "column": 22,
                    "event": "note",
                    "message": "at offset 80 into object 'vvalue' of size 80",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 7310 |         kv_vector_t  vvalue[VVALUE_SINGLE_CNT];",
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
                    "message": "  843|   \tif (VVALUE_FLAGS(vvalue) & SID_KV_FL_ALIGN) {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  844|   \t\tassert(vvalue_size >= VVALUE_IDX_DATA_ALIGNED + idx);",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  845|-> \t\tvvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  846|   \t} else {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "  847|   \t\tassert(vvalue_size >= VVALUE_IDX_DATA + idx);",
                    "verbosity_level": 1
                }
            ]
        },
        {
            "checker": "COMPILER_WARNING",
            "language": "c/c++",
            "tool": "gcc",
            "hash_v1": "9319daeb237eae066205b57ff503fc7160e64785",
            "key_event_idx": 1,
            "events": [
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/ubr.c",
                    "line": 0,
                    "event": "scope_hint",
                    "message": "In function '_do_sid_ucmd_dev_stack_get'",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/ubr.c",
                    "line": 4023,
                    "column": 39,
                    "event": "warning[-Wuse-after-free]",
                    "message": "pointer 'strv1_30' used after 'free'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4023 |                                 strv  = strv1;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "      |                                 ~~~~~~^~~~~~~",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.6-build/sid-0.0.6/src/resource/ubr.c",
                    "line": 4022,
                    "column": 33,
                    "event": "note",
                    "message": "call to 'free' here",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4022 |                                 free(strv);",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "      |                                 ^~~~~~~~~~",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4021|   \t\t\tif (strv1 != strv) {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4022|   \t\t\t\tfree(strv);",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4023|-> \t\t\t\tstrv  = strv1;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4024|   \t\t\t\tcount = count1;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4025|   \t\t\t}",
                    "verbosity_level": 1
                }
            ]
        }
    ]
}
