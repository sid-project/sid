{
    "scan": {
        "analyzer-version-clang": "19.1.7",
        "analyzer-version-cppcheck": "2.16.2",
        "analyzer-version-gcc": "14.2.1",
        "enabled-plugins": "clang, cppcheck, gcc",
        "exit-code": 0,
        "host": "fed.virt",
        "mock-config": "default",
        "project-name": "sid-0.0.7-1.fc41",
        "store-results-to": "/root/rpmbuild/SRPMS/sid-csmock-results.tar.xz",
        "time-created": "2025-01-29 09:21:01",
        "time-finished": "2025-01-29 09:23:38",
        "tool": "csmock",
        "tool-args": "'/usr/bin/csmock' '--cppcheck-add-flag=--check-level=exhaustive' '-o' 'sid-csmock-results.tar.xz' '-r' 'default' '--tools' 'clang,cppcheck,gcc' 'sid-0.0.7-1.fc41.src.rpm'",
        "tool-version": "csmock-3.8.0-1.fc41"
    },
    "defects": [
        {
            "checker": "CPPCHECK_WARNING",
            "cwe": 457,
            "language": "c/c++",
            "tool": "cppcheck",
            "hash_v1": "7bb806057e84ecd51493ff44530c6d5e0851bad3",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/modules/ucmd/block/dm_mpath/dm_mpath.c",
                    "line": 82,
                    "event": "error[uninitvar]",
                    "message": "Uninitialized variable: r",
                    "verbosity_level": 0
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "   80|   ",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "   81|   \tparent = sid_ucmd_dev_stack_va_get(mod_res, ucmd_ctx, .method = SID_DEV_SEARCH_IMM_ANC, .ret_code = &r);",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "   82|-> \tif (r < 0 || !parent)",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "   83|   \t\treturn 0;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": "   84|   ",
                    "verbosity_level": 1
                }
            ]
        },
        {
            "checker": "CLANG_WARNING",
            "language": "c/c++",
            "tool": "clang",
            "hash_v1": "ba5fda7b592cf252fc961c678ed06c653254012c",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 512,
                    "column": 20,
                    "event": "warning[core.NonNullParamChecker]",
                    "message": "Null pointer passed to 1st parameter expecting 'nonnull'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 804,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'args' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 804,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 807,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming the condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 807,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 807,
                    "column": 63,
                    "event": "note",
                    "message": "Assuming field 'key' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/include/internal/util.h",
                    "line": 76,
                    "column": 34,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_EMPTY'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 807,
                    "column": 63,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/include/internal/util.h",
                    "line": 76,
                    "column": 34,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_EMPTY'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 807,
                    "column": 63,
                    "event": "note",
                    "message": "Assuming the condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/include/internal/util.h",
                    "line": 76,
                    "column": 42,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_EMPTY'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/include/internal/util.h",
                    "line": 74,
                    "column": 34,
                    "event": "note",
                    "message": "expanded from macro 'UTIL_STR_END'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 807,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 813,
                    "column": 2,
                    "event": "note",
                    "message": "Value assigned to 'c_archive_key'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 817,
                    "column": 74,
                    "event": "note",
                    "message": "Assuming 'c_archive_key' is equal to NULL",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 820,
                    "column": 11,
                    "event": "note",
                    "message": "Calling '_unset_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 781,
                    "column": 2,
                    "event": "note",
                    "message": "Control jumps to 'case SID_KVS_BACKEND_HASH:'  at line 782",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 783,
                    "column": 8,
                    "event": "note",
                    "message": "Value assigned to 'relay.archive_arg.has_archive', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 783,
                    "column": 8,
                    "event": "note",
                    "message": "Value assigned to 'relay.archive_arg.kv_store_value', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 784,
                    "column": 4,
                    "event": "note",
                    "message": " Execution continues on line 791",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 791,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'r' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 791,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '||' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 791,
                    "column": 15,
                    "event": "note",
                    "message": "Assuming field 'ret_code' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 791,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 794,
                    "column": 2,
                    "event": "note",
                    "message": "Returning without writing to 'kv_store->backend', which participates in a condition later",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 820,
                    "column": 11,
                    "event": "note",
                    "message": "Returning from '_unset_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 820,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 823,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming field 'has_archive' is true",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 823,
                    "column": 6,
                    "event": "note",
                    "message": "Left side of '&&' is true",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 823,
                    "column": 39,
                    "event": "note",
                    "message": "Assuming field 'kv_store_value' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 823,
                    "column": 2,
                    "event": "note",
                    "message": "Taking true branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 830,
                    "column": 23,
                    "event": "note",
                    "message": "Passing null pointer value via 2nd parameter 'key'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 829,
                    "column": 12,
                    "event": "note",
                    "message": "Calling '_set_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
                    "line": 508,
                    "column": 2,
                    "event": "note",
                    "message": "Control jumps to 'case SID_KVS_BACKEND_HASH:'  at line 509",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/kvs.c",
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
            "hash_v1": "a14432df4e694f4780eddfdd63cda9b1e9136b22",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
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
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 0,
                    "event": "scope_hint",
                    "message": "In function '_init_common'",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 7331,
                    "column": 22,
                    "event": "note",
                    "message": "at offset 80 into object 'vvalue' of size 80",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 7331 |         kv_vector_t  vvalue[VVALUE_SINGLE_CNT];",
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
                    "message": "  843|   \tif (VVALUE_FLAGS(vvalue) & SID_KV_FL_AL) {",
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
            "checker": "CLANG_WARNING",
            "language": "c/c++",
            "tool": "clang",
            "hash_v1": "ba2e17fb6718ca4d0a83d5ea3a340d4bd4ba096a",
            "key_event_idx": 0,
            "events": [
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4003,
                    "column": 11,
                    "event": "warning[core.CallAndMessage]",
                    "message": "2nd function call argument is an uninitialized value",
                    "verbosity_level": 0
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4150,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'args' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4150,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4154,
                    "column": 6,
                    "event": "note",
                    "message": "Assuming 'r' is >= 0",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4154,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4160,
                    "column": 25,
                    "event": "note",
                    "message": "Calling '_do_sid_ucmd_dev_stack_get'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4027,
                    "column": 9,
                    "event": "note",
                    "message": "Calling '_get_dev_imm_deps'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3936,
                    "column": 2,
                    "event": "note",
                    "message": "'vvalue_size' declared without an initial value",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3939,
                    "column": 2,
                    "event": "note",
                    "message": "Control jumps to 'case SID_DEV_SEARCH_IMM_DESC:'  at line 3975",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3979,
                    "column": 8,
                    "event": "note",
                    "message": "Assuming 'dev_key' is null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3979,
                    "column": 4,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3994,
                    "column": 61,
                    "event": "note",
                    "message": "'?' condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3987,
                    "column": 13,
                    "event": "note",
                    "message": "Calling '_cmd_get_key_spec_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2679,
                    "column": 8,
                    "event": "note",
                    "message": "Assuming 'key' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2679,
                    "column": 2,
                    "event": "note",
                    "message": "Taking false branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2685,
                    "column": 8,
                    "event": "note",
                    "message": "Calling '_cmd_get_key_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2609,
                    "column": 8,
                    "event": "note",
                    "message": "Assuming 'val' is null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2609,
                    "column": 2,
                    "event": "note",
                    "message": "Taking true branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2610,
                    "column": 3,
                    "event": "note",
                    "message": "Control jumps to line 2663",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2663,
                    "column": 6,
                    "event": "note",
                    "message": "'ret_code' is non-null",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2663,
                    "column": 2,
                    "event": "note",
                    "message": "Taking true branch",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2665,
                    "column": 2,
                    "event": "note",
                    "message": "Returning without writing to '*value_size'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2685,
                    "column": 8,
                    "event": "note",
                    "message": "Returning from '_cmd_get_key_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 2688,
                    "column": 2,
                    "event": "note",
                    "message": "Returning without writing to '*value_size'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 3987,
                    "column": 13,
                    "event": "note",
                    "message": "Returning from '_cmd_get_key_spec_value'",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4000,
                    "column": 8,
                    "event": "note",
                    "message": "Assuming the condition is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4000,
                    "column": 22,
                    "event": "note",
                    "message": "Left side of '&&' is false",
                    "verbosity_level": 2
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4003,
                    "column": 11,
                    "event": "note",
                    "message": "2nd function call argument is an uninitialized value",
                    "verbosity_level": 2
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4001|   \t\t\t\treturn NULL;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4002|   ",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4003|-> \t\t\treturn _get_key_strv_from_vvalue(vvalue,",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4004|   \t\t\t                                 vvalue_size,",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4005|   \t\t\t                                 &KV_KEY_SPEC(.ns = SID_KV_NS_DEV),",
                    "verbosity_level": 1
                }
            ]
        },
        {
            "checker": "COMPILER_WARNING",
            "language": "c/c++",
            "tool": "gcc",
            "hash_v1": "749c52550a54405d977d6b0a0befac87fee1f1bb",
            "key_event_idx": 1,
            "events": [
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 0,
                    "event": "scope_hint",
                    "message": "In function '_do_sid_ucmd_dev_stack_get'",
                    "verbosity_level": 1
                },
                {
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4069,
                    "column": 39,
                    "event": "warning[-Wuse-after-free]",
                    "message": "pointer 'strv1_31' used after 'free'",
                    "verbosity_level": 0
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4069 |                                 strv  = strv1;",
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
                    "file_name": "sid-0.0.7-build/sid-0.0.7/src/resource/ubr.c",
                    "line": 4068,
                    "column": 33,
                    "event": "note",
                    "message": "call to 'free' here",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4068 |                                 free(strv);",
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
                    "message": " 4067|   \t\t\tif (strv1 != strv) {",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4068|   \t\t\t\tfree(strv);",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4069|-> \t\t\t\tstrv  = strv1;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4070|   \t\t\t\tcount = count1;",
                    "verbosity_level": 1
                },
                {
                    "file_name": "",
                    "line": 0,
                    "event": "#",
                    "message": " 4071|   \t\t\t}",
                    "verbosity_level": 1
                }
            ]
        }
    ]
}
