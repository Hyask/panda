// Simple (C ABI) API for other plugins to use when interacting with coverage.
#ifndef __COVERAGE_INT_FNS_H__
#define __COVERAGEF_INT_FNS_H__
#include <stdbool.h>

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

// Enable or disable instrumentation
bool enable_instrumentation(const char *filename);
bool disable_instrumentation(void);

// (Re)configure instrumentation
bool configure(const char* filename, const char* mode, bool log_all_records,
            bool start_disabled, const char* process_name, bool pc_filter,
            target_ulong start_pc, target_ulong end_pc, const char* privilege);
bool reset(void);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
#endif
