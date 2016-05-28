#pragma once
#include <assert.h>

#define raslr_assert(condition, message) do { \
	if (!(condition)) { printf((message)); } \
	assert ((condition)); } while(false)

#define raslr_not_reachable() raslr_assert(false, "not reachable!")

#define raslr_log(fs, fmt, args ...) fprintf(fs, fmt, args)



/* 
 * configurations of raslr
 */

/* print debugging information */
//#define PRINT_INFO 1
//#define PRINT_DEBUG 1
//#define VERBOSE_MODE 1

// print value pointed to by the tracked pointer
//#define PRINT_VALUE

// support pointer mangling
#define PTR_MANGLE 1

// testing raslr with micro benchmark
//#define MICRO_BENCH 1
// testing raslr with macro benchmark
//#define MEASURE_TIME 1

// specify at which forking layer to perform the re-randomization
#define RAND_FORK_LAYER 2

/* file paths */
const char *policyFilePath = "outputs/tracking.policy";
const char *readablePolicyPath = "outputs/readable.policy";
const char *logFilePath = "outputs/raslr.log";
const char *taintVerPath = "outputs/taint.ver";

// range of a valid address
#define MAX_ADDRESS 0x800000000000
#define MIN_ADDRESS 0x400000

/* discarded attempts */
//#define USE_SUB_POLICY 1
//#define SUB_POLICY_LOC 1
//#define SUB_POLICY_HIBIT 1

