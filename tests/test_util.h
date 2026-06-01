/* A tiny single-header test harness - no dependencies, just macros.
 *
 * Each test file defines test functions and lists them in a main() that calls
 * RUN(). CHECK() records a failure but keeps going so one run reports every
 * problem at once.
 */
#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);\
        }                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        g_checks++;                                                          \
        long _va = (long)(a), _vb = (long)(b);                               \
        if (_va != _vb) {                                                    \
            g_failures++;                                                    \
            fprintf(stderr, "  FAIL %s:%d: %s == %s (%ld != %ld)\n",         \
                    __FILE__, __LINE__, #a, #b, _va, _vb);                   \
        }                                                                    \
    } while (0)

#define RUN(fn)                                                              \
    do {                                                                     \
        printf("- %s\n", #fn);                                               \
        fn();                                                                \
    } while (0)

#define TEST_SUMMARY()                                                       \
    do {                                                                     \
        printf("\n%d checks, %d failure%s\n", g_checks, g_failures,          \
               g_failures == 1 ? "" : "s");                                  \
        return g_failures == 0 ? 0 : 1;                                      \
    } while (0)

#endif /* TEST_UTIL_H */
