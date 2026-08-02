#include <arpa/inet.h>
#include <errno.h>
#include <fmtmsg.h>
#include <fnmatch.h>
#include <math.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_identity/identity.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int    failures;
static size_t fault_resource_events;
static FILE  *outcome_stream;

#define P101_TEST_ERRNO_SENTINEL 0x5A5A

#ifdef __linux__
    #define P101_TEST_PLATFORM "linux"
#elif defined(__APPLE__)
    #define P101_TEST_PLATFORM "macos"
#elif defined(__FreeBSD__)
    #define P101_TEST_PLATFORM "freebsd"
#else
    #define P101_TEST_PLATFORM "posix"
#endif

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                                   \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

struct fault_state
{
    int checks;
    int code;
};

static void write_outcome(const char *wrapper, const char *domain, const char *symbol, int code, int passed)
{
    int written;

    if(outcome_stream == NULL)
    {
        return;
    }
    written = fprintf(outcome_stream, "P101WRAPPER\t1\tFAULT\t%s\tlib_identity\t%s\t%s\t%s\t%d\t%s\n", P101_TEST_PLATFORM, wrapper, domain, symbol, code, passed ? "PASS" : "FAIL");
    if(written < 0 || fflush(outcome_stream) != 0)
    {
        fprintf(stderr, "FAIL: cannot write wrapper outcome receipt\n");
        failures++;
    }
}

static int fail_next_call(const struct p101_env *env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)env;
    (void)call_name;
    state = user_data;
    state->checks++;
    return state->code;
}

static void count_fd_event(const struct p101_env *env, p101_env_fd_event event, int fd, const char *file_name, const char *function_name, int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)fd;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

static void count_alloc_event(const struct p101_env *env, p101_env_alloc_event event, const void *ptr, const void *new_ptr, size_t size, const char *file_name, const char *function_name, int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)ptr;
    (void)new_ptr;
    (void)size;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

static void count_resource_event(const struct p101_env *env, p101_env_resource_kind event, const char *resource_class, const char *resource_id, const char *related_id, size_t size, const char *metadata, const char *file_name, const char *function_name,
                                 int line_number, void *user_data)
{
    (void)env;
    (void)event;
    (void)resource_class;
    (void)resource_id;
    (void)related_id;
    (void)size;
    (void)metadata;
    (void)file_name;
    (void)function_name;
    (void)line_number;
    (void)user_data;
    fault_resource_events++;
}

/* P101_TEST_CASE(p101_crypt) */
static void test_p101_crypt(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EINVAL, ENOSYS, EPERM};
    static const char *const error_names[] = {"EINVAL", "ENOSYS", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {ENOSYS};
    static const char *const error_names[] = {"ENOSYS"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        char *result = p101_crypt(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_crypt", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getgrgid_r) */
static void test_p101_getgrgid_r(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
    static const char *const error_names[] = {"EBADF", "EINTR", "EIO", "EMFILE", "ENFILE", "ENOENT", "ENOMEM", "EPERM", "ERANGE", "ESRCH"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
    static const char *const error_names[] = {"EINTR", "EIO", "EMFILE", "ENFILE", "ERANGE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getgrgid_r(env, err, 0, NULL, argument_4, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getgrgid_r", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getgrnam_r) */
static void test_p101_getgrnam_r(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
    static const char *const error_names[] = {"EBADF", "EINTR", "EIO", "EMFILE", "ENFILE", "ENOENT", "ENOMEM", "EPERM", "ERANGE", "ESRCH"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#else
    static const int         errors[]      = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
    static const char *const error_names[] = {"EINTR", "EIO", "EMFILE", "ENFILE", "ERANGE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getgrnam_r(env, err, NULL, NULL, argument_4, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getgrnam_r", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getgroups) */
static void test_p101_getgroups(struct p101_env *env, struct p101_error *err)
{
    gid_t         argument_3[4];
    unsigned char argument_3_before[sizeof(argument_3)];
    memset(argument_3, 0xA5, sizeof(argument_3));
    memcpy(argument_3_before, argument_3, sizeof(argument_3));
#ifdef __linux__
    static const int         errors[]      = {EFAULT, EINVAL};
    static const char *const error_names[] = {"EFAULT", "EINVAL"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EFAULT, EINVAL};
    static const char *const error_names[] = {"EFAULT", "EINVAL"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EFAULT, EINVAL};
    static const char *const error_names[] = {"EFAULT", "EINVAL"};
#else
    static const int         errors[]      = {EINVAL};
    static const char *const error_names[] = {"EINVAL"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getgroups(env, err, 0, argument_3);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(memcmp(argument_3, argument_3_before, sizeof(argument_3)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getgroups", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getlogin_r) */
static void test_p101_getlogin_r(struct p101_env *env, struct p101_error *err)
{
    char          argument_2[4];
    unsigned char argument_2_before[sizeof(argument_2)];
    memset(argument_2, 0xA5, sizeof(argument_2));
    memcpy(argument_2_before, argument_2, sizeof(argument_2));
#ifdef __linux__
    static const int         errors[]      = {EMFILE, ENFILE, ENOENT, ENOMEM, ENOTTY, ENXIO, ERANGE};
    static const char *const error_names[] = {"EMFILE", "ENFILE", "ENOENT", "ENOMEM", "ENOTTY", "ENXIO", "ERANGE"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EMFILE, ENFILE, ENOTTY, ENXIO, ERANGE};
    static const char *const error_names[] = {"EMFILE", "ENFILE", "ENOTTY", "ENXIO", "ERANGE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EFAULT, EINVAL, EPERM, ERANGE};
    static const char *const error_names[] = {"EFAULT", "EINVAL", "EPERM", "ERANGE"};
#else
    static const int         errors[]      = {EMFILE, ENFILE, ENOTTY, ENXIO, ERANGE};
    static const char *const error_names[] = {"EMFILE", "ENFILE", "ENOTTY", "ENXIO", "ERANGE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getlogin_r(env, err, argument_2, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_2, argument_2_before, sizeof(argument_2)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getlogin_r", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getpwnam_r) */
static void test_p101_getpwnam_r(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
    static const char *const error_names[] = {"EBADF", "EINTR", "EIO", "EMFILE", "ENFILE", "ENOENT", "ENOMEM", "EPERM", "ERANGE", "ESRCH"};
#elif defined(__APPLE__)
    static const int         errors[]      = {ERANGE};
    static const char *const error_names[] = {"ERANGE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {ERANGE};
    static const char *const error_names[] = {"ERANGE"};
#else
    static const int         errors[]      = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
    static const char *const error_names[] = {"EINTR", "EIO", "EMFILE", "ENFILE", "ERANGE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getpwnam_r(env, err, NULL, NULL, argument_4, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getpwnam_r", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getpwuid_r) */
static void test_p101_getpwuid_r(struct p101_env *env, struct p101_error *err)
{
    char          argument_4[4];
    unsigned char argument_4_before[sizeof(argument_4)];
    memset(argument_4, 0xA5, sizeof(argument_4));
    memcpy(argument_4_before, argument_4, sizeof(argument_4));
#ifdef __linux__
    static const int         errors[]      = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
    static const char *const error_names[] = {"EBADF", "EINTR", "EIO", "EMFILE", "ENFILE", "ENOENT", "ENOMEM", "EPERM", "ERANGE", "ESRCH"};
#elif defined(__APPLE__)
    static const int         errors[]      = {ERANGE};
    static const char *const error_names[] = {"ERANGE"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {ERANGE};
    static const char *const error_names[] = {"ERANGE"};
#else
    static const int         errors[]      = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
    static const char *const error_names[] = {"EINTR", "EIO", "EMFILE", "ENFILE", "ERANGE"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getpwuid_r(env, err, 0, NULL, argument_4, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == state.code);
        EXPECT(memcmp(argument_4, argument_4_before, sizeof(argument_4)) == 0);
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_getpwuid_r", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_pututxline) */
static void test_p101_pututxline(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EIO};
    static const char *const error_names[] = {"EIO"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EINVAL, ESRCH};
    static const char *const error_names[] = {"EINVAL", "ESRCH"};
#else
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        struct utmpx *result = p101_pututxline(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (NULL));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_pututxline", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setegid) */
static void test_p101_setegid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EINVAL};
    static const char *const error_names[] = {"EINVAL"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#else
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setegid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setegid", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_seteuid) */
static void test_p101_seteuid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#else
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_seteuid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_seteuid", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setgid) */
static void test_p101_setgid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#else
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setgid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setgid", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setregid) */
static void test_p101_setregid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EINVAL, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#else
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setregid(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setregid", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setreuid) */
static void test_p101_setreuid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EINVAL, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#else
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setreuid(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setreuid", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setuid) */
static void test_p101_setuid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int         errors[]      = {EAGAIN, EINVAL, EPERM};
    static const char *const error_names[] = {"EAGAIN", "EINVAL", "EPERM"};
#elif defined(__APPLE__)
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#elif defined(__FreeBSD__)
    static const int         errors[]      = {EPERM};
    static const char *const error_names[] = {"EPERM"};
#else
    static const int         errors[]      = {EINVAL, EPERM};
    static const char *const error_names[] = {"EINVAL", "EPERM"};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};
        int                failures_before;

        failures_before = failures;
        EXPECT(p101_error_has_no_error(err));
        fault_resource_events = 0U;
        errno                 = P101_TEST_ERRNO_SENTINEL;
        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setuid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.code));
        EXPECT(errno == P101_TEST_ERRNO_SENTINEL);
        EXPECT(result == (-1));
        EXPECT(fault_resource_events == 0U);
        write_outcome("p101_setuid", "errno", error_names[index], state.code, failures == failures_before);
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

int main(void)
{
    const char        *outcome_path;
    struct p101_error *err;
    struct p101_env   *env;

    outcome_path = getenv("P101_WRAPPER_OUTCOME_LOG");
    if(outcome_path != NULL && outcome_path[0] != '\0')
    {
        outcome_stream = fopen(outcome_path, "a");
        if(outcome_stream == NULL)
        {
            fprintf(stderr, "FAIL: cannot open wrapper outcome receipt\n");
            return EXIT_FAILURE;
        }
    }
    err = p101_error_create(false);
    if(err == NULL)
    {
        if(outcome_stream != NULL)
        {
            (void)fclose(outcome_stream);
        }
        return EXIT_FAILURE;
    }
    env = p101_env_create(err, NULL);
    if(env == NULL)
    {
        p101_error_destroy(err);
        if(outcome_stream != NULL)
        {
            (void)fclose(outcome_stream);
        }
        return EXIT_FAILURE;
    }
    p101_env_set_fd_observer(env, count_fd_event, NULL);
    p101_env_set_alloc_observer(env, count_alloc_event, NULL);
    p101_env_set_resource_observer(env, count_resource_event, NULL);
    test_p101_crypt(env, err);
    test_p101_getgrgid_r(env, err);
    test_p101_getgrnam_r(env, err);
    test_p101_getgroups(env, err);
    test_p101_getlogin_r(env, err);
    test_p101_getpwnam_r(env, err);
    test_p101_getpwuid_r(env, err);
    test_p101_pututxline(env, err);
    test_p101_setegid(env, err);
    test_p101_seteuid(env, err);
    test_p101_setgid(env, err);
    test_p101_setregid(env, err);
    test_p101_setreuid(env, err);
    test_p101_setuid(env, err);
    p101_env_destroy(env);
    p101_error_destroy(err);
    if(outcome_stream != NULL && fclose(outcome_stream) != 0)
    {
        fprintf(stderr, "FAIL: cannot close wrapper outcome receipt\n");
        failures++;
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
