// test_main.cpp
// Minimal test framework for DDS native Windows components.
//
// No external test framework dependency.  Provides:
//   DDS_ASSERT(cond, msg)  -- assertion macro
//   DDS_TEST(name)         -- test registration macro
//   main()                 -- runs all registered tests and prints results
//

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// ============================================================================
// Assertion support
// ============================================================================

struct DdsTestFailure
{
    const char* file;
    int         line;
    const char* message;
};

static std::vector<DdsTestFailure> g_failures;
static int g_currentTestFailed = 0;

#define DDS_ASSERT(cond, msg)                                               \
    do {                                                                    \
        if (!(cond)) {                                                      \
            DdsTestFailure _f;                                              \
            _f.file    = __FILE__;                                          \
            _f.line    = __LINE__;                                          \
            _f.message = (msg);                                             \
            g_failures.push_back(_f);                                       \
            g_currentTestFailed = 1;                                        \
            fprintf(stderr, "  FAIL  %s:%d: %s\n", __FILE__, __LINE__, msg);\
        }                                                                   \
    } while (0)

// ============================================================================
// Test registration
// ============================================================================

typedef void (*DdsTestFunc)();

struct DdsTestEntry
{
    const char*  name;
    DdsTestFunc  func;
};

static std::vector<DdsTestEntry>& GetTestRegistry()
{
    static std::vector<DdsTestEntry> s_tests;
    return s_tests;
}

struct DdsTestRegistrar
{
    DdsTestRegistrar(const char* name, DdsTestFunc func)
    {
        DdsTestEntry entry;
        entry.name = name;
        entry.func = func;
        GetTestRegistry().push_back(entry);
    }
};

#define DDS_TEST(name)                                                      \
    static void DdsTest_##name();                                           \
    static DdsTestRegistrar g_reg_##name(#name, &DdsTest_##name);           \
    static void DdsTest_##name()

// ============================================================================
// Include individual test files -- they use DDS_TEST / DDS_ASSERT above
// ============================================================================

#include "test_ipc_messages.cpp"
#include "test_dds_auth.cpp"

// ============================================================================
// main -- run all tests, print summary
// ============================================================================

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    auto& tests = GetTestRegistry();

    printf("=== DDS Native Tests ===\n");
    printf("Running %zu test(s)...\n\n", tests.size());

    int passed = 0;
    int failed = 0;

    for (size_t i = 0; i < tests.size(); i++)
    {
        g_currentTestFailed = 0;
        printf("[%zu/%zu] %s ... ", i + 1, tests.size(), tests[i].name);
        fflush(stdout);

        tests[i].func();

        if (g_currentTestFailed)
        {
            printf("FAILED\n");
            failed++;
        }
        else
        {
            printf("ok\n");
            passed++;
        }
    }

    printf("\n=== Results: %d passed, %d failed, %zu total ===\n",
           passed, failed, tests.size());

    if (!g_failures.empty())
    {
        printf("\nFailure details:\n");
        for (size_t i = 0; i < g_failures.size(); i++)
        {
            printf("  [%zu] %s:%d: %s\n",
                   i + 1,
                   g_failures[i].file,
                   g_failures[i].line,
                   g_failures[i].message);
        }
    }

    return (failed > 0) ? 1 : 0;
}
