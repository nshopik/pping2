/*
 * unit_tests.cpp — hand-rolled unit tests for pping internals.
 *
 * Compile:
 *   g++ $(CPPFLAGS) $(CXXFLAGS) -o test/unit_tests test/unit_tests.cpp $(LDFLAGS)
 *
 * The file includes pping.cpp directly so static functions can be tested
 * without refactoring the source.  The `main` symbol in pping.cpp is renamed
 * to `pping_main` to avoid a collision with this file's own main().
 */

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

/* -------------------------------------------------------------------------
 * Minimal test framework
 * ---------------------------------------------------------------------- */

struct TestCase {
    const char* name;
    std::function<void()> fn;
};

static std::vector<TestCase> g_tests;
static int g_failures = 0;
static const char* g_current_test = nullptr;

#define REGISTER_TEST(fn) \
    static bool _reg_##fn = (g_tests.push_back({#fn, fn}), true)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::fprintf(stderr, "  ASSERT_EQ failed in %s: " #a " != " #b "\n", \
                         g_current_test); \
            ++g_failures; \
        } \
    } while (0)

#define ASSERT_STR_EQ(a, b) \
    do { \
        std::string _a(a), _b(b); \
        if (_a != _b) { \
            std::fprintf(stderr, "  ASSERT_STR_EQ failed in %s: \"%s\" != \"%s\"\n", \
                         g_current_test, _a.c_str(), _b.c_str()); \
            ++g_failures; \
        } \
    } while (0)

/* TODO() — marks an unimplemented test body.  Counts as a failure. */
#define TODO() \
    do { \
        std::fprintf(stderr, "  TODO: %s not yet implemented\n", g_current_test); \
        ++g_failures; \
    } while (0)

/* -------------------------------------------------------------------------
 * Pull in pping.cpp with its main() renamed so it doesn't conflict.
 * ---------------------------------------------------------------------- */
#define main pping_main
#include "../pping.cpp"
#undef main

/* -------------------------------------------------------------------------
 * Test functions
 * ---------------------------------------------------------------------- */

static void test_fmtTimeDiff()
{
    // Sub-millisecond, scaled*1e6 < 10: 0.000001s → 1.0us (%.2lf → "1.00us")
    ASSERT_STR_EQ(fmtTimeDiff(0.000001), "1.00us");

    // Sub-millisecond, scaled*1e6 in [10,100): 0.0000123s → 12.3us ("12.3us")
    ASSERT_STR_EQ(fmtTimeDiff(0.0000123), "12.3us");

    // Sub-millisecond, scaled*1e6 >= 100: 0.000456s → 456us (" %.0lf" → " 456us")
    ASSERT_STR_EQ(fmtTimeDiff(0.000456), " 456us");

    // Exactly 1ms boundary: scaled*1e3 = 1.0 (%.2lf → "1.00ms")
    ASSERT_STR_EQ(fmtTimeDiff(0.001), "1.00ms");

    // Mid-millisecond, scaled in [10,100): 0.0123s → 12.3ms ("12.3ms")
    ASSERT_STR_EQ(fmtTimeDiff(0.0123), "12.3ms");

    // Sub-second, scaled >= 100: 0.5s → 500ms (" %.0lf" → " 500ms")
    ASSERT_STR_EQ(fmtTimeDiff(0.5), " 500ms");

    // Exactly 1s boundary: dt stays 1.0, prefix="" (%.2lf → "1.00s")
    ASSERT_STR_EQ(fmtTimeDiff(1.0), "1.00s");

    // ~10s boundary: 9.99s uses %.2lf, 10.0s switches to %.1lf
    ASSERT_STR_EQ(fmtTimeDiff(9.99), "9.99s");
    ASSERT_STR_EQ(fmtTimeDiff(10.0), "10.0s");

    // ~100s boundary: 99.9s uses %.1lf, 100.0s switches to " %.0lf" (leading space)
    ASSERT_STR_EQ(fmtTimeDiff(99.9), "99.9s");
    ASSERT_STR_EQ(fmtTimeDiff(100.0), " 100s");
}
REGISTER_TEST(test_fmtTimeDiff);

static void test_printnz()
{
    // Zero input → empty string (condition is v > 0)
    ASSERT_STR_EQ(printnz(0, " packets, "), "");

    // Positive values → concatenation of decimal and suffix
    ASSERT_STR_EQ(printnz(5, " no TS opt, "), "5 no TS opt, ");
    ASSERT_STR_EQ(printnz(1234, " packets, "), "1234 packets, ");

    // Negative value → empty string (v > 0 is false)
    ASSERT_STR_EQ(printnz(-7, " no TS opt, "), "");
}
REGISTER_TEST(test_printnz);

static void test_addTS()
{
    // --- Scenario 1: first-write-wins ---
    tsTbl.clear();
    tsDropped = 0;

    addTS("flow+1000", new tsInfo(1.0, 0, 0));
    addTS("flow+1000", new tsInfo(2.0, 0, 0));

    ASSERT_EQ(tsTbl["flow+1000"]->t, 1.0);    // first write preserved
    ASSERT_EQ(tsTbl.size(), (size_t)1);        // no duplicate entry

    // clean up scenario 1 before the cap test
    for (auto& kv : tsTbl) delete kv.second;
    tsTbl.clear();
    tsDropped = 0;

    // --- Scenario 2: drop-at-cap ---
    // Override the cap to a small value so we don't allocate 4M objects.
    size_t savedMax = maxTSvals;
    maxTSvals = 5;

    for (size_t i = 0; i < maxTSvals; ++i) {
        tsTbl.emplace("fill+" + std::to_string(i), new tsInfo(0.0, 0, 0));
    }
    ASSERT_EQ(tsTbl.size(), maxTSvals);               // table is at cap

    addTS("overflow+0", new tsInfo(99.0, 0, 0));

    ASSERT_EQ(tsDropped, 1);                          // drop counter incremented
    ASSERT_EQ(tsTbl.count("overflow+0"), (size_t)0);  // key was not inserted
    ASSERT_EQ(tsTbl.size(), maxTSvals);               // size unchanged

    // clean up and restore
    for (auto& kv : tsTbl) delete kv.second;
    tsTbl.clear();
    maxTSvals = savedMax;
}
REGISTER_TEST(test_addTS);

static void test_cleanUp()
{
    // -----------------------------------------------------------------
    // Scenario 1: tsTbl stale eviction
    // cleanUp uses the global capTm for the age check:
    //   capTm - abs(ti->t) > tsvalMaxAge  →  evict
    // -----------------------------------------------------------------
    tsTbl.clear();
    flows.clear();
    flowCnt = 0;

    capTm = 100.0;
    // age = 100 - 85 = 15 > 10  →  evicted
    tsTbl["stale+1"] = new tsInfo(85.0, 0.0, 0.0);
    // age = 100 - 95 = 5 < 10   →  survives
    tsTbl["fresh+1"] = new tsInfo(95.0, 0.0, 0.0);
    // negative t means "already used"; abs(-88)=88, age = 100-88 = 12 > 10 → evicted
    tsTbl["used+1"]  = new tsInfo(-88.0, 0.0, 0.0);

    cleanUp(100.0);

    ASSERT_EQ(tsTbl.count("stale+1"), 0u);
    ASSERT_EQ(tsTbl.count("used+1"),  0u);
    ASSERT_EQ(tsTbl.count("fresh+1"), 1u);

    // clean up the surviving entry to avoid leaks
    delete tsTbl["fresh+1"];
    tsTbl.clear();

    // -----------------------------------------------------------------
    // Scenario 2: flow idle eviction
    // cleanUp(n) evicts flows where  n - fr->last_tm > flowMaxIdle
    // flowMaxIdle = 300.0, so strictly-greater is the boundary:
    //   idle == 300  →  survives  (not >)
    //   idle == 301  →  evicted
    // -----------------------------------------------------------------
    flows.clear();
    flowCnt = 0;

    // idle = 800 - 500 = 300 == flowMaxIdle  →  NOT > 300, survives
    flowRec* fr1 = new flowRec("10.0.0.1:1+10.0.0.2:2");
    fr1->last_tm = 500.0;
    flows["10.0.0.1:1+10.0.0.2:2"] = fr1;

    // idle = 800 - 499 = 301 > flowMaxIdle   →  evicted
    flowRec* fr2 = new flowRec("10.0.0.1:1+10.0.0.3:3");
    fr2->last_tm = 499.0;
    flows["10.0.0.1:1+10.0.0.3:3"] = fr2;

    flowCnt = 2;

    cleanUp(800.0);

    ASSERT_EQ(flows.count("10.0.0.1:1+10.0.0.2:2"), 1u);
    ASSERT_EQ(flows.count("10.0.0.1:1+10.0.0.3:3"), 0u);
    ASSERT_EQ(flowCnt, 1);

    // clean up the surviving flow
    delete flows["10.0.0.1:1+10.0.0.2:2"];
    flows.clear();
    flowCnt = 0;
}
REGISTER_TEST(test_cleanUp);

/* -------------------------------------------------------------------------
 * Test runner
 * ---------------------------------------------------------------------- */

int main()
{
    int run = 0;
    int failed = 0;

    for (auto& tc : g_tests) {
        g_current_test = tc.name;
        g_failures = 0;

        tc.fn();

        if (g_failures == 0) {
            std::printf("PASS %s\n", tc.name);
        } else {
            std::printf("FAIL %s (%d assertion(s) failed)\n", tc.name, g_failures);
            ++failed;
        }
        ++run;
    }

    std::printf("\n%d/%d unit tests passed\n", run - failed, run);
    return (failed > 0) ? 1 : 0;
}
