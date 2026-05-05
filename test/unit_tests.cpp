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

/* -------------------------------------------------------------------------
 * Helpers for building keys in tests.
 * ---------------------------------------------------------------------- */

static FlowKey makeFlow4(uint8_t s_a, uint8_t s_b, uint8_t s_c, uint8_t s_d,
                         uint8_t d_a, uint8_t d_b, uint8_t d_c, uint8_t d_d,
                         uint16_t sport, uint16_t dport)
{
    FlowKey k;
    k.srcIP = {{s_a, s_b, s_c, s_d}};
    k.dstIP = {{d_a, d_b, d_c, d_d}};
    k.sport = sport;
    k.dport = dport;
    k.af = 4;
    return k;
}

static TsKey makeTs4(uint8_t s_a, uint8_t s_b, uint8_t s_c, uint8_t s_d,
                     uint8_t d_a, uint8_t d_b, uint8_t d_c, uint8_t d_d,
                     uint16_t sport, uint16_t dport, uint32_t tsv)
{
    TsKey k;
    k.flow = makeFlow4(s_a, s_b, s_c, s_d, d_a, d_b, d_c, d_d, sport, dport);
    k.tsval = tsv;
    return k;
}

/* -------------------------------------------------------------------------
 * FlowKey / TsKey / ByteHash invariants
 * ---------------------------------------------------------------------- */

static void test_flowkey_padding()
{
    // Sizes are baked into the on-the-wire hash function. If they change,
    // every running pping that shares state (none today) would disagree —
    // but more importantly, _pad shifting silently breaks ByteHash equality.
    static_assert(sizeof(FlowKey) == 40, "FlowKey size guard");
    static_assert(sizeof(TsKey) == 48,   "TsKey size guard");

    // Same logical key constructed via two independent default-init paths
    // must be byte-identical. If padding leaks stack garbage, this fails.
    FlowKey k1 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1234, 80);
    FlowKey k2 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1234, 80);

    ASSERT_EQ(std::memcmp(&k1, &k2, sizeof(FlowKey)), 0);
    ASSERT_EQ(k1 == k2, true);

    ByteHash h;
    ASSERT_EQ(h(k1), h(k2));

    // The pad bytes themselves: walk from `af` forward and verify all-zero.
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&k1);
    // af is at offset 16+16+2+2 = 36; pad starts at 37
    for (size_t i = 37; i < sizeof(FlowKey); ++i) {
        ASSERT_EQ((int)p[i], 0);
    }

    // Same for TsKey: tsval at offset 40-43, pad at 44-47.
    TsKey t1 = makeTs4(10, 0, 0, 1, 10, 0, 0, 2, 1234, 80, 555);
    const uint8_t* tp = reinterpret_cast<const uint8_t*>(&t1);
    for (size_t i = 44; i < sizeof(TsKey); ++i) {
        ASSERT_EQ((int)tp[i], 0);
    }
}
REGISTER_TEST(test_flowkey_padding);

static void test_flowkey_reversed()
{
    FlowKey k = makeFlow4(10, 0, 0, 1, 192, 168, 1, 1, 12345, 443);
    FlowKey r = k.reversed();

    ASSERT_EQ(r.srcIP == k.dstIP, true);
    ASSERT_EQ(r.dstIP == k.srcIP, true);
    ASSERT_EQ((int)r.sport, (int)k.dport);
    ASSERT_EQ((int)r.dport, (int)k.sport);
    ASSERT_EQ((int)r.af,    (int)k.af);

    // round-trip: reversed().reversed() == original (byte-exact)
    FlowKey rr = r.reversed();
    ASSERT_EQ(std::memcmp(&rr, &k, sizeof(FlowKey)), 0);
}
REGISTER_TEST(test_flowkey_reversed);

static void test_flowkey_v4_v6_disambig()
{
    // Same first 4 IP bytes; only `af` differs. memcmp must NOT report equal.
    // Without the af field, a v4 key 1.2.3.4 and a v6 key starting 01:02:03:04::
    // would collide (both have zero in the trailing 12 bytes for v4).
    FlowKey v4;
    v4.srcIP = {{1, 2, 3, 4}};
    v4.dstIP = {{5, 6, 7, 8}};
    v4.sport = 100;
    v4.dport = 200;
    v4.af = 4;

    FlowKey v6 = v4;     // copy entire struct including padding
    v6.af = 6;           // only difference

    ASSERT_EQ(v4 == v6, false);

    // Hashes will essentially always differ — FNV-1a is sensitive to a
    // single-byte change. Treat equality as a regression worth flagging.
    ByteHash h;
    if (h(v4) == h(v6)) {
        std::fprintf(stderr,
            "  unexpected: v4 and v6 keys hashed equal (byte difference at af)\n");
        ++g_failures;
    }
}
REGISTER_TEST(test_flowkey_v4_v6_disambig);

static void test_seq_compare_wrap()
{
    // Identity / adjacent
    ASSERT_EQ(seq_lt(1u, 2u), true);
    ASSERT_EQ(seq_lt(2u, 1u), false);
    ASSERT_EQ(seq_lt(5u, 5u), false);
    ASSERT_EQ(seq_geq(5u, 5u), true);
    ASSERT_EQ(seq_geq(6u, 5u), true);
    ASSERT_EQ(seq_geq(4u, 5u), false);

    // Wrap: a just below 2^32, b just above 0. a < b in stream order.
    const uint32_t near_max = 0xFFFFFFFEu;
    const uint32_t small    = 0x00000002u;
    ASSERT_EQ(seq_lt(near_max, small), true);
    ASSERT_EQ(seq_geq(small, near_max), true);

    // Half-window edge case: a and b are exactly 2^31 apart. RFC 1323 leaves
    // this undefined; the implementation computes int32_t(a - b) < 0, which
    // for b = a + 2^31 yields INT32_MIN < 0 == true, so seq_lt returns true.
    const uint32_t a = 0x10000000u;
    const uint32_t b = a + 0x80000000u; // exactly 2^31 ahead
    ASSERT_EQ(seq_lt(a, b), true);
    ASSERT_EQ(seq_geq(b, a), true);
}
REGISTER_TEST(test_seq_compare_wrap);

/* -------------------------------------------------------------------------
 * addTS / cleanUp — migrated to FlowKey/TsKey + tsInfo-by-value.
 * ---------------------------------------------------------------------- */

static void test_addTS()
{
    // --- Scenario 1: first-write-wins ---
    tsTbl.clear();
    tsDropped = 0;

    TsKey k = makeTs4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 1000);
    addTS(k, tsInfo{1.0, 0, 0});
    addTS(k, tsInfo{2.0, 0, 0});

    ASSERT_EQ(tsTbl.at(k).t, 1.0);     // first write preserved
    ASSERT_EQ(tsTbl.size(), (size_t)1); // no duplicate entry

    tsTbl.clear();
    tsDropped = 0;

    // --- Scenario 2: drop-at-cap ---
    size_t savedMax = maxTSvals;
    maxTSvals = 5;

    for (size_t i = 0; i < maxTSvals; ++i) {
        TsKey kfill = makeTs4((uint8_t)i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        tsTbl.emplace(kfill, tsInfo{0.0, 0, 0});
    }
    ASSERT_EQ(tsTbl.size(), maxTSvals);

    TsKey ovr = makeTs4(99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    addTS(ovr, tsInfo{99.0, 0, 0});

    ASSERT_EQ(tsDropped, 1);
    ASSERT_EQ(tsTbl.count(ovr), (size_t)0);
    ASSERT_EQ(tsTbl.size(), maxTSvals);

    tsTbl.clear();
    maxTSvals = savedMax;
}
REGISTER_TEST(test_addTS);

static void test_addTS_no_leak_on_duplicate()
{
    // The pre-rewrite addTS() leaked tsInfo* on the duplicate-key path
    // (TODO #2). With by-value storage there's no pointer to leak — the
    // leak is structurally impossible. This test asserts the observable
    // consequences: duplicates don't grow size, and first-write wins.
    tsTbl.clear();
    tsDropped = 0;

    TsKey k = makeTs4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 1000);
    addTS(k, tsInfo{1.0, 100, 50});
    addTS(k, tsInfo{2.0, 200, 60});   // duplicate
    addTS(k, tsInfo{3.0, 300, 70});   // duplicate

    ASSERT_EQ(tsTbl.size(), (size_t)1);
    ASSERT_EQ(tsTbl.at(k).t, 1.0);
    ASSERT_EQ(tsTbl.at(k).fBytes, 100.0);  // payload from first write
    ASSERT_EQ(tsTbl.at(k).dBytes, 50.0);
    ASSERT_EQ(tsDropped, 0);

    tsTbl.clear();
}
REGISTER_TEST(test_addTS_no_leak_on_duplicate);

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
    TsKey stale = makeTs4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 1);
    TsKey fresh = makeTs4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 2);
    TsKey used  = makeTs4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 3);
    // age = 100 - 85 = 15 > 10  →  evicted
    tsTbl[stale] = tsInfo{85.0, 0.0, 0.0};
    // age = 100 - 95 = 5 < 10   →  survives
    tsTbl[fresh] = tsInfo{95.0, 0.0, 0.0};
    // negative t means "already used"; abs(-88)=88, age = 100-88 = 12 > 10 → evicted
    tsTbl[used]  = tsInfo{-88.0, 0.0, 0.0};

    cleanUp(100.0);

    ASSERT_EQ(tsTbl.count(stale), 0u);
    ASSERT_EQ(tsTbl.count(used),  0u);
    ASSERT_EQ(tsTbl.count(fresh), 1u);

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

    FlowKey f1 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr1 = new flowRec();
    fr1->last_tm = 500.0;
    flows[f1] = fr1;

    FlowKey f2 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 3, 1, 3);
    flowRec* fr2 = new flowRec();
    fr2->last_tm = 499.0;
    flows[f2] = fr2;

    flowCnt = 2;

    cleanUp(800.0);

    ASSERT_EQ(flows.count(f1), 1u);   // idle == 300, survives
    ASSERT_EQ(flows.count(f2), 0u);   // idle == 301, evicted
    ASSERT_EQ(flowCnt, 1);

    delete flows[f1];
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
