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

static void test_ipToStr_v4()
{
    auto fmt = [](uint8_t a, uint8_t b, uint8_t c, uint8_t d) -> std::string {
        std::array<uint8_t, 16> bytes{};
        bytes[0] = a; bytes[1] = b; bytes[2] = c; bytes[3] = d;
        IpStr s = ipToStr(bytes, 4);
        return std::string(s.buf.data());
    };

    ASSERT_STR_EQ(fmt(0,   0,   0,   0),   "0.0.0.0");
    ASSERT_STR_EQ(fmt(255, 255, 255, 255), "255.255.255.255");
    ASSERT_STR_EQ(fmt(192, 168, 1,   1),   "192.168.1.1");
    ASSERT_STR_EQ(fmt(10,  0,   0,   1),   "10.0.0.1");
    ASSERT_STR_EQ(fmt(8,   8,   8,   8),   "8.8.8.8");
}
REGISTER_TEST(test_ipToStr_v4);

static void test_ipToStr_v6()
{
    auto fmt = [](std::array<uint8_t, 16> bytes) -> std::string {
        IpStr s = ipToStr(bytes, 6);
        return std::string(s.buf.data());
    };

    // ::
    ASSERT_STR_EQ(fmt({{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}), "::");
    // ::1
    ASSERT_STR_EQ(fmt({{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}), "::1");
    // ::ffff:1.2.3.4 — IPv4-mapped IPv6; inet_ntop renders the v4 dotted suffix
    ASSERT_STR_EQ(fmt({{0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4}}), "::ffff:1.2.3.4");
    // 2001:db8:: (full first hextet, rest zero)
    ASSERT_STR_EQ(fmt({{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0}}), "2001:db8::");
    // fe80::1
    ASSERT_STR_EQ(fmt({{0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}), "fe80::1");
}
REGISTER_TEST(test_ipToStr_v6);

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
    // this undefined. int32_t(a - b) = INT32_MIN: seq_lt(a,b) treats it as
    // "less than" (INT32_MIN < 0 is true). Symmetrically, seq_geq(b, a)
    // computes int32_t(b - a) = INT32_MIN >= 0, which is false — so
    // seq_geq is NOT the boolean negation of seq_lt at this exact boundary.
    // Both assertions lock the current implementation behavior.
    const uint32_t a = 0x10000000u;
    const uint32_t b = a + 0x80000000u; // exactly 2^31 ahead
    ASSERT_EQ(seq_lt(a, b), true);
    ASSERT_EQ(seq_geq(b, a), false);
}
REGISTER_TEST(test_seq_compare_wrap);

static void test_flowrec_seq_field_defaults()
{
    flowRec fr;
    ASSERT_EQ((int)fr.outstanding_end, 0);
    ASSERT_EQ(fr.outstanding_time, 0.0);
    ASSERT_EQ((int)fr.high_seq, 0);
    ASSERT_EQ(fr.high_seq_init, false);
    ASSERT_EQ(fr.retx_flag, false);
    ASSERT_EQ(fr.tsCapable, false);
    ASSERT_EQ(fr.classified, false);
    ASSERT_EQ(fr.revFlowRec, (flowRec*)nullptr);
    // Aggregator additions:
    ASSERT_EQ((int)fr.n_samples, 0);
    ASSERT_EQ(fr.window_start, 0.0);
    ASSERT_EQ(fr.closed, false);
}
REGISTER_TEST(test_flowrec_seq_field_defaults);

static void test_capacity_defaults()
{
    ASSERT_EQ(maxFlows,  1048576);
    ASSERT_EQ(maxTSvals, (size_t)268435456);
    ASSERT_EQ(flowMaxAge, 1800.);     // new: 30 min, middle ground for ClickHouse buckets
    ASSERT_EQ(aggregateOutput, false);
    ASSERT_EQ(flowsDropped,   0);
    ASSERT_EQ(aggregatedRows, 0);
}
REGISTER_TEST(test_capacity_defaults);

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
 * emit_aggregated — formats one row to stdout in the -a / --aggregate
 * 9-field schema. Captures stdout via dup2 so we can assert the bytes.
 * ---------------------------------------------------------------------- */
#include <fcntl.h>
#include <unistd.h>

static std::string capture_stdout(std::function<void()> fn)
{
    fflush(stdout);
    int saved_fd = dup(fileno(stdout));
    FILE* tmp = tmpfile();
    if (!tmp) { perror("tmpfile"); return ""; }
    dup2(fileno(tmp), fileno(stdout));

    fn();

    fflush(stdout);
    dup2(saved_fd, fileno(stdout));
    close(saved_fd);

    rewind(tmp);
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, tmp);
    buf[n] = 0;
    fclose(tmp);
    return std::string(buf);
}

static void test_emit_aggregated_format()
{
    flowRec fr;
    fr.last_tm    = 12.345;
    fr.min        = 0.005;
    fr.n_samples  = 7;
    fr.tsCapable  = true;

    FlowKey fk = makeFlow4(192, 168, 1, 1, 10, 0, 0, 1, 1234, 80);

    int64_t saved_off = offTm;
    std::string saved_node = node;
    offTm = 1700000000;
    node = "testhost";

    std::string out = capture_stdout([&]() { emit_aggregated(&fr, fk); });

    offTm = saved_off;
    node = saved_node;

    ASSERT_STR_EQ(out,
        "1700000012.345000 0.005000 7 192.168.1.1 1234 10.0.0.1 80 testhost t\n");
}
REGISTER_TEST(test_emit_aggregated_format);

static void test_emit_aggregated_seq_tag()
{
    flowRec fr;
    fr.last_tm    = 5.0;
    fr.min        = 0.012;
    fr.n_samples  = 3;
    fr.tsCapable  = false;     // SEQ-only flow

    FlowKey fk = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);

    int64_t saved_off = offTm;
    std::string saved_node = node;
    offTm = 0;
    node = "h";

    std::string out = capture_stdout([&]() { emit_aggregated(&fr, fk); });

    offTm = saved_off;
    node = saved_node;

    ASSERT_STR_EQ(out,
        "5.000000 0.012000 3 10.0.0.1 1 10.0.0.2 2 h s\n");
}
REGISTER_TEST(test_emit_aggregated_seq_tag);

static void test_cleanUp_closed_emits_and_deletes()
{
    flows.clear();
    tsTbl.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    // Save & set globals
    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    capTm = 100.0;

    // Closed flow with samples — should emit + delete
    FlowKey f1 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr1 = new flowRec();
    fr1->last_tm = 50.0;
    fr1->min = 0.001;
    fr1->n_samples = 4;
    fr1->closed = true;
    fr1->tsCapable = true;
    fr1->window_start = 10.0;
    flows[f1] = fr1;
    flowCnt = 1;

    // Closed flow with no samples — should silently delete (no emit)
    FlowKey f2 = makeFlow4(10, 0, 0, 3, 10, 0, 0, 4, 1, 2);
    flowRec* fr2 = new flowRec();
    fr2->last_tm = 50.0;
    fr2->min = 1e30;
    fr2->n_samples = 0;
    fr2->closed = true;
    flows[f2] = fr2;
    flowCnt = 2;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // Both deleted
    ASSERT_EQ(flows.count(f1), 0u);
    ASSERT_EQ(flows.count(f2), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 1);

    // Output: exactly one line for f1
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 1);

    // Restore
    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_closed_emits_and_deletes);

static void test_cleanUp_idle_with_samples_emits()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    capTm = 1000.0;

    // Idle flow with samples — emits + deletes.
    // flowMaxIdle = 300 by default; idle = 1000 - 600 = 400 > 300.
    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 600.0;
    fr->min = 0.002;
    fr->n_samples = 5;
    fr->tsCapable = true;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    ASSERT_EQ(flows.count(f), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 1);
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 1);

    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_idle_with_samples_emits);

static void test_cleanUp_idle_zero_samples_silent_delete()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    bool saved_agg = aggregateOutput;
    aggregateOutput = true;
    capTm = 1000.0;

    // Idle flow with zero samples — silently deleted, no emit.
    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 600.0;
    fr->n_samples = 0;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    ASSERT_EQ(flows.count(f), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 0);
    ASSERT_STR_EQ(out, "");

    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_idle_zero_samples_silent_delete);

static void test_cleanUp_age_cap_resets_window_keeps_tcp_state()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    double saved_age = flowMaxAge;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    flowMaxAge = 100.;     // small for the test
    capTm = 200.0;

    // Active flow — packets recent, but window started long ago.
    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 195.0;        // recent — not idle
    fr->window_start = 50.0;    // 200 - 50 = 150 > flowMaxAge (100): cap fires
    fr->min = 0.003;
    fr->n_samples = 9;
    fr->tsCapable = true;
    // Some TCP state we expect to be preserved:
    fr->high_seq = 12345;
    fr->high_seq_init = true;
    fr->outstanding_end = 67890;
    fr->outstanding_time = 195.0;
    fr->bytesSnt = 1000.0;
    fr->lstBytesSnt = 800.0;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // Flow still in table
    ASSERT_EQ(flows.count(f), 1u);
    ASSERT_EQ(flowCnt, 1);
    ASSERT_EQ(aggregatedRows, 1);
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 1);

    flowRec* alive = flows[f];
    // Aggregator state reset:
    ASSERT_EQ((int)alive->n_samples, 0);
    ASSERT_EQ(alive->min, 1e30);
    ASSERT_EQ(alive->window_start, capTm);
    ASSERT_EQ(alive->lstBytesSnt, alive->bytesSnt);
    // TCP state preserved:
    ASSERT_EQ((int)alive->high_seq, 12345);
    ASSERT_EQ(alive->high_seq_init, true);
    ASSERT_EQ((int)alive->outstanding_end, 67890);
    ASSERT_EQ(alive->outstanding_time, 195.0);
    ASSERT_EQ(alive->bytesSnt, 1000.0);

    delete flows[f];
    flows.clear();
    flowCnt = 0;
    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
    flowMaxAge = saved_age;
}
REGISTER_TEST(test_cleanUp_age_cap_resets_window_keeps_tcp_state);

static void test_cleanUp_age_cap_skipped_in_non_agg_mode()
{
    // Bit-for-bit guarantee: in non-aggregator modes (-e, -m, human), an
    // age-cap-eligible flow must not be reset. fr->min and fr->lstBytesSnt
    // are visible in -e output; resetting them mid-flow would corrupt
    // the running minRTT and pBytes columns.
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    bool saved_agg = aggregateOutput;
    double saved_age = flowMaxAge;
    aggregateOutput = false;     // non-agg mode
    flowMaxAge = 100.;           // small for the test
    capTm = 200.0;

    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 195.0;          // recent — not idle
    fr->window_start = 50.0;      // 200 - 50 = 150 > flowMaxAge (100)
    fr->min = 0.003;
    fr->n_samples = 9;
    fr->bytesSnt = 1000.0;
    fr->lstBytesSnt = 800.0;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // No emit, no reset — flow untouched in non-agg mode.
    ASSERT_EQ(aggregatedRows, 0);
    ASSERT_STR_EQ(out, "");
    flowRec* alive = flows[f];
    ASSERT_EQ(alive->min, 0.003);                // untouched
    ASSERT_EQ(alive->lstBytesSnt, 800.0);        // untouched
    ASSERT_EQ(alive->window_start, 50.0);        // untouched
    ASSERT_EQ((int)alive->n_samples, 9);         // untouched

    delete flows[f];
    flows.clear();
    flowCnt = 0;
    aggregateOutput = saved_agg;
    flowMaxAge = saved_age;
}
REGISTER_TEST(test_cleanUp_age_cap_skipped_in_non_agg_mode);

static void test_cleanUp_age_cap_disabled_when_zero()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    bool saved_agg = aggregateOutput;
    double saved_age = flowMaxAge;
    aggregateOutput = true;
    flowMaxAge = 0.;       // disabled
    capTm = 1e9;           // very large

    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 1e9 - 1.;     // recent
    fr->window_start = 0.0;     // long-ago — would cap-fire if cap were enabled
    fr->n_samples = 5;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // No emit, no reset.
    ASSERT_EQ(aggregatedRows, 0);
    ASSERT_STR_EQ(out, "");
    ASSERT_EQ(flows[f]->window_start, 0.0);   // untouched
    ASSERT_EQ((int)flows[f]->n_samples, 5);

    delete flows[f];
    flows.clear();
    flowCnt = 0;
    aggregateOutput = saved_agg;
    flowMaxAge = saved_age;
}
REGISTER_TEST(test_cleanUp_age_cap_disabled_when_zero);

static void test_cleanUp_flush_all_drains_active_flows()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    capTm = 100.0;

    // Three active (non-idle, non-closed, no age-cap) flows.
    // f1, f2 have samples (should emit), f3 has zero (silent delete).
    FlowKey f1 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr1 = new flowRec();
    fr1->last_tm = 99.0; fr1->min = 0.001; fr1->n_samples = 3; fr1->tsCapable = true;
    flows[f1] = fr1;

    FlowKey f2 = makeFlow4(10, 0, 0, 3, 10, 0, 0, 4, 3, 4);
    flowRec* fr2 = new flowRec();
    fr2->last_tm = 99.5; fr2->min = 0.002; fr2->n_samples = 7; fr2->tsCapable = false;
    flows[f2] = fr2;

    FlowKey f3 = makeFlow4(10, 0, 0, 5, 10, 0, 0, 6, 5, 6);
    flowRec* fr3 = new flowRec();
    fr3->last_tm = 99.0; fr3->n_samples = 0;
    flows[f3] = fr3;

    flowCnt = 3;

    std::string out = capture_stdout([&]() { cleanUp(capTm, /*flush_all=*/true); });

    // All three deleted. Two emitted.
    ASSERT_EQ(flows.size(), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 2);
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 2);

    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_flush_all_drains_active_flows);

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
