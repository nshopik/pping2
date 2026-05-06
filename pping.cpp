/**********************************************************************
 pping - Pollere Basic Passive Ping

 Copyright (C) 2017  Kathleen Nichols, Pollere, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


 Usage:
    pping -i interfacename
 or
    pping -r pcapfilename
 
 Typing pping without arguments gives a list of available optional arguments.

 Computes the round trip delay captured packets experience between
 the packet capture point to a host and prints this information to
 standard output, per flow.

 pping is provided as sample code for a basic passive
 ping. It is NOT intended as production code.

 pping operates on TCP headers, v4 or v6. It requires the
 following:
 - time of packet capture
 - packet IP source, destination, sport, and dport
 - TSval and ERC from packet TCP timestamp option
 - both directions of a connection

 The core mechanism saves the first time a TSval is seen and matches it
 with the first time that value is seen as a ERC in the reverse direction.
 Every match produces a round trip time line printed on
 standard output with the format:
    packet capture time (time this round trip delay was observed)
    round trip delay
    shortest round trip delay seen so far for this flow 
    flow in the form:  srcIP:port+dstIP:port

 For continued live use, output may be redirected to a file or
 piped to some sort of display or summarization widget.

 More information on pping is available at pollere.net/pping
 
  ***********************************************************************/

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <pcap.h>
#include <csignal>
#include <ctime>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <cmath>
#include <array>
#include <cstring>
#include "tins/tins.h"

using namespace Tins;

// Packed POD key for flow lookup. 40B total: 16+16+2+2+1 = 37 named bytes,
// then 3B trailing pad after `af`. Default member initializers zero everything
// (including _pad), so `FlowKey k;` produces a key whose padding bytes are
// guaranteed zero — required so memcmp/ByteHash agree across construction sites.
struct FlowKey {
    std::array<uint8_t, 16> srcIP{};   // v4 in first 4 bytes, rest zero
    std::array<uint8_t, 16> dstIP{};
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint8_t  af = 0;                   // 4 or 6 — disambiguates v4 from v6
    uint8_t  _pad[3] = {0, 0, 0};      // explicit pad — must remain zero

    bool operator==(const FlowKey& o) const noexcept {
        return std::memcmp(this, &o, sizeof(FlowKey)) == 0;
    }
    FlowKey reversed() const noexcept {
        FlowKey r;
        r.srcIP = dstIP;
        r.dstIP = srcIP;
        r.sport = dport;
        r.dport = sport;
        r.af = af;
        return r;
    }
};
static_assert(sizeof(FlowKey) == 40, "FlowKey size changed; tests rely on this");

// FlowKey + tsval. 40 + 4 named + 4B pad = 48B. Same zero-pad invariant.
struct TsKey {
    FlowKey flow{};
    uint32_t tsval = 0;
    uint8_t  _pad[4] = {0, 0, 0, 0};

    bool operator==(const TsKey& o) const noexcept {
        return std::memcmp(this, &o, sizeof(TsKey)) == 0;
    }
};
static_assert(sizeof(TsKey) == 48, "TsKey size changed; tests rely on this");

// FNV-1a over the raw bytes of T. Padding participates — that's why the
// zero-pad invariant above is load-bearing.
struct ByteHash {
    template<class T>
    size_t operator()(const T& k) const noexcept {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&k);
        size_t h = 14695981039346656037ULL;
        for (size_t i = 0; i < sizeof(T); ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        return h;
    }
};

// Wrap-safe TCP sequence-number comparison. Treats a, b as points on a
// 2^32 cycle; correct as long as |a - b| < 2^31 (RFC 1323 PAWS bound).
// Used unconditionally on the SEQ-path hot path; cost is sub/sign-compare.
static inline bool seq_lt(uint32_t a, uint32_t b) noexcept {
    return int32_t(a - b) < 0;
}
static inline bool seq_geq(uint32_t a, uint32_t b) noexcept {
    return int32_t(a - b) >= 0;
}
// TCP payload length from a libtins TCP PDU. inner_pdu()->size() if present;
// otherwise zero (pure ACK / SYN / FIN / RST). Safe on truncated frames.
static inline uint32_t tcp_payload_len(const TCP* t_tcp) noexcept {
    const PDU* inner = t_tcp->inner_pdu();
    return inner ? static_cast<uint32_t>(inner->size()) : 0u;
}

class flowRec
{
  public:
    flowRec() = default;
    ~flowRec() = default;

    double last_tm{};
    double min{1e30};   // current min value for capturepoint-to-source RTT
    double bytesSnt{};  // number of bytes sent through CP toward dst
                        // inbound-to-CP, or return, direction
    double lstBytesSnt{};   //value of bytesSnt for flow at previous pping printing
    double bytesDep{};  // set on RTT sample computation for the stream for which
                        // this flow is the "forward" or outbound-from-mp direction.
                        // It is the value of this bytes_snt when a TSval entry was made
                        // and is set when an RTT is computed for this stream by getting a
                        // match on TSval entry by reverse flow, i.e. the number of bytes
                        // departed through CP the last time an RTT was computed for this stream
    bool revFlow{};             //inidcates if a reverse flow has been seen
    // Peer flowRec* — set when both directions are first observed, nulled on
    // peer expiry. Lets the SEQ ACK fast-path skip the per-packet flows.find(rk).
    // revFlow stays sticky-true for the TS-path early-return logic; revFlowRec
    // is lifecycle-managed because it must never dangle.
    flowRec* revFlowRec{nullptr};

    // SEQ-path state (used in --mode seq and --mode hybrid for non-TS flows)
    uint32_t outstanding_end{0};   // expected ack; 0 = no measurement in flight
    double   outstanding_time{0.}; // capTm at store
    uint32_t high_seq{0};          // highest seq+eff_len seen forward
    bool     high_seq_init{false}; // sentinel-safe across full uint32 range
    bool     retx_flag{false};     // strict Karn: invalidate sample if set

    // Aggregator state (used in --aggregate mode for per-flow rows).
    uint32_t n_samples    = 0;        // RTT matches counted in current window;
                                      // resets on age-cap fire.
    double   window_start = 0.;       // capTm at flow creation (or last age-cap reset).
                                      // 0.0 means "not yet seen a packet" — process_packet
                                      // sets it on the inserted branch.
    bool     closed       = false;    // first FIN observed on this direction's flowRec,
                                      // or RST observed on either direction (peer's flag
                                      // is set via revFlowRec from the RST-receiving side).

    // Set once on first packet through process_packet, then never modified.
    bool     tsCapable{false};
    bool     classified{false};
};

struct tsInfo {
    double t;       //wall clock time of new TSval pkt arrival (negated after match)
    double fBytes;  //total bytes of flow through CP including this pkt
    double dBytes;  //total bytes departed
};

static std::unordered_map<FlowKey, flowRec*, ByteHash> flows;
static std::unordered_map<TsKey, tsInfo, ByteHash> tsTbl;

// Format a 16-byte IP slot (per af) as a printable string. Called only on the
// rare/print paths — never on the hot per-packet path.
static inline std::string ipToString(const std::array<uint8_t, 16>& bytes, uint8_t af)
{
    if (af == 4) {
        uint32_t ip_n;
        std::memcpy(&ip_n, bytes.data(), 4);
        return IPv4Address(ip_n).to_string();
    }
    return IPv6Address(bytes.data()).to_string();
}

// Human-readable "src:port+dst:port". Errors + human output only.
static inline std::string flowKeyName(const FlowKey& k)
{
    return ipToString(k.srcIP, k.af) + ":" + std::to_string(k.sport)
         + "+" + ipToString(k.dstIP, k.af) + ":" + std::to_string(k.dport);
}

#define SNAP_LEN 144                // maximum bytes per packet to capture
static double tsvalMaxAge = 10.;    // limit age of TSvals to use
static double flowMaxIdle = 300.;   // flow idle time until flow forgotten
static double sumInt = 10.;         // how often (sec) to print summary line
static bool sumExplicit = false;    // user passed -q/-v/--sumInt; suppresses
                                    // the pcap-mode silent default below
static int maxFlows = 1048576;   // 1024^2 — bumped per per-flow aggregation spec
static int flowCnt;
// tsTbl size cap. ~56GB IPv4 / ~74GB IPv6 at the cap (theoretical;
// real workloads at 1Mpps stay single-digit GB via tsvalMaxAge age-out).
// Sized large enough that 1Mpps captures don't hit the cap; the natural
// bound is tsvalMaxAge * (TSval-tick-rate * concurrent-TS-flows).
static size_t maxTSvals = 268435456;  // 16^7 = 2^28 — bumped per per-flow aggregation spec
static int tsDropped;
static int seqSamples;     // production: RTT samples emitted via SEQ path
static int seqKarnDrops;   // diagnostic: samples discarded by strict Karn
static int seqStale;       // diagnostic: outstanding measurements aged out
// Aggregator state. Off by default; -a / --aggregate enables.
static bool aggregateOutput = false;
static double flowMaxAge = 1800.;        // age-cap on per-flow accumulator (sec). 0=off.
static int flowsDropped = 0;             // new flows rejected at maxFlows cap (per summary period)
static int aggregatedRows = 0;           // -a rows emitted (per summary period)
enum class Mode { TS, SEQ, HYBRID };
static Mode mode = Mode::HYBRID;
// Set by SIGINT/SIGTERM handler to break the packet loop cleanly so the
// end-of-run wall-clock summary still prints on Ctrl+C from live capture.
static volatile sig_atomic_t stopRequested = 0;
// Set by SIGHUP handler (if --logfile is in use) so the packet loop can
// reopen the log file in place after an external rotation. Async-signal-safe:
// the handler only writes the flag; the actual reopen happens on the main
// thread between packets.
static volatile sig_atomic_t reopenRequested = 0;
static std::string logfilePath;   // empty when --logfile not used
static double time_to_run;      // how many seconds to capture (0=no limit)
static int maxPackets;          // max packets to capture (0=no limit)
static int64_t offTm = -1;      // first packet capture time (used to
                                // avoid precision loss when 52 bit timestamp
                                // normalized into FP double 47 bit mantissa)
static bool machineReadable = false;         // machine or human readable output
static bool extendedMachineOutput = false;   // extended machine output with all fields
static double capTm, startm;        // (in seconds)
static int pktCnt, not_tcp, no_TS, not_v4or6, uniDir;
static std::string node;            // FQDN hostname of this capture node
static std::string localIP;         // ignore pp through this address (display form)
static std::array<uint8_t, 16> localIPBytes{}; // packed form for hot-path compare
static uint8_t localIPaf = 0;       // 4 or 6 once localIP is parsed
static bool filtLocal = true;
static std::string filter("tcp");    // default bpf filter
static int64_t flushInt = 1 << 20;  // stdout flush interval (~uS)
static int64_t nextFlush;       // next stdout flush time (~uS)


// save capture time of packet using its flow + TSval as key.  If key
// exists, don't change it.  The same TSval may appear on multiple
// packets so this retains the first (oldest) appearance which may
// overestimate RTT but won't underestimate. This slight bias may be
// reduced by adding additional fields to the key (such as packet's
// ending tcp_seq to match against returned tcp_ack) but this can
// substantially increase the state burden for a small improvement.

static inline void addTS(const TsKey& key, const tsInfo& ti)
{
    // Below cap: try_emplace gives first-write-wins for free.
    // At cap: count a *new* key as dropped; an existing key would be a no-op
    // anyway so skip the insert. Storage is by-value, so the duplicate-key
    // path can't leak (TODO #2 fix folded in).
    if (tsTbl.size() < maxTSvals) {
        tsTbl.try_emplace(key, ti);
    } else if (tsTbl.find(key) == tsTbl.end()) {
        ++tsDropped;
    }
}

// A packet's ECR (timestamp echo reply) should match the TSval of some
// packet seen earlier in the flow's reverse direction so lookup the
// capture time recorded above using the reversed flow + ECR as key. If
// found, the difference between now and capture time of that packet is
// >= the current RTT. Multiple packets may have the same ECR but the
// first packet's capture time gives the best RTT estimate so the time
// in the entry is negated after retrieval to prevent reuse.  The entry
// can't be deleted yet because TSvals may change on time scales longer
// than the RTT so a deleted entry could be recreated by a later packet
// with the same TSval which could match an ECR from an earlier
// incarnation resulting in a large RTT underestimate.  Table entries
// are deleted after a time interval (tsvalMaxAge) that should be:
//  a) longer than the largest time between TSval ticks
//  b) longer than longest queue wait packets are expected to experience

static std::string fmtTimeDiff(double dt)
{
    const char* SIprefix = "";
    if (dt < 1e-3) {
        dt *= 1e6;
        SIprefix = "u";
    } else if (dt < 1) {
        dt *= 1e3;
        SIprefix = "m";
    } 
    const char* fmt;
    if (dt < 10.) {
        fmt = "%.2lf%ss";
    } else if (dt < 100.) {
        fmt = "%.1lf%ss";
    } else {
        fmt = " %.0lf%ss";
    }
    char buf[10];
    snprintf(buf, sizeof(buf), fmt, dt, SIprefix);
    return buf;
}

/*
 * return (approximate) time in a 64bit fixed point integer with the
 * binary point at bit 20. High accuracy isn't needed (this time is
 * only used to control output flushing) so time is stretched ~5%
 * ((1024^2)/1e6) to avoid a 64 bit multiply.
 */
static int64_t clock_now(void) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t(tv.tv_sec) << 20) | tv.tv_usec;
}

// Shared output helper for both the TS and SEQ paths. `tag` is 't' (TS path)
// or 's' (SEQ path); always emitted for -e and human formats, omitted from -m.
static void emit(double rtt, flowRec* fr, const FlowKey& fk,
                 double fBytes, double dBytes, double pBytes, char tag)
{
    std::string ipsstr = ipToString(fk.srcIP, fk.af);
    std::string ipdstr = ipToString(fk.dstIP, fk.af);

    if (extendedMachineOutput) {
        printf("%" PRId64 ".%06d %.6f %.6f %.0f %.0f %.0f %s %u %s %u %s %c\n",
                int64_t(capTm + offTm), int((capTm - floor(capTm)) * 1e6),
                rtt, fr->min, fBytes, dBytes, pBytes,
                ipsstr.c_str(), fk.sport,
                ipdstr.c_str(), fk.dport,
                node.c_str(),
                tag);
    } else if (machineReadable) {
        printf("%" PRId64 ".%06d %.6f %s %s\n",
                int64_t(capTm + offTm), int((capTm - floor(capTm)) * 1e6),
                rtt, ipsstr.c_str(), ipdstr.c_str());
    } else {
        std::time_t result = static_cast<std::time_t>(int64_t(capTm + offTm));
        char tbuff[80];
        struct tm* ptm = std::localtime(&result);
        strftime(tbuff, 80, "%T", ptm);
        printf("%s %s %s %s:%u+%s:%u [%c]\n",
               tbuff, fmtTimeDiff(rtt).c_str(),
               fmtTimeDiff(fr->min).c_str(),
               ipsstr.c_str(), fk.sport, ipdstr.c_str(), fk.dport,
               tag);
    }
    int64_t now = clock_now();
    if (now - nextFlush >= 0) {
        nextFlush = now + flushInt;
        fflush(stdout);
    }
}

// Aggregator output helper — emits one row per flow per closure-or-window event.
// Called only from cleanUp; invariant: caller has verified n_samples > 0 and
// aggregateOutput == true. Row timestamp uses fr->last_tm (not capTm at the
// cleanUp tick) so emission time matches the last packet seen on this flow.
// Format: "epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag\n"
static void emit_aggregated(const flowRec* fr, const FlowKey& fk)
{
    std::string ipsstr = ipToString(fk.srcIP, fk.af);
    std::string ipdstr = ipToString(fk.dstIP, fk.af);
    printf("%" PRId64 ".%06d %.6f %u %s %u %s %u %s %c\n",
           int64_t(fr->last_tm + offTm),
           int((fr->last_tm - floor(fr->last_tm)) * 1e6),
           fr->min, fr->n_samples,
           ipsstr.c_str(), fk.sport,
           ipdstr.c_str(), fk.dport,
           node.c_str(),
           fr->tsCapable ? 't' : 's');
    int64_t now = clock_now();
    if (now - nextFlush >= 0) {
        nextFlush = now + flushInt;
        fflush(stdout);
    }
}

static void process_packet(const Packet& pkt)
{
    pktCnt++;
    const TCP* t_tcp;
    if ((t_tcp = pkt.pdu()->find_pdu<TCP>()) == nullptr) {
        not_tcp++;
        return;
    }

    // FlowKey + IP/IPv6 selection (unchanged)
    FlowKey fk;
    const IP* ip;
    const IPv6* ipv6;
    if ((ip = pkt.pdu()->find_pdu<IP>()) != nullptr) {
        uint32_t s = ip->src_addr();
        uint32_t d = ip->dst_addr();
        std::memcpy(fk.srcIP.data(), &s, 4);
        std::memcpy(fk.dstIP.data(), &d, 4);
        fk.af = 4;
    } else if ((ipv6 = pkt.pdu()->find_pdu<IPv6>()) != nullptr) {
        IPv6Address sa = ipv6->src_addr();
        IPv6Address da = ipv6->dst_addr();
        std::copy(sa.begin(), sa.end(), fk.srcIP.begin());
        std::copy(da.begin(), da.end(), fk.dstIP.begin());
        fk.af = 6;
    } else {
        not_v4or6++;
        return;
    }
    fk.sport = t_tcp->sport();
    fk.dport = t_tcp->dport();

    // capture clock time (unchanged)
    if (offTm < 0) {
        offTm = static_cast<int64_t>(pkt.timestamp().seconds());
        startm = double(pkt.timestamp().microseconds()) * 1e-6;
        capTm = startm;
        if (sumInt) {
            std::time_t first = pkt.timestamp().seconds();
            std::cerr << "First packet at "
                      << std::asctime(std::localtime(&first)) << "\n";
        }
    } else {
        int64_t tt = static_cast<int64_t>(pkt.timestamp().seconds()) - offTm;
        capTm = double(tt) + double(pkt.timestamp().microseconds()) * 1e-6;
    }

    auto fres = flows.try_emplace(fk, nullptr);
    auto fit = fres.first;
    bool inserted = fres.second;
    flowRec* fr;
    if (inserted) {
        if (flowCnt >= maxFlows) {
            // Cap rejection — increment counter; the per-packet stderr line
            // was removed because at high pps it would flood stderr. Counter
            // surfaces in printSummary as "<n> flows dropped (cap),".
            ++flowsDropped;
            flows.erase(fit);
            return;
        }
        fr = new flowRec();
        fr->window_start = capTm;
        fit->second = fr;
        flowCnt++;
        // Reverse-flow lookup runs only on first-packet-of-flow, not per-packet.
        const FlowKey rk = fk.reversed();
        auto rit = flows.find(rk);
        if (rit != flows.end()) {
            rit->second->revFlow = true;
            rit->second->revFlowRec = fr;
            fr->revFlow = true;
            fr->revFlowRec = rit->second;
        }
    } else {
        fr = fit->second;
    }
    fr->last_tm = capTm;

    // Defer TSOPT parse until after flow classification: only first-packet
    // (to set tsCapable) or subsequent packets of TS-capable flows need it.
    // Non-TS flows in --mode seq/hybrid skip the option search entirely.
    bool tsopt_present = false;
    uint32_t rcv_tsval = 0, rcv_tsecr = 0;
    if (!fr->classified || fr->tsCapable) {
        const auto* tsopt = t_tcp->search_option(TCP::TSOPT);
        tsopt_present = (tsopt && tsopt->data_size() >= 8);
        if (tsopt_present) {
            uint32_t be;
            std::memcpy(&be, tsopt->data_ptr(),     4); rcv_tsval = ntohl(be);
            std::memcpy(&be, tsopt->data_ptr() + 4, 4); rcv_tsecr = ntohl(be);
        }
    }

    // Classify the flow on its first packet (set once, never changes).
    if (!fr->classified) {
        fr->tsCapable = tsopt_present;
        fr->classified = true;
    }

    if (!fr->revFlow) {
        uniDir++;
        return;
    }
    // Close-flag detection. FIN is unidirectional in TCP — A's FIN closes A→B
    // but B may still send. RST kills both directions; propagate to the peer
    // flowRec via the cached pointer (null-checked since the peer may have
    // been idle-evicted earlier).
    {
        const auto cflags = t_tcp->flags();
        if (cflags & TCP::FIN) {
            fr->closed = true;
        }
        if (cflags & TCP::RST) {
            fr->closed = true;
            if (fr->revFlowRec) fr->revFlowRec->closed = true;
        }
    }
    double arr_fwd = fr->bytesSnt + pkt.pdu()->size();
    fr->bytesSnt = arr_fwd;

    // Mode dispatch.
    const bool useSeq =
        (mode == Mode::SEQ) ||
        (mode == Mode::HYBRID && !fr->tsCapable);
    const bool useTs =
        (mode == Mode::TS && fr->tsCapable) ||
        (mode == Mode::HYBRID && fr->tsCapable);

    if (mode == Mode::TS && !fr->tsCapable) {
        // Today's behavior in --mode ts: count and drop.
        no_TS++;
        return;
    }

    bool toLocal = filtLocal && localIPaf == fk.af
                && std::memcmp(localIPBytes.data(), fk.dstIP.data(), 16) == 0;

    if (useTs) {
        // Existing TS path: preserves the rcv_tsval / rcv_tsecr sanity checks.
        if (rcv_tsval == 0 || (rcv_tsecr == 0 && (t_tcp->flags() != TCP::SYN))) {
            return;
        }
        if (!toLocal) {
            TsKey tk;
            tk.flow = fk;
            tk.tsval = rcv_tsval;
            addTS(tk, tsInfo{capTm, arr_fwd, fr->bytesDep});
        }
        TsKey lookup;
        lookup.flow = fk.reversed();
        lookup.tsval = rcv_tsecr;
        auto eit = tsTbl.find(lookup);
        if (eit != tsTbl.end() && eit->second.t > 0.0) {
            double t = eit->second.t;
            double rtt = capTm - t;
            if (fr->min > rtt) fr->min = rtt;
            ++fr->n_samples;   // aggregator: count this match in the current window
            double fBytes = eit->second.fBytes;
            double dBytes = eit->second.dBytes;
            double pBytes = arr_fwd - fr->lstBytesSnt;
            fr->lstBytesSnt = arr_fwd;
            // Use the cached reverse-flow pointer; null when peer expired
            // (equivalent to the prior flows.find(rk) miss). Note: if the peer
            // expires and is later re-created with the same FlowKey, the cached
            // pointer stays null until *this* flow itself is re-inserted (the
            // linkage at line ~434 only fires on the inserted branch). The
            // original flows.find(rk) would have re-discovered the recycled
            // peer and written bytesDep to a fresh-but-unrelated flowRec; the
            // new behavior is strictly more conservative.
            if (fr->revFlowRec) fr->revFlowRec->bytesDep = fBytes;
            if (!aggregateOutput) {
                emit(rtt, fr, fk, fBytes, dBytes, pBytes, /*tag=*/'t');
            }
            eit->second.t = -t;
        }
    }

    if (useSeq) {
        const uint32_t seq    = t_tcp->seq();
        const auto     flags  = t_tcp->flags();
        const uint32_t pay    = tcp_payload_len(t_tcp);
        const uint32_t eff_len = pay
                               + ((flags & TCP::SYN) ? 1u : 0u)
                               + ((flags & TCP::FIN) ? 1u : 0u);

        // Forward direction: open or refresh outstanding measurement
        if (eff_len > 0 && !toLocal) {
            const uint32_t end = seq + eff_len;
            if (!fr->high_seq_init) {
                // First forward data packet — seed retx baseline and open
                // the outstanding measurement on this flow.
                fr->high_seq          = end;
                fr->high_seq_init     = true;
                fr->outstanding_end   = end;
                fr->outstanding_time  = capTm;
                fr->retx_flag         = false;
            } else if (seq_lt(seq, fr->high_seq)) {
                // Retransmission of bytes already seen forward.
                if (fr->outstanding_end != 0) fr->retx_flag = true;
            } else {
                if (seq_geq(end, fr->high_seq)) fr->high_seq = end;
                if (fr->outstanding_end == 0) {
                    fr->outstanding_end  = end;
                    fr->outstanding_time = capTm;
                    fr->retx_flag        = false;
                }
                // else: in-flight data while a measurement is pending — do
                // nothing (one outstanding per direction).
            }
        }

        // Reverse direction: ACK that crosses the outstanding boundary closes
        // the in-flight measurement on the forward (reverse-of-this-packet) flow.
        if (flags & TCP::ACK) {
            const uint32_t ack = t_tcp->ack_seq();
            // Cached reverse-flow pointer; replaces a per-ACK flows.find(rk).
            // Null when the peer has expired (cleanUp unlinks before delete).
            flowRec* rr = fr->revFlowRec;
            if (rr && rr->outstanding_end != 0 && seq_geq(ack, rr->outstanding_end)) {
                const double rtt        = capTm - rr->outstanding_time;
                const bool   karn_clean = !rr->retx_flag;
                rr->outstanding_end = 0;
                rr->retx_flag       = false;
                if (karn_clean) {
                    if (rr->min > rtt) rr->min = rtt;
                    ++rr->n_samples;   // aggregator: count this match on the data-carrying flowRec
                    ++seqSamples;

                    // The RTT belongs to the forward (rr) flow; emit using
                    // its key. The fk in this scope is the reverse direction.
                    FlowKey ffk = fk.reversed();
                    const double fBytes = rr->bytesSnt;
                    const double dBytes = rr->bytesDep;
                    const double pBytes = rr->bytesSnt - rr->lstBytesSnt;
                    rr->lstBytesSnt = rr->bytesSnt;
                    if (!aggregateOutput) {
                        emit(rtt, rr, ffk, fBytes, dBytes, pBytes, /*tag=*/'s');
                    }
                } else {
                    ++seqKarnDrops;
                }
            }
        }
    }
}

static void cleanUp(double n, bool flush_all = false)
{
    // erase entry if its TSval was seen more than tsvalMaxAge
    // seconds in the past.
    for (auto it = tsTbl.begin(); it != tsTbl.end();) {
        if (capTm - std::abs(it->second.t) > tsvalMaxAge) {
            it = tsTbl.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = flows.begin(); it != flows.end();) {
        flowRec* fr = it->second;

        // Determine emission reason. Priority: shutdown-flush > closed > idle > age-cap.
        // shutdown-flush emits any flow with samples regardless of trigger.
        bool emit_now    = false;
        bool delete_after = false;
        bool reset_window = false;

        if (flush_all) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            delete_after = true;
        } else if (fr->closed) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            delete_after = true;
        } else if (n - fr->last_tm > flowMaxIdle) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            delete_after = true;
        } else if (aggregateOutput && flowMaxAge > 0. && capTm - fr->window_start > flowMaxAge) {
            // Age-cap is aggregator-only: resetting fr->min/lstBytesSnt
            // for non-agg modes would mid-stream-clear the running minRTT
            // exposed in -e/-m/human output, violating the spec's
            // "bit-for-bit unchanged" guarantee for those modes.
            emit_now = fr->n_samples > 0;
            reset_window = true;
        }

        if (emit_now) {
            emit_aggregated(fr, it->first);
            ++aggregatedRows;
        }

        if (delete_after) {
            // Unlink peer's cached pointer before delete to avoid dangling.
            if (fr->revFlowRec) fr->revFlowRec->revFlowRec = nullptr;
            delete fr;
            it = flows.erase(it);
            flowCnt--;
            continue;
        }

        if (reset_window) {
            fr->n_samples    = 0;
            fr->min          = 1e30;
            fr->window_start = capTm;
            fr->lstBytesSnt  = fr->bytesSnt;
        }

        // Age out unmatched SEQ-path outstanding measurements. Same threshold
        // as the TS-path tsTbl entries.
        if (fr->outstanding_end != 0 &&
            capTm - fr->outstanding_time > tsvalMaxAge) {
            fr->outstanding_end = 0;
            fr->retx_flag       = false;
            ++seqStale;
        }
        ++it;
    }
}

static std::string getFQDN()
{
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return "unknown";
    }
    struct addrinfo hints{}, *info;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(hostname, nullptr, &hints, &info) != 0 || !info) {
        return hostname;
    }
    std::string fqdn = info->ai_canonname;
    freeaddrinfo(info);
    return fqdn;
}

// return the local ip address of 'ifname'
// XXX since an interface can have multiple addresses, both IP4 and IP6,
// this should really create a set of all of them and later test for
// membership. But for now we just take the first IP4 address.
static std::string localAddrOf(const std::string ifname)
{
    std::string local{};
    struct ifaddrs* ifap;

    if (getifaddrs(&ifap) == 0) {
        for (auto ifp = ifap; ifp; ifp = ifp->ifa_next) {
            if (ifname == ifp->ifa_name &&
                  ifp->ifa_addr->sa_family == AF_INET) {
                uint32_t ip = ((struct sockaddr_in*)
                               ifp->ifa_addr)->sin_addr.s_addr;
                local = IPv4Address(ip).to_string();
                break;
            }
        }
        freeifaddrs(ifap);
    }
    return local;
}

static void handleSignal(int) { stopRequested = 1; }

static void handleSighup(int) { reopenRequested = 1; }

// Reopen the --logfile path: open a fresh fd, dup2 onto stdout, close the
// extra fd. Used at startup (before the packet loop) and from the main loop
// when reopenRequested is set by SIGHUP. On reopen failure we keep the
// existing stdout — never silently lose output.
static bool reopenLogfile(const char* path)
{
    fflush(stdout);
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return false;
    int rc = dup2(fd, STDOUT_FILENO);
    int saved_errno = errno;
    close(fd);
    if (rc < 0) {
        errno = saved_errno;
        return false;
    }
    return true;
}

// Drop root after the packet socket / pcap file is open. The packet loop
// then parses untrusted bytes (network or pcap) through libtins as an
// unprivileged user, so a parse-time memory bug cannot pivot to root.
// No-op when not running as root (e.g. installed with `setcap cap_net_raw+ep`).
static void dropPrivileges(const char* user)
{
    if (geteuid() != 0) {
        return;
    }
    struct passwd* pw = getpwnam(user);
    if (pw == nullptr) {
        std::cerr << "fatal: user '" << user
                  << "' not found; refusing to run packet parser as root\n";
        exit(EXIT_FAILURE);
    }
    if (setgroups(0, nullptr) != 0) { perror("setgroups"); exit(EXIT_FAILURE); }
    if (setgid(pw->pw_gid) != 0)    { perror("setgid");    exit(EXIT_FAILURE); }
    if (setuid(pw->pw_uid) != 0)    { perror("setuid");    exit(EXIT_FAILURE); }
    // sanity: confirm we cannot regain uid 0
    if (setuid(0) == 0) {
        std::cerr << "fatal: privilege drop failed (regained root)\n";
        exit(EXIT_FAILURE);
    }
#ifdef __linux__
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
    }
#endif
}

static inline std::string printnz(int v, const char *s) {
    return (v > 0? std::to_string(v) + s : "");
}

static void printSummary()
{
    std::cerr << flowCnt << " flows, "
              << pktCnt << " packets, " +
                 printnz(no_TS, " no TS opt, ") +
                 printnz(uniDir, " uni-directional, ") +
                 printnz(not_tcp, " not TCP, ") +
                 printnz(not_v4or6, " not v4 or v6, ") +
                 printnz(tsDropped, " tsTbl drops, ") +
                 printnz(seqSamples, " seq samples, ") +
                 printnz(seqKarnDrops, " seq karn drops, ") +
                 printnz(seqStale, " seq stale, ") +
                 printnz(aggregatedRows, " aggregated rows, ") +
                 printnz(flowsDropped, " flows dropped (cap), ") +
                 "\n";
}

static struct option opts[] = {
    { "interface", required_argument, nullptr, 'i' },
    { "read",      required_argument, nullptr, 'r' },
    { "filter",    required_argument, nullptr, 'f' },
    { "count",     required_argument, nullptr, 'c' },
    { "seconds",   required_argument, nullptr, 's' },
    { "quiet",     no_argument,       nullptr, 'q' },
    { "verbose",   no_argument,       nullptr, 'v' },
    { "showLocal", no_argument,       nullptr, 'l' },
    { "machine",   no_argument,       nullptr, 'm' },
    { "extended",  no_argument,       nullptr, 'e' },
    { "aggregate", no_argument,       nullptr, 'a' },
    { "sumInt",    required_argument, nullptr, 'S' },
    { "tsvalMaxAge", required_argument, nullptr, 'M' },
    { "flowMaxIdle", required_argument, nullptr, 'F' },
    { "help",      no_argument,       nullptr, 'h' },
    { "mode",      required_argument, nullptr,  0  },   // long-only
    { "flowMaxAge", required_argument, nullptr, 0 },    // long-only
    { "logfile",   required_argument, nullptr, 0 },     // long-only
    { 0, 0, 0, 0 }
};

static void usage(const char* pname) {
    std::cerr << "usage: " << pname << " [flags] -i interface | -r pcapFile\n";
}

static void help(const char* pname) {
    usage(pname);
    std::cerr << " flags:\n"
"  -i|--interface ifname   do live capture from interface <ifname>\n"
"\n"
"  -r|--read pcap     process capture file <pcap>\n"
"\n"
"  -f|--filter expr   pcap filter applied to packets.\n"
"                     Eg., \"-f 'net 74.125.0.0/16 or 45.57.0.0/17'\"\n" 
"                     only shows traffic to/from youtube or netflix.\n"
"\n"
"  -m|--machine       'machine readable' output format suitable\n"
"                     for graphing or post-processing. Timestamps\n"
"                     are printed as seconds since capture start.\n"
"                     RTT is printed as seconds with a resolution of\n"
"                     1us (6 digits after decimal point).\n"
"                     Fields: timestamp rtt srcIP dstIP\n"
"\n"
"  -e|--extended      'machine readable' output format suitable\n"
"                     for graphing or post-processing. Timestamps\n"
"                     are printed as seconds since capture start.\n"
"                     RTT and minRTT are printed as seconds. All\n"
"                     times have a resolution of 1us (6 digits after\n"
"                     decimal point).\n"
"                     Fields: timestamp rtt minRTT fBytes dBytes pBytes\n"
"                     srcIP sport dstIP dport node\n"
"\n"
"  -a|--aggregate     emit one row per flow per closure-or-window event\n"
"                     instead of one row per RTT match. Mutually exclusive\n"
"                     with -e and -m. Row format (9 fields, space-separated):\n"
"                       epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag\n"
"                     epoch.usec is the flow's last_tm; min_rtt is in seconds.\n"
"                     Triggers: FIN/RST close (this dir for FIN, both for RST),\n"
"                     idle expiry via --flowMaxIdle, age-cap via --flowMaxAge,\n"
"                     and shutdown flush. Designed for direct ingestion into\n"
"                     ClickHouse.\n"
"\n"
"  -c|--count num     stop after capturing <num> packets\n"
"\n"
"  -s|--seconds num   stop after capturing for <num> seconds \n"
"\n"
"  -q|--quiet         don't print summary reports to stderr\n"
"\n"
"  -v|--verbose       print summary reports to stderr every sumInt (10) seconds.\n"
"                     Summaries are on by default for live capture (-i) and off\n"
"                     by default for pcap replay (-r); -v forces them on for -r.\n"
"\n"
"  -l|--showLocal     show RTTs through local host applications\n"
"\n"
"  --sumInt num       summary report print interval (default 10s)\n"
"\n"
"  --tsvalMaxAge num  max age of an unmatched tsval (default 10s)\n"
"\n"
"  --flowMaxIdle num  flows idle longer than <num> are deleted (default 300s)\n"
"\n"
"  --logfile path     reopen stdout to <path> at startup (append+create).\n"
"                     Send SIGHUP to reopen the same path again, which lets\n"
"                     external tools rotate the log atomically: mv old new;\n"
"                     kill -HUP <pid>; process new. Without this flag pping\n"
"                     writes to whichever stdout it inherits (terminal,\n"
"                     redirect, or systemd's StandardOutput=).\n"
"\n"
"  --flowMaxAge num   in -a mode, emit a row and reset the per-flow accumulator\n"
"                     after the flow has been alive for <num> seconds (default\n"
"                     1800). 0 disables — long flows then flush only on FIN,\n"
"                     RST, idle, or shutdown. Negative values rejected.\n"
"\n"
"  --mode {ts,seq,hybrid}\n"
"                     RTT measurement path. (default: hybrid)\n"
"                       ts      — TCP timestamp option only (legacy behavior;\n"
"                                 flows without TSopt are dropped as no_TS).\n"
"                       seq     — TCP SEQ/ACK only; works on every TCP flow.\n"
"                       hybrid  — TS path on TS-capable flows, SEQ path on\n"
"                                 the rest. Recommended; produces samples on\n"
"                                 mixed-OS workloads (Windows, stripped TS).\n"
"                     The no_TS counter only increments in --mode ts (where\n"
"                     non-TS packets are dropped); in seq/hybrid those packets\n"
"                     are handled by the SEQ path and not counted.\n"
"\n"
"  -e output adds a 12th field (t = TS path, s = SEQ path) per RTT line.\n"
"  Human-readable output adds a trailing [t] or [s] tag.\n"
"\n"
"  -h|--help          print help then exit\n"
;
}

int main(int argc, char* const* argv)
{
    bool liveInp = false;
    std::string fname;
    if (argc <= 1) {
        help(argv[0]);
        exit(1);
    }
    int longindex = -1;
    for (int c; (c = getopt_long(argc, argv, "i:r:f:c:s:hlmqvea",
                                 opts, &longindex)) != -1; ) {
        switch (c) {
        case 'i': liveInp = true; fname = optarg; break;
        case 'r': fname = optarg; break;
        case 'f': filter += " and (" + std::string(optarg) + ")"; break;
        case 'c': maxPackets = atof(optarg); break;
        case 's': time_to_run = atof(optarg); break;
        case 'q': sumInt = 0.; sumExplicit = true; break;
        case 'v': sumExplicit = true; break;
        case 'l': filtLocal = false; break;
        case 'm': machineReadable = true; break;
        case 'e': machineReadable = true; extendedMachineOutput = true; break;
        case 'a': aggregateOutput = true; break;
        case 'S': sumInt = atof(optarg); sumExplicit = true; break;
        case 'M': tsvalMaxAge = atof(optarg); break;
        case 'F': flowMaxIdle = atof(optarg); break;
        case 'h': help(argv[0]); exit(0);
        case 0: {
            // long-only options dispatched by name
            const char* name = opts[longindex].name;
            if (std::strcmp(name, "mode") == 0) {
                if      (std::strcmp(optarg, "ts")     == 0) mode = Mode::TS;
                else if (std::strcmp(optarg, "seq")    == 0) mode = Mode::SEQ;
                else if (std::strcmp(optarg, "hybrid") == 0) mode = Mode::HYBRID;
                else {
                    std::cerr << "unknown --mode value: " << optarg
                              << " (expected ts, seq, or hybrid)\n";
                    exit(EXIT_FAILURE);
                }
            } else if (std::strcmp(name, "flowMaxAge") == 0) {
                double v = atof(optarg);
                if (v < 0.) {
                    std::cerr << "fatal: --flowMaxAge=" << optarg
                              << " must be >= 0 (0=disabled, default=1800)\n";
                    exit(EXIT_FAILURE);
                }
                flowMaxAge = v;
            } else if (std::strcmp(name, "logfile") == 0) {
                logfilePath = optarg;
            }
            break;
        }
        }
    }
    if (aggregateOutput && (extendedMachineOutput || machineReadable)) {
        std::cerr << "fatal: -a/--aggregate is mutually exclusive with "
                     "-e/--extended and -m/--machine\n";
        exit(EXIT_FAILURE);
    }
    if (optind < argc || fname.empty()) {
        usage(argv[0]);
        exit(1);
    }
    // pcap mode: 10s of capture-time can fly by in milliseconds of wall time,
    // so the periodic summary spams the console. Default to silent unless the
    // user explicitly asked for summaries via -q/-v/--sumInt.
    if (!liveInp && !sumExplicit) {
        sumInt = 0.;
    }

    if (!logfilePath.empty()) {
        if (!reopenLogfile(logfilePath.c_str())) {
            std::cerr << "fatal: cannot open --logfile=" << logfilePath
                      << ": " << strerror(errno) << "\n";
            exit(EXIT_FAILURE);
        }
    }

    BaseSniffer* snif;
    {
        SnifferConfiguration config;
        config.set_filter(filter);
        config.set_promisc_mode(false);
        config.set_snap_len(SNAP_LEN);
        config.set_timeout(250);

        try {
            if (liveInp) {
                snif = new Sniffer(fname, config);
                if (filtLocal) {
                    localIP = localAddrOf(fname);
                    if (localIP.empty()) {
                        // couldn't get local ip addr
                        filtLocal = false;
                    } else {
                        // Pre-parse localIP into packed bytes so the per-packet
                        // filter compares 16 bytes instead of std::string.
                        // localAddrOf only returns IPv4 today (see its XXX note).
                        try {
                            uint32_t ip_n = IPv4Address(localIP);
                            std::memcpy(localIPBytes.data(), &ip_n, 4);
                            localIPaf = 4;
                        } catch (std::exception&) {
                            filtLocal = false;
                        }
                    }
                }
            } else {
                snif = new FileSniffer(fname, config);
                // pcap mode: no local-host concept, so disable the filter
                // explicitly. Otherwise filtLocal stays true and only the
                // localIPaf == 0 branch in process_packet keeps the filter
                // from misfiring — fragile if anyone touches that init.
                filtLocal = false;
            }
        } catch (std::exception& ex) {
            std::cerr << "Couldn't open " << fname << ": " << ex.what() << "\n";
            exit(EXIT_FAILURE);
        }
    }
    dropPrivileges("nobody");
    node = getFQDN();
    if (liveInp && machineReadable) {
        // output every 100ms when piping to analysis/display program
        flushInt /= 10;
    }
    nextFlush = clock_now() + flushInt;

    double nxtSum = 0., nxtClean = 0.;
    int64_t totalPkts = 0;
    struct timespec wallStart, wallEnd;
    clock_gettime(CLOCK_MONOTONIC, &wallStart);

    // Catch Ctrl+C and SIGTERM so the loop exits cleanly via the flag check
    // below. In file mode this lets the wall-clock summary still print after
    // an interrupted long replay. No SA_RESTART so libpcap returns from its
    // blocking read promptly on signal.
    struct sigaction sa{};
    sa.sa_handler = handleSignal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    // Only intercept SIGHUP when --logfile is in use; otherwise leave the
    // default (terminate) so pping behaves like a normal CLI tool.
    if (!logfilePath.empty()) {
        struct sigaction sahup{};
        sahup.sa_handler = handleSighup;
        sigemptyset(&sahup.sa_mask);
        sigaction(SIGHUP, &sahup, nullptr);
    }
    // Ignore SIGPIPE so a closed downstream pipe (e.g. `pping ... | head`)
    // doesn't kill us before the wall-clock summary prints. Writes to the
    // closed fd will return EPIPE, which iostream/printf swallow silently.
    signal(SIGPIPE, SIG_IGN);

    for (const auto& packet : *snif) {
        if (stopRequested) break;
        if (reopenRequested) {
            reopenRequested = 0;
            if (!logfilePath.empty() && !reopenLogfile(logfilePath.c_str())) {
                std::cerr << "pping: failed to reopen --logfile="
                          << logfilePath << ": " << strerror(errno)
                          << "; continuing with existing fd\n";
            }
        }
        process_packet(packet);
        ++totalPkts;

        if ((time_to_run > 0. && capTm - startm >= time_to_run) ||
            (maxPackets > 0 && pktCnt >= maxPackets)) {
            printSummary();
            std::cerr << "capture-time: " << (capTm - startm)
                      << "s, " << pktCnt << " packets\n";
            break;
        }
        if (capTm >= nxtSum && sumInt) {
            if (nxtSum > 0.) {
                printSummary();
                pktCnt = 0;
                no_TS = 0;
                uniDir = 0;
                not_tcp = 0;
                not_v4or6 = 0;
                tsDropped = 0;
                seqSamples = 0;
                seqKarnDrops = 0;
                seqStale = 0;
                aggregatedRows = 0;
                flowsDropped = 0;
            }
            nxtSum = capTm + sumInt;

        }
        if (capTm >= nxtClean) {
            cleanUp(capTm);  // get rid of stale entries
            nxtClean = capTm + tsvalMaxAge;
        }
    }

    // Aggregator shutdown flush: drain every live flow with samples to
    // guarantee no in-progress accumulator state is silently dropped on
    // graceful exit (signal, end of pcap, -c, -s, --seconds).
    if (aggregateOutput) {
        cleanUp(capTm, /*flush_all=*/true);
    }

    // File-mode only: wall-clock measures CPU-bound replay throughput, which
    // is the useful benchmark number. Live capture is bounded by what arrives
    // on the wire, not by pping, so the same number would just describe the
    // network's quietness.
    if (!liveInp) {
        clock_gettime(CLOCK_MONOTONIC, &wallEnd);
        double wallSec = (wallEnd.tv_sec - wallStart.tv_sec) +
                         (wallEnd.tv_nsec - wallStart.tv_nsec) * 1e-9;
        if (totalPkts > 0 && wallSec > 0) {
            fprintf(stderr,
                    "wall-clock: %.3fs, %" PRId64 " packets, %.1f ns/pkt, %.3f Mpps\n",
                    wallSec, totalPkts,
                    wallSec * 1e9 / totalPkts,
                    totalPkts / wallSec / 1e6);
        }
    }

    exit(0);
}

