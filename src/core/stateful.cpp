// Copyright (c) winiptables authors. All rights reserved.
// stateful.cpp -- StatefulTracker implementation
//
// Task 9.2: TCP state machine (SYN->ESTABLISHED->FIN->CLOSED)
// Task 9.3: UDP session state tracking (based on 5-tuple bidirectional traffic)
// Task 9.4: LRU eviction policy (connection table max 65536 entries)
// Task 9.5: TCP/UDP connection timeout cleanup

#include "winiptables/stateful.hpp"

#include <algorithm>
#include <cstring>
#include <functional>

// IPPROTO constants (avoid dependency on winsock2.h)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// TCP flag bits
namespace tcp_flags {
constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kAck = 0x10;
}  // namespace tcp_flags

namespace winiptables {

// -- ConnKey ---------------------------------------------------------------------

// Compare two IpAddress values (for canonical ordering)
static int CompareIp(const IpAddress& a, const IpAddress& b) noexcept {
    if (a.af != b.af) return static_cast<int>(a.af) - static_cast<int>(b.af);
    if (a.af == AddressFamily::kIPv4) {
        return std::memcmp(a.v4, b.v4, 4);
    }
    return std::memcmp(a.v6, b.v6, 16);
}

ConnKey ConnKey::Canonical() const noexcept {
    // Canonicalize: ensure (src, src_port) <= (dst, dst_port), guaranteeing bidirectional mapping to same key
    int cmp = CompareIp(src_ip, dst_ip);
    if (cmp < 0 || (cmp == 0 && src_port <= dst_port)) {
        return *this;
    }
    ConnKey flipped;
    flipped.src_ip   = dst_ip;
    flipped.dst_ip   = src_ip;
    flipped.src_port = dst_port;
    flipped.dst_port = src_port;
    flipped.protocol = protocol;
    return flipped;
}

bool ConnKey::operator==(const ConnKey& other) const noexcept {
    return src_port == other.src_port &&
           dst_port == other.dst_port &&
           protocol == other.protocol &&
           src_ip   == other.src_ip   &&
           dst_ip   == other.dst_ip;
}

// -- ConnKeyHash -----------------------------------------------------------------

static std::size_t HashBytes(const void* data, std::size_t len,
                              std::size_t seed = 0) noexcept {
    // FNV-1a hash
    constexpr std::size_t kFnvPrime  = 0x00000100000001B3ULL;
    constexpr std::size_t kFnvOffset = 0xcbf29ce484222325ULL;
    std::size_t h = kFnvOffset ^ seed;
    const auto* p = static_cast<const uint8_t*>(data);
    for (std::size_t i = 0; i < len; ++i) {
        h ^= static_cast<std::size_t>(p[i]);
        h *= kFnvPrime;
    }
    return h;
}

std::size_t ConnKeyHash::operator()(const ConnKey& k) const noexcept {
    std::size_t h = 0;
    if (k.src_ip.af == AddressFamily::kIPv4) {
        h = HashBytes(k.src_ip.v4, 4, h);
        h = HashBytes(k.dst_ip.v4, 4, h);
    } else {
        h = HashBytes(k.src_ip.v6, 16, h);
        h = HashBytes(k.dst_ip.v6, 16, h);
    }
    h = HashBytes(&k.src_port, sizeof(k.src_port), h);
    h = HashBytes(&k.dst_port, sizeof(k.dst_port), h);
    h = HashBytes(&k.protocol, sizeof(k.protocol), h);
    return h;
}

// -- StatefulTracker::IsExpired --------------------------------------------------

// static
bool StatefulTracker::IsExpired(const ConnEntry& entry) noexcept {
    using namespace std::chrono;
    auto now     = steady_clock::now();
    auto elapsed = duration_cast<seconds>(now - entry.last_seen).count();

    // Closed TCP connections are evicted immediately
    if (entry.tcp_state == TcpConnState::kClosed) {
        return true;
    }

    // TIME_WAIT: evicted after 120 seconds
    if (entry.tcp_state == TcpConnState::kTimeWait) {
        return elapsed >= kTcpTimeWaitTimeoutSec;
    }

    switch (entry.state) {
        case ConnState::kEstablished:
            // TCP ESTABLISHED idle timeout 3600s, UDP session timeout 30s
            if (entry.tcp_state == TcpConnState::kEstablished) {
                return elapsed >= kTcpEstablishedTimeoutSec;
            }
            // UDP (tcp_state reused as kEstablished)
            return elapsed >= kUdpEstablishedTimeoutSec;

        case ConnState::kNew:
        default:
            // NEW state (TCP SYN handshake incomplete, or UDP unidirectional first packet) timeout 30s
            return elapsed >= kTcpNewTimeoutSec;
    }
}

// -- StatefulTracker::TouchLru ---------------------------------------------------

void StatefulTracker::TouchLru(const ConnKey& key, LruIter it) {
    // Move node to head of linked list (most recently used)
    lru_list_.splice(lru_list_.begin(), lru_list_, it);
    (void)key;
}

// -- StatefulTracker::InsertEntry ------------------------------------------------

void StatefulTracker::InsertEntry(const ConnKey& canonical_key,
                                   ConnEntry entry) {
    // If connection table is full, evict LRU tail entry
    while (conn_table_.size() >= kMaxConnections && !lru_list_.empty()) {
        const ConnKey& evict_key = lru_list_.back();
        conn_table_.erase(evict_key);
        lru_list_.pop_back();
    }

    // Insert new entry at head of linked list
    lru_list_.push_front(canonical_key);
    LruEntry lru_entry{std::move(entry), lru_list_.begin()};
    conn_table_.emplace(canonical_key, std::move(lru_entry));
}

// -- StatefulTracker::HandleTcp --------------------------------------------------

ConnState StatefulTracker::HandleTcp(const Packet& packet,
                                      const ConnKey& canonical_key) {
    const uint8_t flags = packet.tcp_flags;
    const bool is_syn   = (flags & tcp_flags::kSyn) && !(flags & tcp_flags::kAck);
    const bool is_synack = (flags & tcp_flags::kSyn) && (flags & tcp_flags::kAck);
    const bool is_ack   = (flags & tcp_flags::kAck) && !(flags & tcp_flags::kSyn);
    const bool is_fin   = (flags & tcp_flags::kFin) != 0;
    const bool is_rst   = (flags & tcp_flags::kRst) != 0;

    auto it = conn_table_.find(canonical_key);

    // RST: close connection immediately
    if (is_rst && it != conn_table_.end()) {
        it->second.entry.tcp_state  = TcpConnState::kClosed;
        it->second.entry.state      = ConnState::kInvalid;
        it->second.entry.last_seen  = std::chrono::steady_clock::now();
        TouchLru(canonical_key, it->second.lru_pos);
        return ConnState::kInvalid;
    }

    // New SYN: create new connection
    if (is_syn && it == conn_table_.end()) {
        ConnEntry entry{};
        entry.state        = ConnState::kNew;
        entry.tcp_state    = TcpConnState::kSynSent;
        entry.last_seen    = std::chrono::steady_clock::now();
        entry.orig_src_ip  = packet.src_ip;
        entry.orig_src_port = packet.src_port;
        InsertEntry(canonical_key, std::move(entry));
        return ConnState::kNew;
    }

    // Non-SYN packet without corresponding connection -> INVALID
    if (it == conn_table_.end()) {
        return ConnState::kInvalid;
    }

    ConnEntry& entry = it->second.entry;
    entry.last_seen  = std::chrono::steady_clock::now();
    TouchLru(canonical_key, it->second.lru_pos);

    // Closed connection -> INVALID
    if (entry.tcp_state == TcpConnState::kClosed) {
        return ConnState::kInvalid;
    }

    // State machine transition
    switch (entry.tcp_state) {
        case TcpConnState::kSynSent:
            if (is_synack) {
                // Received SYN-ACK, waiting for final ACK
                entry.tcp_state = TcpConnState::kSynReceived;
                entry.state     = ConnState::kNew;
            }
            break;

        case TcpConnState::kSynReceived:
            if (is_ack) {
                // Three-way handshake complete, connection established
                entry.tcp_state = TcpConnState::kEstablished;
                entry.state     = ConnState::kEstablished;
            }
            break;

        case TcpConnState::kEstablished:
            if (is_fin) {
                entry.tcp_state = TcpConnState::kFinWait;
                // State remains ESTABLISHED until four-way handshake completes
            }
            break;

        case TcpConnState::kFinWait:
            if (is_fin || (is_ack && is_fin)) {
                // Received peer's FIN, enter CLOSE_WAIT
                entry.tcp_state = TcpConnState::kCloseWait;
            }
            break;

        case TcpConnState::kCloseWait:
            if (is_ack) {
                // Four-way handshake complete, enter TIME_WAIT (wait 120 seconds before closing)
                entry.tcp_state = TcpConnState::kTimeWait;
                entry.state     = ConnState::kEstablished;  // Still considered valid during TIME_WAIT
                entry.last_seen = std::chrono::steady_clock::now();  // Reset timer
            }
            break;

        case TcpConnState::kTimeWait:
            // TIME_WAIT state does not accept new state transitions, wait for timeout cleanup
            break;

        default:
            break;
    }

    return entry.state;
}

// -- StatefulTracker::HandleUdp --------------------------------------------------

ConnState StatefulTracker::HandleUdp(const Packet& packet,
                                      const ConnKey& canonical_key) {
    auto it = conn_table_.find(canonical_key);

    if (it == conn_table_.end()) {
        // First packet: create NEW state UDP session
        ConnEntry entry{};
        entry.state         = ConnState::kNew;
        entry.tcp_state     = TcpConnState::kEstablished;  // UDP has no state machine, reuse field
        entry.last_seen     = std::chrono::steady_clock::now();
        entry.orig_src_ip   = packet.src_ip;
        entry.orig_src_port = packet.src_port;
        InsertEntry(canonical_key, std::move(entry));
        return ConnState::kNew;
    }

    ConnEntry& entry = it->second.entry;
    entry.last_seen  = std::chrono::steady_clock::now();
    TouchLru(canonical_key, it->second.lru_pos);

    // Check if this is reverse traffic (i.e., peer's response)
    bool is_reply = !(packet.src_ip  == entry.orig_src_ip &&
                      packet.src_port == entry.orig_src_port);

    if (is_reply && entry.state == ConnState::kNew) {
        // Received response, upgrade to ESTABLISHED
        entry.state = ConnState::kEstablished;
    }

    return entry.state;
}

// -- StatefulTracker::GetState ----------------------------------------------------

ConnState StatefulTracker::GetState(const Packet& packet) {
    // Only handle TCP and UDP
    if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP) {
        return ConnState::kInvalid;
    }

    ConnKey key{};
    key.src_ip   = packet.src_ip;
    key.dst_ip   = packet.dst_ip;
    key.src_port = packet.src_port;
    key.dst_port = packet.dst_port;
    key.protocol = packet.protocol;

    const ConnKey canonical = key.Canonical();

    std::lock_guard<std::mutex> lock(mutex_);

    if (packet.protocol == IPPROTO_TCP) {
        return HandleTcp(packet, canonical);
    } else {
        return HandleUdp(packet, canonical);
    }
}

// -- StatefulTracker::CleanupExpired --------------------------------------------

void StatefulTracker::CleanupExpired() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Scan from LRU tail forward, remove expired entries
    // Note: expired entries are not necessarily at tail (different timeout durations), need full table scan
    auto it = conn_table_.begin();
    while (it != conn_table_.end()) {
        if (IsExpired(it->second.entry)) {
            lru_list_.erase(it->second.lru_pos);
            it = conn_table_.erase(it);
        } else {
            ++it;
        }
    }
}

// -- StatefulTracker::Size --------------------------------------------------------

std::size_t StatefulTracker::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return conn_table_.size();
}

}  // namespace winiptables