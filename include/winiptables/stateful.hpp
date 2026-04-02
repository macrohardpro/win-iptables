// Copyright (c) winiptables authors. All rights reserved.
// stateful.hpp -- StatefulTracker: Connection state tracking (conntrack)
//
// Implements TCP state machine (SYN->ESTABLISHED->FIN->CLOSED) and UDP session tracking,
// uses LRU policy to manage connection table (max 65536 entries), supports timeout cleanup.

#ifndef WINIPTABLES_STATEFUL_HPP_
#define WINIPTABLES_STATEFUL_HPP_

#include "winiptables/packet.hpp"

#include <chrono>
#include <cstdint>
#include <list>
#include <mutex>
#include <unordered_map>

namespace winiptables {

// -- Connection States -----------------------------------------------------------------

enum class ConnState : uint8_t {
    kNew         = 0x01,  // New connection (first packet, not yet established)
    kEstablished = 0x02,  // Established connection (bidirectional traffic confirmed)
    kRelated     = 0x04,  // Related connection (e.g., FTP data channel)
    kInvalid     = 0x08,  // Invalid packet (does not belong to any known connection)
};

// -- TCP Internal State Machine -------------------------------------------------------

enum class TcpConnState : uint8_t {
    kSynSent,       // SYN sent, waiting for SYN-ACK
    kSynReceived,   // SYN-ACK received, waiting for ACK
    kEstablished,   // Connection established
    kFinWait,       // FIN sent, waiting for peer's FIN
    kCloseWait,     // Received peer's FIN, waiting for local FIN
    kTimeWait,      // TIME_WAIT state, waiting 120 seconds before closing
    kClosed,        // Connection closed (four-way handshake completed or RST)
};

// -- Connection Five-Tuple Key (supports bidirectional matching) ---------------------

struct ConnKey {
    IpAddress src_ip;
    IpAddress dst_ip;
    uint16_t  src_port;
    uint16_t  dst_port;
    uint8_t   protocol;  // IPPROTO_TCP / IPPROTO_UDP

    // Canonicalize: ensure src < dst, so A->B and B->A map to the same key
    ConnKey Canonical() const noexcept;

    bool operator==(const ConnKey& other) const noexcept;
};

// ConnKey hash (for unordered_map)
struct ConnKeyHash {
    std::size_t operator()(const ConnKey& k) const noexcept;
};

// -- Connection Table Entry ------------------------------------------------------------

struct ConnEntry {
    ConnState    state;
    TcpConnState tcp_state;  // Only valid for TCP
    std::chrono::steady_clock::time_point last_seen;

    // Record "forward" direction (first packet's src->dst), used to distinguish bidirectional TCP states
    IpAddress    orig_src_ip;
    uint16_t     orig_src_port;
};

// -- StatefulTracker -------------------------------------------------------------------

class StatefulTracker {
public:
    // Maximum number of entries in connection table
    static constexpr std::size_t kMaxConnections = 65536;

    // Timeout configuration (seconds)
    static constexpr int kTcpEstablishedTimeoutSec = 3600;  // ESTABLISHED idle timeout
    static constexpr int kTcpTimeWaitTimeoutSec    = 120;   // TIME_WAIT timeout
    static constexpr int kTcpNewTimeoutSec         = 30;    // SYN handshake timeout
    static constexpr int kUdpEstablishedTimeoutSec = 30;    // UDP session timeout
    static constexpr int kUdpNewTimeoutSec         = 30;    // UDP first packet timeout

    StatefulTracker() = default;

    // Non-copyable
    StatefulTracker(const StatefulTracker&) = delete;
    StatefulTracker& operator=(const StatefulTracker&) = delete;

    /// Query connection state of a packet, update internal state machine.
    /// Thread-safe (holds mutex internally).
    ConnState GetState(const Packet& packet);

    /// Clean up expired connection entries.
    /// Recommended to call periodically (e.g., every 30 seconds).
    void CleanupExpired();

    /// Returns current number of entries in connection table (for testing/monitoring).
    std::size_t Size() const;

private:
    // LRU list: front = most recently used, back = least recently used
    using LruList = std::list<ConnKey>;
    using LruIter = LruList::iterator;

    struct LruEntry {
        ConnEntry entry;
        LruIter   lru_pos;  // Position in lru_list_
    };

    mutable std::mutex mutex_;
    LruList lru_list_;
    std::unordered_map<ConnKey, LruEntry, ConnKeyHash> conn_table_;

    // -- Internal helpers (caller must hold mutex_) -----------------------------------

    /// Move key to head of LRU list (mark as most recently used)
    void TouchLru(const ConnKey& key, LruIter it);

    /// Insert new connection entry, evict least recently used entry if necessary
    void InsertEntry(const ConnKey& canonical_key, ConnEntry entry);

    /// Handle TCP packet, return ConnState
    ConnState HandleTcp(const Packet& packet, const ConnKey& canonical_key);

    /// Handle UDP packet, return ConnState
    ConnState HandleUdp(const Packet& packet, const ConnKey& canonical_key);

    /// Check if entry has expired
    static bool IsExpired(const ConnEntry& entry) noexcept;
};

}  // namespace winiptables

#endif  // WINIPTABLES_STATEFUL_HPP_