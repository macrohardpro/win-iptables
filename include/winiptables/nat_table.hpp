#pragma once
// nat_table.hpp -- NAT connection tracking table
// Records DNAT/SNAT mappings so return traffic can be reverse-translated.

#include "winiptables/packet.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace winiptables {

// Five-tuple key for a NAT session (always stored in the "original" direction).
struct NatKey {
    uint32_t src_ip_be;   // original source IP (network byte order)
    uint32_t dst_ip_be;   // original destination IP (network byte order)
    uint16_t src_port;    // original source port (host byte order)
    uint16_t dst_port;    // original destination port (host byte order)
    uint8_t  protocol;    // IPPROTO_TCP / IPPROTO_UDP

    bool operator==(const NatKey& o) const noexcept {
        return src_ip_be == o.src_ip_be && dst_ip_be == o.dst_ip_be &&
               src_port  == o.src_port  && dst_port  == o.dst_port  &&
               protocol  == o.protocol;
    }
};

struct NatKeyHash {
    std::size_t operator()(const NatKey& k) const noexcept {
        // FNV-1a over the 13 bytes of the key
        constexpr std::size_t kPrime  = 0x00000100000001B3ULL;
        constexpr std::size_t kOffset = 0xcbf29ce484222325ULL;
        std::size_t h = kOffset;
        auto mix = [&](const void* p, std::size_t n) {
            const auto* b = static_cast<const uint8_t*>(p);
            for (std::size_t i = 0; i < n; ++i) { h ^= b[i]; h *= kPrime; }
        };
        mix(&k.src_ip_be, 4);
        mix(&k.dst_ip_be, 4);
        mix(&k.src_port,  2);
        mix(&k.dst_port,  2);
        mix(&k.protocol,  1);
        return h;
    }
};

// What was rewritten and how to undo it on the return path.
struct NatEntry {
    // Rewritten values (what the packet was changed TO)
    uint32_t new_dst_ip_be;   // DNAT: new destination IP
    uint16_t new_dst_port;    // DNAT: new destination port (0 = not rewritten)
    uint32_t new_src_ip_be;   // SNAT/MASQUERADE: new source IP
    uint16_t new_src_port;    // SNAT: new source port (0 = not rewritten)

    bool is_dnat;             // true = DNAT entry, false = SNAT entry
    std::chrono::steady_clock::time_point last_seen;

    static constexpr int kTimeoutSec = 3600;  // 1 hour idle timeout
};

// -----------------------------------------------------------------------
// NatTable — thread-safe NAT session table
// -----------------------------------------------------------------------
class NatTable {
public:
    NatTable() = default;

    // Non-copyable
    NatTable(const NatTable&) = delete;
    NatTable& operator=(const NatTable&) = delete;

    // Record a DNAT translation.
    // orig_*: original packet fields; new_dst_*: what they were rewritten to.
    void RecordDnat(uint32_t orig_src_ip, uint16_t orig_src_port,
                    uint32_t orig_dst_ip, uint16_t orig_dst_port,
                    uint8_t  protocol,
                    uint32_t new_dst_ip, uint16_t new_dst_port);

    // Record a SNAT/MASQUERADE translation.
    void RecordSnat(uint32_t orig_src_ip, uint16_t orig_src_port,
                    uint32_t orig_dst_ip, uint16_t orig_dst_port,
                    uint8_t  protocol,
                    uint32_t new_src_ip, uint16_t new_src_port);

    // Look up a DNAT return packet (reply from the DNAT target back to the client).
    // Packet arrives as: src=new_dst, dst=orig_src → need to rewrite src back to orig_dst.
    // Returns true and fills out_* if a matching entry is found.
    bool LookupDnatReply(uint32_t src_ip,  uint16_t src_port,
                         uint32_t dst_ip,  uint16_t dst_port,
                         uint8_t  protocol,
                         uint32_t& out_new_src_ip, uint16_t& out_new_src_port) const;

    // Look up a SNAT return packet (reply from the destination back to the masqueraded host).
    bool LookupSnatReply(uint32_t src_ip,  uint16_t src_port,
                         uint32_t dst_ip,  uint16_t dst_port,
                         uint8_t  protocol,
                         uint32_t& out_new_dst_ip, uint16_t& out_new_dst_port) const;

    // Remove expired entries (call periodically).
    void CleanupExpired();

    std::size_t Size() const;

private:
    mutable std::mutex mutex_;

    // Forward table: original five-tuple → NatEntry
    std::unordered_map<NatKey, NatEntry, NatKeyHash> forward_;

    // Reverse index for DNAT: (new_dst_ip, new_dst_port, orig_src_ip, orig_src_port, proto)
    // → original (orig_dst_ip, orig_dst_port)
    // Key: src=new_dst, dst=orig_src (the reply packet's five-tuple)
    std::unordered_map<NatKey, NatEntry, NatKeyHash> reverse_;
};

}  // namespace winiptables
