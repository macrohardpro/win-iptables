// nat_table.cpp -- NatTable implementation

#include "winiptables/nat_table.hpp"

#include <algorithm>

namespace winiptables {

// -----------------------------------------------------------------------
// RecordDnat
// -----------------------------------------------------------------------

void NatTable::RecordDnat(uint32_t orig_src_ip, uint16_t orig_src_port,
                           uint32_t orig_dst_ip, uint16_t orig_dst_port,
                           uint8_t  protocol,
                           uint32_t new_dst_ip,  uint16_t new_dst_port) {
    NatKey fwd_key{orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, protocol};

    NatEntry entry{};
    entry.new_dst_ip_be  = new_dst_ip;
    entry.new_dst_port   = new_dst_port;
    entry.new_src_ip_be  = 0;
    entry.new_src_port   = 0;
    entry.is_dnat        = true;
    entry.last_seen      = std::chrono::steady_clock::now();

    // Reverse key: reply packet arrives src=new_dst, dst=orig_src
    NatKey rev_key{new_dst_ip, orig_src_ip, new_dst_port, orig_src_port, protocol};

    NatEntry rev_entry{};
    // On the reply we rewrite src back to orig_dst
    rev_entry.new_src_ip_be = orig_dst_ip;
    rev_entry.new_src_port  = orig_dst_port;
    rev_entry.new_dst_ip_be = 0;
    rev_entry.new_dst_port  = 0;
    rev_entry.is_dnat       = true;
    rev_entry.last_seen     = entry.last_seen;

    std::lock_guard<std::mutex> lock(mutex_);
    forward_[fwd_key] = entry;
    reverse_[rev_key] = rev_entry;
}

// -----------------------------------------------------------------------
// RecordSnat
// -----------------------------------------------------------------------

void NatTable::RecordSnat(uint32_t orig_src_ip, uint16_t orig_src_port,
                           uint32_t orig_dst_ip, uint16_t orig_dst_port,
                           uint8_t  protocol,
                           uint32_t new_src_ip,  uint16_t new_src_port) {
    NatKey fwd_key{orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, protocol};

    NatEntry entry{};
    entry.new_src_ip_be  = new_src_ip;
    entry.new_src_port   = new_src_port;
    entry.new_dst_ip_be  = 0;
    entry.new_dst_port   = 0;
    entry.is_dnat        = false;
    entry.last_seen      = std::chrono::steady_clock::now();

    // Reverse key: reply arrives src=orig_dst, dst=new_src
    uint16_t rev_src_port = orig_dst_port;
    uint16_t rev_dst_port = (new_src_port != 0) ? new_src_port : orig_src_port;
    NatKey rev_key{orig_dst_ip, new_src_ip, rev_src_port, rev_dst_port, protocol};

    NatEntry rev_entry{};
    // On the reply we rewrite dst back to orig_src
    rev_entry.new_dst_ip_be = orig_src_ip;
    rev_entry.new_dst_port  = orig_src_port;
    rev_entry.new_src_ip_be = 0;
    rev_entry.new_src_port  = 0;
    rev_entry.is_dnat       = false;
    rev_entry.last_seen     = entry.last_seen;

    std::lock_guard<std::mutex> lock(mutex_);
    forward_[fwd_key] = entry;
    reverse_[rev_key] = rev_entry;
}

// -----------------------------------------------------------------------
// LookupDnatReply
// -----------------------------------------------------------------------

bool NatTable::LookupDnatReply(uint32_t src_ip,  uint16_t src_port,
                                uint32_t dst_ip,  uint16_t dst_port,
                                uint8_t  protocol,
                                uint32_t& out_new_src_ip,
                                uint16_t& out_new_src_port) const {
    NatKey key{src_ip, dst_ip, src_port, dst_port, protocol};
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reverse_.find(key);
    if (it == reverse_.end() || !it->second.is_dnat) return false;
    out_new_src_ip   = it->second.new_src_ip_be;
    out_new_src_port = it->second.new_src_port;
    // Touch last_seen
    const_cast<NatEntry&>(it->second).last_seen = std::chrono::steady_clock::now();
    return true;
}

// -----------------------------------------------------------------------
// LookupSnatReply
// -----------------------------------------------------------------------

bool NatTable::LookupSnatReply(uint32_t src_ip,  uint16_t src_port,
                                uint32_t dst_ip,  uint16_t dst_port,
                                uint8_t  protocol,
                                uint32_t& out_new_dst_ip,
                                uint16_t& out_new_dst_port) const {
    NatKey key{src_ip, dst_ip, src_port, dst_port, protocol};
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reverse_.find(key);
    if (it == reverse_.end() || it->second.is_dnat) return false;
    out_new_dst_ip   = it->second.new_dst_ip_be;
    out_new_dst_port = it->second.new_dst_port;
    const_cast<NatEntry&>(it->second).last_seen = std::chrono::steady_clock::now();
    return true;
}

// -----------------------------------------------------------------------
// CleanupExpired
// -----------------------------------------------------------------------

void NatTable::CleanupExpired() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    auto cleanup = [&](auto& table) {
        for (auto it = table.begin(); it != table.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_seen).count();
            if (elapsed >= NatEntry::kTimeoutSec) {
                it = table.erase(it);
            } else {
                ++it;
            }
        }
    };
    cleanup(forward_);
    cleanup(reverse_);
}

// -----------------------------------------------------------------------
// Size
// -----------------------------------------------------------------------

std::size_t NatTable::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return forward_.size();
}

}  // namespace winiptables
