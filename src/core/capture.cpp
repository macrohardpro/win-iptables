// Copyright (c) winiptables authors. All rights reserved.
// capture.cpp — PacketCapture implementation (Task 10.2 ~ 10.5)
//
// Task 10.2: WinDivertOpen + blocking recv()
// Task 10.3: inject()
// Task 10.4: error handling (driver missing / insufficient privileges)
// Task 10.5: multi-threaded processing loop (thread pool)

#include "winiptables/capture.hpp"
#include "winiptables/log.hpp"
#include "winiptables/nat_table.hpp"
#include "winiptables/packet.hpp"
#include "winiptables/table_pipeline.hpp"

#include <cstring>
#include <iostream>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

namespace winiptables {

// ── Ctor / dtor ─────────────────────────────────────────────────────────────

PacketCapture::PacketCapture(HANDLE windivert_handle)
    : handle_(windivert_handle) {}

PacketCapture::~PacketCapture() {
    Stop();
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
}

PacketCapture::PacketCapture(PacketCapture&& other) noexcept
    : handle_(other.handle_),
      stop_flag_(other.stop_flag_.load()),
      workers_(std::move(other.workers_)) {
    other.handle_ = INVALID_HANDLE_VALUE;
}

PacketCapture& PacketCapture::operator=(PacketCapture&& other) noexcept {
    if (this != &other) {
        Stop();
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
        }
        handle_    = other.handle_;
        stop_flag_.store(other.stop_flag_.load());
        workers_   = std::move(other.workers_);
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    return *this;
}

// ── Static factory (Task 10.4) ─────────────────────────────────────────────

std::optional<PacketCapture> PacketCapture::Open(
    const std::string& filter,
    WINDIVERT_LAYER    layer,
    INT16              priority)
{
    HANDLE h = WinDivertOpen(filter.c_str(), layer, priority, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        switch (err) {
            case ERROR_ACCESS_DENIED:
                std::cerr << "[winiptables] Error: access denied. Run as Administrator."
                          << " (WinDivertOpen returned ERROR_ACCESS_DENIED)\n";
                break;
            case ERROR_FILE_NOT_FOUND:
                std::cerr << "[winiptables] Error: WinDivert driver not installed. "
                          << "Place WinDivert64.sys and WinDivert.dll next to the executable and run as Administrator."
                          << " (WinDivertOpen returned ERROR_FILE_NOT_FOUND)\n";
                break;
            case ERROR_INVALID_PARAMETER:
                std::cerr << "[winiptables] Error: invalid filter syntax."
                          << " filter=\"" << filter << "\""
                          << " (WinDivertOpen returned ERROR_INVALID_PARAMETER)\n";
                break;
            default:
                std::cerr << "[winiptables] Error: WinDivertOpen failed, error code 0x"
                          << std::hex << err << std::dec << "\n";
                break;
        }
        return std::nullopt;
    }
    return PacketCapture(h);
}

// ── recv() (Task 10.2) ──────────────────────────────────────────────────────

std::optional<PacketCapture::CapturedPacket> PacketCapture::recv() {
    // WinDivert maximum MTU: 40 + 65535 bytes
    constexpr UINT kBufSize = 40 + 0xFFFF;
    std::vector<uint8_t> buf(kBufSize);

    UINT recv_len = 0;
    WINDIVERT_ADDRESS addr{};

    BOOL ok = WinDivertRecv(
        handle_,
        buf.data(),
        kBufSize,
        &recv_len,
        &addr);

    if (!ok) {
        // Handle was closed (via Stop()) or another error occurred
        return std::nullopt;
    }

    if (recv_len == 0) {
        return std::nullopt;
    }

    buf.resize(recv_len);

    // Choose parser based on WinDivert address IPv6 flag
    std::optional<Packet> pkt;
    if (addr.IPv6) {
        pkt = ParseIPv6(buf.data(), buf.size());
    } else {
        pkt = ParseIPv4(buf.data(), buf.size());
    }

    if (!pkt.has_value()) {
        // Parse failed (malformed packet), skip
        return std::nullopt;
    }

    // Fill interface index and direction
    pkt->iface_index = addr.Network.IfIdx;
    pkt->direction   = DirectionFromAddr(addr);

    CapturedPacket cp;
    cp.packet = std::move(*pkt);
    cp.addr   = addr;
    return cp;
}

// ── inject() (Task 10.3) ────────────────────────────────────────────────────

bool PacketCapture::inject(const Packet& packet, const WINDIVERT_ADDRESS& addr) {
    const std::vector<uint8_t>& bytes = packet.ToBytes();
    if (bytes.empty()) {
        return false;
    }

    UINT send_len = 0;
    BOOL ok = WinDivertSend(
        handle_,
        bytes.data(),
        static_cast<UINT>(bytes.size()),
        &send_len,
        &addr);

    return ok == TRUE;
}

// ── Multi-threaded processing loop (Task 10.5) ─────────────────────────────

void PacketCapture::Start(std::size_t thread_count,
                          TablePipeline* pipeline,
                          const RuleStore* /*store*/)
{
    stop_flag_.store(false, std::memory_order_relaxed);
    workers_.reserve(thread_count);
    for (std::size_t i = 0; i < thread_count; ++i) {
        workers_.emplace_back([this, pipeline]() {
            WorkerLoop(pipeline);
        });
    }
}

void PacketCapture::Stop() {
    // Set stop flag
    stop_flag_.store(true, std::memory_order_relaxed);

    // Wake threads blocked in WinDivertRecv by shutting down the handle
    if (handle_ != INVALID_HANDLE_VALUE) {
        // WinDivertShutdown tells the driver to stop receiving so Recv returns immediately
        WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_BOTH);
    }

    // Wait for workers to exit
    for (auto& t : workers_) {
        if (t.joinable()) {
            t.join();
        }
    }
    workers_.clear();
}

// ── NAT helpers ─────────────────────────────────────────────────────────────

// Parse "ip:port" or "ip" into (ip_be, port). Returns false on failure.
static bool ParseNatAddr(const std::string& addr_str,
                          uint32_t& out_ip_be,
                          uint16_t& out_port,
                          bool&     out_has_port) {
    auto colon = addr_str.rfind(':');
    std::string ip_str;
    out_has_port = false;
    out_port     = 0;

    if (colon != std::string::npos) {
        ip_str = addr_str.substr(0, colon);
        try {
            int p = std::stoi(addr_str.substr(colon + 1));
            if (p > 0 && p <= 65535) {
                out_port     = static_cast<uint16_t>(p);
                out_has_port = true;
            }
        } catch (...) {}
    } else {
        ip_str = addr_str;
    }

    struct in_addr ia{};
    if (InetPtonA(AF_INET, ip_str.c_str(), &ia) != 1) return false;
    out_ip_be = ia.s_addr;  // already network byte order
    return true;
}

// Apply DNAT: rewrite dst IP (and optionally dst port) in raw_data in-place.
// raw_data must be a valid IPv4 packet.
static void ApplyDnat(std::vector<uint8_t>& raw_data,
                       uint32_t new_dst_ip_be,
                       uint16_t new_dst_port,
                       bool     has_port) {
    if (raw_data.size() < 20) return;  // too short for IPv4 header

    const uint8_t ihl = (raw_data[0] & 0x0F) * 4;
    if (raw_data.size() < ihl) return;

    // Rewrite destination IP (bytes 16-19)
    std::memcpy(raw_data.data() + 16, &new_dst_ip_be, 4);

    // Rewrite destination port in TCP/UDP header
    if (has_port && raw_data.size() >= static_cast<size_t>(ihl) + 4) {
        uint8_t proto = raw_data[9];
        if (proto == 6 || proto == 17) {  // TCP or UDP
            uint16_t port_be = htons(new_dst_port);
            std::memcpy(raw_data.data() + ihl + 2, &port_be, 2);  // dst port offset = 2
        }
    }
}

// Apply SNAT: rewrite src IP (and optionally src port) in raw_data in-place.
static void ApplySnat(std::vector<uint8_t>& raw_data,
                       uint32_t new_src_ip_be,
                       uint16_t new_src_port,
                       bool     has_port) {
    if (raw_data.size() < 20) return;

    const uint8_t ihl = (raw_data[0] & 0x0F) * 4;
    if (raw_data.size() < ihl) return;

    // Rewrite source IP (bytes 12-15)
    std::memcpy(raw_data.data() + 12, &new_src_ip_be, 4);

    if (has_port && raw_data.size() >= static_cast<size_t>(ihl) + 2) {
        uint8_t proto = raw_data[9];
        if (proto == 6 || proto == 17) {
            uint16_t port_be = htons(new_src_port);
            std::memcpy(raw_data.data() + ihl, &port_be, 2);  // src port offset = 0
        }
    }
}


// Lookup the primary IPv4 address of the outbound interface identified by IfIdx.
// Returns 0 on failure.
static uint32_t GetIfaceIpv4(DWORD if_idx) {
    ULONG buf_size = 15 * 1024;
    std::vector<uint8_t> buf(buf_size);
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                              nullptr,
                              reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
                              &buf_size) != ERROR_SUCCESS) {
        return 0;
    }
    auto* aa = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    for (; aa; aa = aa->Next) {
        if (aa->IfIndex != if_idx) continue;
        for (auto* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                return reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr)->sin_addr.s_addr;
            }
        }
    }
    return 0;
}

// Build and inject an ICMP Port Unreachable response for a rejected TCP/UDP packet.
static void SendIcmpUnreachable(HANDLE handle,
                                 const std::vector<uint8_t>& orig_raw,
                                 const WINDIVERT_ADDRESS& orig_addr) {
    if (orig_raw.size() < 20) return;
    const uint8_t ihl = (orig_raw[0] & 0x0F) * 4;
    if (orig_raw.size() < ihl) return;

    // ICMP unreachable: IP header (20) + ICMP header (8) + original IP header + 8 bytes of original payload
    const size_t orig_payload_copy = std::min(orig_raw.size() - ihl, static_cast<size_t>(8));
    const size_t icmp_data_len     = ihl + orig_payload_copy;
    const size_t total_len         = 20 + 8 + icmp_data_len;

    std::vector<uint8_t> pkt(total_len, 0);

    // IP header
    pkt[0]  = 0x45;                                          // version=4, IHL=5
    pkt[8]  = 64;                                            // TTL
    pkt[9]  = 1;                                             // protocol ICMP
    // src = original dst, dst = original src
    std::memcpy(pkt.data() + 12, orig_raw.data() + 16, 4);  // src IP
    std::memcpy(pkt.data() + 16, orig_raw.data() + 12, 4);  // dst IP
    uint16_t ip_total = htons(static_cast<uint16_t>(total_len));
    std::memcpy(pkt.data() + 2, &ip_total, 2);

    // ICMP header: type=3 (Destination Unreachable), code=3 (Port Unreachable)
    pkt[20] = 3;  // type
    pkt[21] = 3;  // code
    // Copy original IP header + 8 bytes
    std::memcpy(pkt.data() + 28, orig_raw.data(), icmp_data_len);

    // Recalculate checksums and send in opposite direction
    WINDIVERT_ADDRESS send_addr = orig_addr;
    send_addr.Outbound = !orig_addr.Outbound;
    send_addr.Impostor = 1;  // do not re-capture
    WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(pkt.size()), &send_addr, 0);

    UINT sent = 0;
    WinDivertSend(handle, pkt.data(), static_cast<UINT>(pkt.size()), &sent, &send_addr);
}


// Helper: extract IPv4 src/dst as uint32_t (network byte order) from raw packet
static uint32_t RawSrcIp(const std::vector<uint8_t>& raw) {
    if (raw.size() < 20) return 0;
    uint32_t v; std::memcpy(&v, raw.data() + 12, 4); return v;
}
static uint32_t RawDstIp(const std::vector<uint8_t>& raw) {
    if (raw.size() < 20) return 0;
    uint32_t v; std::memcpy(&v, raw.data() + 16, 4); return v;
}

void PacketCapture::WorkerLoop(TablePipeline* pipeline) {
    // Cleanup NAT table every ~60 seconds
    int cleanup_counter = 0;

    while (!stop_flag_.load(std::memory_order_relaxed)) {
        auto captured = recv();
        if (!captured.has_value()) {
            if (stop_flag_.load(std::memory_order_relaxed)) break;
            continue;
        }

        Packet& pkt = captured->packet;
        const WINDIVERT_ADDRESS& addr = captured->addr;

        // ── Step 1: Check NAT connection tracking for return traffic ─────────
        // Before running the pipeline, check if this packet is a reply to a
        // previously NATed connection and needs reverse translation.
        bool reverse_translated = false;
        if (pkt.af == AddressFamily::kIPv4) {
            uint32_t src_ip_be = RawSrcIp(pkt.raw_data);
            uint32_t dst_ip_be = RawDstIp(pkt.raw_data);

            // Check DNAT reply: packet from the DNAT target back to the original client.
            // The reply src port matches new_dst_port, dst matches orig_src.
            uint32_t rev_src_ip = 0; uint16_t rev_src_port = 0;
            if (nat_table_.LookupDnatReply(src_ip_be, pkt.src_port,
                                            dst_ip_be, pkt.dst_port,
                                            pkt.protocol,
                                            rev_src_ip, rev_src_port)) {
                // Rewrite src IP:port back to the original destination
                ApplySnat(pkt.raw_data, rev_src_ip, rev_src_port, rev_src_port != 0);
                LOG_DEBUG("NAT-reply DNAT: {}:{} -> {}:{} rewrite src to {}:{}",
                          pkt.SrcIpStr(), pkt.src_port,
                          pkt.DstIpStr(), pkt.dst_port,
                          rev_src_ip, rev_src_port);
                reverse_translated = true;
            }

            // Check SNAT reply: packet from the destination back to the masqueraded host.
            uint32_t rev_dst_ip = 0; uint16_t rev_dst_port = 0;
            if (!reverse_translated &&
                nat_table_.LookupSnatReply(src_ip_be, pkt.src_port,
                                            dst_ip_be, pkt.dst_port,
                                            pkt.protocol,
                                            rev_dst_ip, rev_dst_port)) {
                ApplyDnat(pkt.raw_data, rev_dst_ip, rev_dst_port, rev_dst_port != 0);
                LOG_DEBUG("NAT-reply SNAT: {}:{} -> {}:{} rewrite dst to {}:{}",
                          pkt.SrcIpStr(), pkt.src_port,
                          pkt.DstIpStr(), pkt.dst_port,
                          rev_dst_ip, rev_dst_port);
                reverse_translated = true;
            }

            if (reverse_translated) {
                // Recalculate checksums after rewrite, then inject directly — skip pipeline
                WinDivertHelperCalcChecksums(
                    pkt.raw_data.data(),
                    static_cast<UINT>(pkt.raw_data.size()),
                    const_cast<WINDIVERT_ADDRESS*>(&addr), 0);
                WINDIVERT_ADDRESS send_addr = addr;
                send_addr.Impostor = 1;
                UINT send_len = 0;
                WinDivertSend(handle_, pkt.raw_data.data(),
                              static_cast<UINT>(pkt.raw_data.size()),
                              &send_len, &send_addr);
                continue;
            }
        }

        // ── Step 2: Run the normal pipeline ──────────────────────────────────
        PipelineContext ctx{};
        ctx.direction = pkt.direction;
        Verdict verdict = pipeline->process(pkt, ctx);

        // ── Step 3: Apply NAT rewrites and record in connection table ─────────
        if (pkt.af == AddressFamily::kIPv4) {
            uint32_t orig_src_be = RawSrcIp(pkt.raw_data);
            uint32_t orig_dst_be = RawDstIp(pkt.raw_data);

            // DNAT
            if (!ctx.eval_ctx.nat_dst_addr.empty()) {
                uint32_t new_ip = 0; uint16_t new_port = 0; bool has_port = false;
                if (ParseNatAddr(ctx.eval_ctx.nat_dst_addr, new_ip, new_port, has_port)) {
                    // Record before rewriting so we have the original values
                    nat_table_.RecordDnat(orig_src_be, pkt.src_port,
                                          orig_dst_be, pkt.dst_port,
                                          pkt.protocol,
                                          new_ip, has_port ? new_port : pkt.dst_port);
                    ApplyDnat(pkt.raw_data, new_ip, new_port, has_port);
                    LOG_INFO("DNAT applied: {}:{} -> {}:{} ({})",
                             pkt.SrcIpStr(), pkt.src_port,
                             pkt.DstIpStr(), pkt.dst_port,
                             ctx.eval_ctx.nat_dst_addr);
                }
            }

            // SNAT / MASQUERADE
            if (!ctx.eval_ctx.nat_src_addr.empty()) {
                uint32_t new_ip = 0; uint16_t new_port = 0; bool has_port = false;
                if (ctx.eval_ctx.nat_src_addr == "MASQUERADE") {
                    new_ip = GetIfaceIpv4(addr.Network.IfIdx);
                    has_port = false;
                } else {
                    ParseNatAddr(ctx.eval_ctx.nat_src_addr, new_ip, new_port, has_port);
                }
                if (new_ip != 0) {
                    nat_table_.RecordSnat(orig_src_be, pkt.src_port,
                                          orig_dst_be, pkt.dst_port,
                                          pkt.protocol,
                                          new_ip, has_port ? new_port : 0);
                    ApplySnat(pkt.raw_data, new_ip, new_port, has_port);
                    LOG_INFO("SNAT applied: {}:{} -> {}:{} new_src={}:{}",
                             pkt.SrcIpStr(), pkt.src_port,
                             pkt.DstIpStr(), pkt.dst_port,
                             new_ip, new_port);
                }
            }
        }

        // ── Step 4: Inject or drop ────────────────────────────────────────────
        if (verdict == Verdict::Accept) {
            std::vector<uint8_t> mutable_bytes = pkt.ToBytes();
            if (!mutable_bytes.empty()) {
                WINDIVERT_ADDRESS send_addr = addr;
                send_addr.Impostor = 1;
                WinDivertHelperCalcChecksums(
                    mutable_bytes.data(),
                    static_cast<UINT>(mutable_bytes.size()),
                    &send_addr, 0);
                UINT send_len = 0;
                WinDivertSend(handle_, mutable_bytes.data(),
                              static_cast<UINT>(mutable_bytes.size()),
                              &send_len, &send_addr);
            }
        } else {
            LOG_INFO("DROP {}:{} -> {}:{} proto={}",
                     pkt.SrcIpStr(), pkt.src_port,
                     pkt.DstIpStr(), pkt.dst_port,
                     pkt.protocol);
        }

        // REJECT: send ICMP Port Unreachable
        if (verdict == Verdict::Drop && ctx.eval_ctx.rejected &&
            pkt.af == AddressFamily::kIPv4) {
            LOG_INFO("REJECT (ICMP unreachable) {}:{} -> {}:{}",
                     pkt.SrcIpStr(), pkt.src_port,
                     pkt.DstIpStr(), pkt.dst_port);
            SendIcmpUnreachable(handle_, pkt.raw_data, addr);
        }

        // Periodic NAT table cleanup
        if (++cleanup_counter >= 10000) {
            cleanup_counter = 0;
            nat_table_.CleanupExpired();
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

Direction PacketCapture::DirectionFromAddr(const WINDIVERT_ADDRESS& addr) noexcept {
    // FORWARD layer: packet is being forwarded
    if (addr.Layer == WINDIVERT_LAYER_NETWORK_FORWARD) {
        return Direction::kForward;
    }
    // NETWORK layer: decide direction based on Outbound flag
    return addr.Outbound ? Direction::kOutbound : Direction::kInbound;
}

}  // namespace winiptables
