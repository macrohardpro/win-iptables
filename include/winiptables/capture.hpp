// Copyright (c) winiptables authors. All rights reserved.
// capture.hpp — PacketCapture declaration (Task 10.1)
//
// Wraps WinDivert packet capture/injection and provides a multi-threaded processing loop.

#pragma once

#ifndef WINIPTABLES_CAPTURE_HPP_
#define WINIPTABLES_CAPTURE_HPP_

#include "winiptables/packet.hpp"
#include "winiptables/nat_table.hpp"
#include "winiptables/rule_store.hpp"
#include "winiptables/table_pipeline.hpp"

#include <windows.h>
#include <windivert.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace winiptables {

// PacketCapture: wraps a WinDivert handle and provides capture/inject and a multi-threaded loop.
class PacketCapture {
public:
    // No default constructor
    PacketCapture() = delete;

    // Construct from an already-open WinDivert handle (takes ownership)
    explicit PacketCapture(HANDLE windivert_handle);

    // Closes the handle on destruction
    ~PacketCapture();

    // Non-copyable
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Movable
    PacketCapture(PacketCapture&& other) noexcept;
    PacketCapture& operator=(PacketCapture&& other) noexcept;

    // ── Captured packet ──────────────────────────────────────────────────────

    struct CapturedPacket {
        Packet            packet;  // parsed packet
        WINDIVERT_ADDRESS addr;    // WinDivert address metadata
    };

    // ── Static factory ───────────────────────────────────────────────────────

    /// Opens a WinDivert handle.
    /// filter:   WinDivert filter string (e.g. "ip or ipv6")
    /// layer:    capture layer (default: WINDIVERT_LAYER_NETWORK)
    /// priority: priority (default: 0)
    ///
    /// On failure, prints a specific error message based on GetLastError()
    /// and returns std::nullopt:
    ///   ERROR_ACCESS_DENIED      → suggests running as Administrator
    ///   ERROR_FILE_NOT_FOUND     → suggests installing the WinDivert driver
    ///   other errors             → prints the error code
    static std::optional<PacketCapture> Open(
        const std::string& filter = "ip or ipv6",
        WINDIVERT_LAYER    layer    = WINDIVERT_LAYER_NETWORK,
        INT16              priority = 0);

    // ── Core operations ──────────────────────────────────────────────────────

    /// Blocks to capture the next packet (IPv4 or IPv6).
    /// Returns std::nullopt if the handle is closed or an error occurs.
    std::optional<CapturedPacket> recv();

    /// Re-injects a packet into the network stack.
    /// Returns true on success, false on failure.
    bool inject(const Packet& packet, const WINDIVERT_ADDRESS& addr);

    // ── Multi-threaded processing loop ───────────────────────────────────────

    /// Starts a thread pool. Each thread calls recv() and processes packets via TablePipeline.
    /// thread_count: number of worker threads
    /// pipeline:     table pipeline (lifetime managed by caller)
    /// store:        rule store (lifetime managed by caller)
    void Start(std::size_t thread_count,
               TablePipeline* pipeline,
               const RuleStore* store);

    /// Gracefully stops the thread pool: sets stop flag, closes the WinDivert handle
    /// to wake a blocking recv(), and waits for all worker threads to exit.
    void Stop();

    /// Returns whether the handle is valid
    bool IsValid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE handle_;
    std::atomic<bool> stop_flag_{false};
    std::vector<std::thread> workers_;
    NatTable nat_table_;  // NAT connection tracking table

    // Worker thread entrypoint
    void WorkerLoop(TablePipeline* pipeline);

    // Determines packet direction from WINDIVERT_ADDRESS
    static Direction DirectionFromAddr(const WINDIVERT_ADDRESS& addr) noexcept;
};

}  // namespace winiptables

#endif  // WINIPTABLES_CAPTURE_HPP_
