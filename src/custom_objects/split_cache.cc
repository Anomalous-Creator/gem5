/*
 * Copyright (c) 2017 Jason Lowe-Power
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "custom_objects/split_cache.hh"

#include "base/compiler.hh"
#include "base/random.hh"
#include "debug/SplitCache.hh"
#include "sim/system.hh"

#define CUTOFF  8000
namespace gem5
{

SplitCache::SplitCache(const SplitCacheParams &params) :
    ClockedObject(params),
    latency(params.latency),
    blockSize(params.system->cacheLineSize()),
    capacity(params.size / blockSize),
    memPort(params.name + ".mem_side", this),
    blocked(false), originalPacket(nullptr), waitingPortId(-1), stats(this)
{
    // Since the CPU side ports are a vector of ports, create an instance of
    // the CPUSidePort for each connection. This member of params is
    // automatically created depending on the name of the vector port and
    // holds the number of connections to this port name
    for (int i = 0; i < params.port_cpu_side_connection_count; ++i) {
        cpuPorts.emplace_back(name() + csprintf(".cpu_side[%d]", i), i, this);
    }
}

Port &
SplitCache::getPort(const std::string &if_name, PortID idx)
{
    // This is the name from the Python SimObject declaration in SplitCache.py
    if (if_name == "mem_side") {
        panic_if(idx != InvalidPortID,
                 "Mem side of simple cache not a vector port");
        return memPort;
    } else if (if_name == "cpu_side" && idx < cpuPorts.size()) {
        // We should have already created all of the ports in the constructor
        return cpuPorts[idx];
    } else {
        // pass it along to our super class
        return ClockedObject::getPort(if_name, idx);
    }
}

void
SplitCache::CPUSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the cache is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    DPRINTF(SplitCache, "Sending %s to CPU\n", pkt->print());
    if (!sendTimingResp(pkt)) {
        DPRINTF(SplitCache, "failed!\n");
        blockedPacket = pkt;
    }
}

AddrRangeList
SplitCache::CPUSidePort::getAddrRanges() const
{
    return owner->getAddrRanges();
}

void
SplitCache::CPUSidePort::trySendRetry()
{
    if (needRetry && blockedPacket == nullptr) {
        // Only send a retry if the port is now completely free
        needRetry = false;
        DPRINTF(SplitCache, "Sending retry req.\n");
        sendRetryReq();
    }
}

void
SplitCache::CPUSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the cache.
    return owner->handleFunctional(pkt);
}

bool
SplitCache::CPUSidePort::recvTimingReq(PacketPtr pkt)
{
    DPRINTF(SplitCache, "Got request %s\n", pkt->print());

    if (blockedPacket || needRetry) {
        // The cache may not be able to send a reply if this is blocked
        DPRINTF(SplitCache, "Request blocked\n");
        needRetry = true;
        return false;
    }
    // Just forward to the cache.
    if (!owner->handleRequest(pkt, id)) {
        DPRINTF(SplitCache, "Request failed\n");
        // stalling
        needRetry = true;
        return false;
    } else {
        DPRINTF(SplitCache, "Request succeeded\n");
        return true;
    }
}

void
SplitCache::CPUSidePort::recvRespRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    DPRINTF(SplitCache, "Retrying response pkt %s\n", pkt->print());
    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);

    // We may now be able to accept new packets
    trySendRetry();
}

void
SplitCache::MemSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the cache is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingReq(pkt)) {
        blockedPacket = pkt;
    }
}

bool
SplitCache::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    // Just forward to the cache.
    return owner->handleResponse(pkt);
}

void
SplitCache::MemSidePort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);
}

void
SplitCache::MemSidePort::recvRangeChange()
{
    owner->sendRangeChange();
}

bool
SplitCache::handleRequest(PacketPtr pkt, int port_id)
{
    if (blocked) {
        // There is currently an outstanding request so we can't respond. Stall
        return false;
    }

    DPRINTF(SplitCache, "Got request for addr %#x\n", pkt->getAddr());

    // This cache is now blocked waiting for the response to this packet.
    blocked = true;

    // Store the port for when we get the response
    assert(waitingPortId == -1);
    waitingPortId = port_id;

    // Schedule an event after cache access latency to actually access
    schedule(new EventFunctionWrapper([this, pkt]{ accessTiming(pkt); },
                                      name() + ".accessEvent", true),
             clockEdge(latency));

    return true;
}

bool
SplitCache::handleResponse(PacketPtr pkt)
{
    assert(blocked);
    DPRINTF(SplitCache, "Got response for addr %#x\n", pkt->getAddr());

    // For now assume that inserts are off of the critical path and don't count
    // for any added latency.
    insert(pkt);

    stats.missLatency.sample(curTick() - missTime);

    // If we had to upgrade the request packet to a full cache line, now we
    // can use that packet to construct the response.
    if (originalPacket != nullptr) {
        DPRINTF(SplitCache, "Copying data from new packet to old\n");
        // We had to upgrade a previous packet. We can functionally deal with
        // the cache access now. It better be a hit.
        GEM5_VAR_USED bool hit = accessFunctional(originalPacket);
        panic_if(!hit, "Should always hit after inserting");
        originalPacket->makeResponse();
        delete pkt; // We may need to delay this, I'm not sure.
        pkt = originalPacket;
        originalPacket = nullptr;
    } // else, pkt contains the data it needs

    sendResponse(pkt);

    return true;
}

void SplitCache::sendResponse(PacketPtr pkt)
{
    assert(blocked);
    DPRINTF(SplitCache, "Sending resp for addr %#x\n", pkt->getAddr());

    int port = waitingPortId;

    // The packet is now done. We're about to put it in the port, no need for
    // this object to continue to stall.
    // We need to free the resource before sending the packet in case the CPU
    // tries to send another request immediately (e.g., in the same callchain).
    blocked = false;
    waitingPortId = -1;

    // Simply forward to the memory port
    cpuPorts[port].sendPacket(pkt);

    // For each of the cpu ports, if it needs to send a retry, it should do it
    // now since this memory object may be unblocked now.
    for (auto& port : cpuPorts) {
        port.trySendRetry();
    }
}

void
SplitCache::handleFunctional(PacketPtr pkt)
{
    if (accessFunctional(pkt)) {
        pkt->makeResponse();
    } else {
        memPort.sendFunctional(pkt);
    }
}

void
SplitCache::accessTiming(PacketPtr pkt)
{
    bool hit = accessFunctional(pkt);

    DPRINTF(SplitCache, "%s for packet: %s\n", hit ? "Hit" : "Miss",
            pkt->print());

    if (hit) {
        // Respond to the CPU side
        stats.hits++; // update stats
        DDUMP(SplitCache, pkt->getConstPtr<uint8_t>(), pkt->getSize());
        pkt->makeResponse();
        sendResponse(pkt);
    } else {
        stats.misses++; // update stats
        missTime = curTick();
        // Forward to the memory side.
        // We can't directly forward the packet unless it is exactly the size
        // of the cache line, and aligned. Check for that here.
        Addr addr = pkt->getAddr();
        Addr block_addr = pkt->getBlockAddr(blockSize);
        unsigned size = pkt->getSize();
        if (addr == block_addr && size == blockSize) {
            // Aligned and block size. We can just forward.
            DPRINTF(SplitCache, "forwarding packet\n");
            memPort.sendPacket(pkt);
        } else {
            DPRINTF(SplitCache, "Upgrading packet to block size\n");
            panic_if(addr - block_addr + size > blockSize,
                     "Cannot handle accesses that span multiple cache lines");
            // Unaligned access to one cache block
            assert(pkt->needsResponse());
            MemCmd cmd;
            if (pkt->isWrite() || pkt->isRead()) {
                // Read the data from memory to write into the block.
                // We'll write the data in the cache (i.e., a writeback cache)
                cmd = MemCmd::ReadReq;
            } else {
                panic("Unknown packet type in upgrade size");
            }

            // Create a new packet that is blockSize
            PacketPtr new_pkt = new Packet(pkt->req, cmd, blockSize);
            new_pkt->allocate();

            // Should now be block aligned
            assert(new_pkt->getAddr() == new_pkt->getBlockAddr(blockSize));

            // Save the old packet
            originalPacket = pkt;

            DPRINTF(SplitCache, "forwarding packet\n");
            memPort.sendPacket(new_pkt);
        }
    }
}

bool
SplitCache::accessFunctional(PacketPtr pkt)
{
    Addr block_addr = pkt->getBlockAddr(blockSize);
    if (block_addr < CUTOFF) {
        auto it = cacheStore1.find(block_addr);
        if (it != cacheStore1.end()) {
            if (pkt->isWrite()) {
                // Write the data into the block in the cache
                pkt->writeDataToBlock(it->second, blockSize);
            } else if (pkt->isRead()) {
                // Read the data out of the cache block into the packet
                pkt->setDataFromBlock(it->second, blockSize);
            } else {
                panic("Unknown packet type!");
            }
            return true;
        }
        return false;
    } else {
        auto it = cacheStore2.find(block_addr);
        if (it != cacheStore2.end()) {
            if (pkt->isWrite()) {
                // Write the data into the block in the cache
                pkt->writeDataToBlock(it->second, blockSize);
            } else if (pkt->isRead()) {
                // Read the data out of the cache block into the packet
                pkt->setDataFromBlock(it->second, blockSize);
            } else {
                panic("Unknown packet type!");
            }
            return true;
        }
        return false;

    }
}

void
SplitCache::insert(PacketPtr pkt)
{
    // The packet should be aligned.
    assert(pkt->getAddr() ==  pkt->getBlockAddr(blockSize));
    // The address should not be in the cache
    if (pkt->getAddr() < CUTOFF) {
        assert(cacheStore1.find(pkt->getAddr()) == cacheStore1.end());

        // The pkt should be a response
        assert(pkt->isResponse());

        if (cacheStore1.size() >= capacity) {
            // Select random thing to evict. This is a little convoluted since
            // we are using a std::unordered_map. See http://bit.ly/2hrnLP2
            int bucket, bucket_size;
            do {
                bucket = random_mt.random(
                        0, (int)cacheStore1.bucket_count() - 1);
            } while ( (bucket_size = cacheStore1.bucket_size(bucket)) == 0 );
            auto block = std::next(cacheStore1.begin(bucket),
                                   random_mt.random(0, bucket_size - 1));

            DPRINTF(SplitCache, "Removing addr %#x\n", block->first);

            // Write back the data.
            // Create a new request-packet pair
            RequestPtr req = std::make_shared<Request>(
                block->first, blockSize, 0, 0);

            PacketPtr new_pkt = new Packet(
                    req, MemCmd::WritebackDirty, blockSize);
            new_pkt->dataDynamic(block->second); // This will be deleted later

            DPRINTF(SplitCache, "Writing packet back %s\n", pkt->print());
            // Send the write to memory
            memPort.sendPacket(new_pkt);

            // Delete this entry
            cacheStore1.erase(block->first);
        }

        DPRINTF(SplitCache, "Inserting %s\n", pkt->print());
        DDUMP(SplitCache, pkt->getConstPtr<uint8_t>(), blockSize);

        // Allocate space for the cache block data
        uint8_t *data = new uint8_t[blockSize];

        // Insert the data and address into the cache store
        cacheStore1[pkt->getAddr()] = data;

        // Write the data into the cache
        pkt->writeDataToBlock(data, blockSize);
    } else {
        assert(cacheStore2.find(pkt->getAddr()) == cacheStore2.end());

        // The pkt should be a response
        assert(pkt->isResponse());

        if (cacheStore2.size() >= capacity) {
            // Select random thing to evict. This is a little convoluted since
            // we are using a std::unordered_map. See http://bit.ly/2hrnLP2
            int bucket, bucket_size;
            do {
                bucket = random_mt.random(0,
                        (int)cacheStore2.bucket_count() - 1);
            } while ( (bucket_size = cacheStore2.bucket_size(bucket)) == 0 );
            auto block = std::next(cacheStore2.begin(bucket),
                                   random_mt.random(0, bucket_size - 1));

            DPRINTF(SplitCache, "Removing addr %#x\n", block->first);

            // Write back the data.
            // Create a new request-packet pair
            RequestPtr req = std::make_shared<Request>(
                block->first, blockSize, 0, 0);

            PacketPtr new_pkt = new Packet(
                    req, MemCmd::WritebackDirty, blockSize);
            new_pkt->dataDynamic(block->second); // This will be deleted later

            DPRINTF(SplitCache, "Writing packet back %s\n", pkt->print());
            // Send the write to memory
            memPort.sendPacket(new_pkt);

            // Delete this entry
            cacheStore2.erase(block->first);
        }

        DPRINTF(SplitCache, "Inserting %s\n", pkt->print());
        DDUMP(SplitCache, pkt->getConstPtr<uint8_t>(), blockSize);

        // Allocate space for the cache block data
        uint8_t *data = new uint8_t[blockSize];

        // Insert the data and address into the cache store
        cacheStore2[pkt->getAddr()] = data;

        // Write the data into the cache
        pkt->writeDataToBlock(data, blockSize);
    }
}

AddrRangeList
SplitCache::getAddrRanges() const
{
    DPRINTF(SplitCache, "Sending new ranges\n");
    // Just use the same ranges as whatever is on the memory side.
    return memPort.getAddrRanges();
}

void
SplitCache::sendRangeChange() const
{
    for (auto& port : cpuPorts) {
        port.sendRangeChange();
    }
}

SplitCache::SplitCacheStats::SplitCacheStats(statistics::Group *parent)
      : statistics::Group(parent),
      ADD_STAT(hits, statistics::units::Count::get(), "Number of hits"),
      ADD_STAT(misses, statistics::units::Count::get(), "Number of misses"),
      ADD_STAT(missLatency, statistics::units::Tick::get(),
               "Ticks for misses to the cache"),
      ADD_STAT(hitRatio, statistics::units::Ratio::get(),
               "The ratio of hits to the total accesses to the cache",
               hits / (hits + misses))
{
    missLatency.init(16); // number of buckets
}

} // namespace gem5
