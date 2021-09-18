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

#include "custom_objects/cache_controller.hh"

#include "base/trace.hh"
#include "debug/CacheController.hh"

namespace gem5
{

CacheController::CacheController(const CacheControllerParams &params) :
    ClockedObject(params),
//    instPort(params.name + ".inst_port", this),
    dataPort(params.name + ".data_port", this),
//    memPortInst(params.name + ".mem_side_inst", this),
    memPortData1(params.name + ".mem_side_data", this),
    memPortData2(params.name + ".mem_side_data_2", this),
    activePort(params.active_port),
    blocked(false)
{
}

Port &
CacheController::getPort(const std::string &if_name, PortID idx)
{
    panic_if(idx != InvalidPortID, "This object doesn't support vector ports");

    if (if_name == "mem_side_data_port_1") {
        return memPortData1;
    } else if (if_name == "mem_side_data_port_2") {
        return memPortData2;
//    } else if (if_name == "inst_port") {
//        return instPort;
    } else if (if_name == "data_port") {
        return dataPort;
    } else {
        // pass it along to our super class
        return ClockedObject::getPort(if_name, idx);
    }
}

void
CacheController::CPUSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the memobj is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingResp(pkt)) {
        blockedPacket = pkt;
    }
}

AddrRangeList
CacheController::CPUSidePort::getAddrRanges() const
{
    return owner->getAddrRanges();
}

void
CacheController::CPUSidePort::trySendRetry()
{
    if (needRetry && blockedPacket == nullptr) {
        // Only send a retry if the port is now completely free
        needRetry = false;
        DPRINTF(CacheController, "Sending retry req for %d\n", id);
        sendRetryReq();
    }
}

void
CacheController::CPUSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->handleFunctional(pkt);
}

bool
CacheController::CPUSidePort::recvTimingReq(PacketPtr pkt)
{
    // Just forward to the memobj.
    if (!owner->handleRequest(pkt)) {
        needRetry = true;
        return false;
    } else {
        return true;
    }
}

void
CacheController::CPUSidePort::recvRespRetry()
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
CacheController::MemSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the memobj is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingReq(pkt)) {
        blockedPacket = pkt;
    }
}

bool
CacheController::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->handleResponse(pkt);
}

void
CacheController::MemSidePort::recvReqRetry()
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
CacheController::MemSidePort::recvRangeChange()
{
    owner->sendRangeChange();
}

bool
CacheController::handleRequest(PacketPtr pkt)
{
    if (blocked) {
        // There is currently an outstanding request. Stall.
        return false;
    }

//    DPRINTF(CacheController, "Got request for addr %#x\n", pkt->getAddr());
    DPRINTF(CacheController, "PC %#x\n", pkt->req->getPC());

    if (pkt->req->getPC() == 0x401d71) {
        DPRINTF(CacheController, "hit");
        activePort = (activePort+1) % 2;
    }

    // This memobj is now blocked waiting for the response to this packet.
    blocked = true;

    // Simply forward to the memory port
    if (pkt->req->hasPaddr())
    {
        if (activePort == 0) {
            memPortData1.sendPacket(pkt);
        } else if (activePort == 1) {
            memPortData2.sendPacket(pkt);
        }
    } else {
        return false;
    }
//    memPort.sendPacket(pkt);

    return true;
}

bool
CacheController::handleResponse(PacketPtr pkt)
{
    assert(blocked);
    DPRINTF(CacheController, "Got response for addr %#x\n", pkt->getAddr());

    // The packet is now done. We're about to put it in the port, no need for
    // this object to continue to stall.
    // We need to free the resource before sending the packet in case the CPU
    // tries to send another request immediately (e.g., in the same callchain).
    blocked = false;

    // Simply forward to the memory port
//    if (pkt->req->isInstFetch()) {
//        instPort.sendPacket(pkt);
//    } else {
        dataPort.sendPacket(pkt);
//    }

    // For each of the cpu ports, if it needs to send a retry, it should do it
    // now since this memory object may be unblocked now.
//    instPort.trySendRetry();
    dataPort.trySendRetry();

    return true;
}

void
CacheController::handleFunctional(PacketPtr pkt)
{
    if (pkt->req->hasPaddr())
    {
        if (activePort == 0) {
            memPortData1.sendFunctional(pkt);
        } else if (activePort == 1) {
            memPortData2.sendFunctional(pkt);
        }
    }

    // Just pass this on to the memory side to handle for now.
//    memPort.sendFunctional(pkt);
}

AddrRangeList
CacheController::getAddrRanges() const
{
    DPRINTF(CacheController, "Sending new ranges\n");
    // Just use the same ranges as whatever is on the memory side.
//    std::cout << memPort1.getAddrRanges();
    return memPortData1.getAddrRanges();
}

void
CacheController::sendRangeChange()
{
//    instPort.sendRangeChange();
    dataPort.sendRangeChange();
}

} // namespace gem5
