
#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <arpa/inet.h>

#include "MyVariables.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MyVariables, "Manually defined variables", "MyVariables");

void MyVariables::initialize() {
    readConfig();
}

void MyVariables::readConfig() {
    ConfigFile *config = s2e()->getConfig();
    std::string cfgKey = getConfigKey();
    ConfigFile::integer_list il;

    // load function addresses
    std::vector<std::string> functions = config->getListKeys(cfgKey + ".functions");
    foreach2 (it, functions.begin(), functions.end()) {
        uint64_t funcAddr = config->getInt(cfgKey + ".functions." + *it);
        functionAddrs[*it] = funcAddr;
    }

    // load TCP keypoint addresses
    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterSockLookup")) {
        addrsAfterSockLookup.insert(addr);
    }

    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterReqSockLookup")) {
        addrsAfterReqSockLookup.insert(addr);
    }

    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterReqSockAllocation")) {
        addrsAfterReqSockAllocation.insert(addr);
    }

    //for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterSynAckSkbAllocation")) {
    //    addrsAfterSynAckSkbAllocation.insert(addr);
    //}

    //for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterSynAckSeqAssignment")) {
    //    addrsAfterSynAckSeqAssignment.insert(addr);
    //}

    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterFullSockAllocation")) {
        addrsAfterFullSockAllocation.insert(addr);
    }

    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsAfterServerISNAssignment")) {
        addrsAfterServerISNAssignment.insert(addr);
    }

    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsSetTCPStateCloseWait")) {
        addrsSetTCPStateCloseWait.insert(addr);
    }

    // load TCP option edge addresses
    il = config->getIntegerList(cfgKey + ".edgeTCPOptParsingLoopBackEdge");
    if (!il.empty()) {
        edgeTCPOptParsingLoopBackEdge.src = il[0];
        edgeTCPOptParsingLoopBackEdge.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptWindow");
    if (!il.empty()) {
        edgeTCPOptWindow.src = il[0];
        edgeTCPOptWindow.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptMSS");
    if (!il.empty()) {
        edgeTCPOptMSS.src = il[0];
        edgeTCPOptMSS.dst= il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptTimestamp");
    if (!il.empty()) {
        edgeTCPOptTimestamp.src = il[0];
        edgeTCPOptTimestamp.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptSACKPerm");
    if (!il.empty()) {
        edgeTCPOptSACKPerm.src = il[0];
        edgeTCPOptSACKPerm.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptSACK");
    if (!il.empty()) {
        edgeTCPOptSACK.src = il[0];
        edgeTCPOptSACK.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptMD5");
    if (!il.empty()) {
        edgeTCPOptMD5.src = il[0];
        edgeTCPOptMD5.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptFastopen");
    if (!il.empty()) {
        edgeTCPOptFastopen.src = il[0];
        edgeTCPOptFastopen.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptExpFastopen");
    if (!il.empty()) {
        edgeTCPOptExpFastopen.src = il[0];
        edgeTCPOptExpFastopen.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptNop");
    if (!il.empty()) {
        edgeTCPOptNop.src = il[0];
        edgeTCPOptNop.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptNop2");
    if (!il.empty()) {
        edgeTCPOptNop2.src = il[0];
        edgeTCPOptNop2.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptEOL");
    if (!il.empty()) {
        edgeTCPOptEOL.src = il[0];
        edgeTCPOptEOL.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptOther");
    if (!il.empty()) {
        edgeTCPOptOther.src = il[0];
        edgeTCPOptOther.dst = il[1];
    }
    il = config->getIntegerList(cfgKey + ".edgeTCPOptOther2");
    if (!il.empty()) {
        edgeTCPOptOther2.src = il[0];
        edgeTCPOptOther2.dst = il[1];
    }

    // load accept/drop points
    ConfigFile::string_list accept_points = config->getStringList(cfgKey + ".acceptPoints");
    getDebugStream() << "acceptPoints:\n";
    for (std::string ap : accept_points) {
        size_t pos = ap.find(':');
        if (pos == std::string::npos) {
            uint64_t address = stoull(ap, 0, 16);
            acceptAddrs.insert(address);
            getDebugStream() << hexval(address) << "\n";
        } else {
            uint64_t src = stoull(ap.substr(0, pos), NULL, 16);
            uint64_t dst = stoull(ap.substr(pos + 1), NULL, 16);
            acceptEdges.insert(Edge(src, dst));
            getDebugStream() << hexval(src) << "->" << hexval(dst) << "\n";
        }
    }

    ConfigFile::string_list drop_points = config->getStringList(cfgKey + ".dropPoints");
    getDebugStream() << "dropPoints:\n";
    for (std::string dp : drop_points) {
        size_t pos = dp.find(':');
        if (pos == std::string::npos) {
            uint64_t address = stoull(dp, 0, 16);
            dropAddrs.insert(address);
            getDebugStream() << hexval(address) << "\n";
        } else {
            uint64_t src = stoull(dp.substr(0, pos), NULL, 16);
            uint64_t dst = stoull(dp.substr(pos + 1), NULL, 16);
            dropEdges.insert(Edge(src, dst));
            getDebugStream() << hexval(src) << "->" << hexval(dst) << "\n";
        }
    }

    // load checksum validation addresses
    for (int64_t addr : config->getIntegerList(cfgKey + ".addrsChecksumValidation")) {
        addrsChecksumValidation.insert(addr);
    }

    addrJiffies = config->getInt(cfgKey + ".addrJiffies");
    
    offsetSkBuffData = config->getInt(cfgKey + ".offsetSkBuffData");
    //offsetSkBuffCb = config->getInt(cfgKey + ".offsetSkBuffCb");
    offsetSockState = config->getInt(cfgKey + ".offsetSockState");
    offsetReqSockSntIsn = config->getInt(cfgKey + ".offsetReqSockSntIsn");
    offsetSkbIpSummed = config->getInt(cfgKey + ".offsetSkbIpSummed");
    offsetSkbIpSummedBit = config->getInt(cfgKey + ".offsetSkbIpSummedBit");

    regSockLookup = config->getInt(cfgKey + ".regSockLookup");
}

} // namespace plugins
} // namespace s2e
