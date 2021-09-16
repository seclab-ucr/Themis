
#ifndef S2E_PLUGINS_MYVARIABLES_H
#define S2E_PLUGINS_MYVARIABLES_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/MyPlugins/Edge.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>


namespace s2e {
namespace plugins {


class MyVariables : public Plugin {
    S2E_PLUGIN
public:
    MyVariables(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    std::unordered_set<uint64_t> acceptAddrs;
    std::unordered_set<Edge> acceptEdges;
    std::unordered_set<uint64_t> dropAddrs;
    std::unordered_set<Edge> dropEdges;

    std::unordered_set<uint64_t> addrsChecksumValidation;

    std::unordered_map<std::string, uint64_t> functionAddrs;

    std::unordered_set<uint64_t> addrsAfterSockLookup;
    std::unordered_set<uint64_t> addrsAfterReqSockLookup;
    std::unordered_set<uint64_t> addrsAfterReqSockAllocation;
    //std::unordered_set<uint64_t> addrsAfterSynAckSkbAllocation;
    //std::unordered_set<uint64_t> addrsAfterSynAckSeqAssignment;
    std::unordered_set<uint64_t> addrsAfterFullSockAllocation;
    std::unordered_set<uint64_t> addrsAfterServerISNAssignment;

    std::unordered_set<uint64_t> addrsSetTCPStateCloseWait;

    Edge edgeTCPOptParsingLoopBackEdge;
    Edge edgeTCPOptWindow;
    Edge edgeTCPOptMSS;
    Edge edgeTCPOptTimestamp;
    Edge edgeTCPOptSACKPerm;
    Edge edgeTCPOptSACK;
    Edge edgeTCPOptMD5;
    Edge edgeTCPOptFastopen;
    Edge edgeTCPOptExpFastopen;
    Edge edgeTCPOptNop;
    Edge edgeTCPOptNop2;
    Edge edgeTCPOptEOL;
    Edge edgeTCPOptOther;
    Edge edgeTCPOptOther2;

    uint64_t addrJiffies;

    // offsets
    int offsetSkBuffData;
    //int offsetSkBuffCb;
    int offsetSockState;
    int offsetReqSockSntIsn;
    int offsetSkbIpSummed;
    int offsetSkbIpSummedBit;

    // registers
    int regSockLookup;

private:
    void readConfig();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MYVARIABLES_H
