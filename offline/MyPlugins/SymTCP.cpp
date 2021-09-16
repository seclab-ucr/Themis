
#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <klee/util/ExprSMTLIBPrinter.h>

#include <arpa/inet.h>

#include "SymTCP.h"

#define SERVER_PORT 5555

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(SymTCP, "Symbolize TCP packet header fields.", "SymTCP", "BaseInstructions", "MemRangeDetector", "MyExecutionMonitor", "MyVariables", "TestCaseGenerator", "MyTracer", "PathMerger", "MergingSearcher");

void SymTCP::initialize() {
    m_base = s2e()->getPlugin<BaseInstructions>();
    m_memrange = s2e()->getPlugin<MemRangeDetector>();
    m_monitor = s2e()->getPlugin<MyExecutionMonitor>();
    m_vars = s2e()->getPlugin<MyVariables>();
    m_tcgen = s2e()->getPlugin<testcases::TestCaseGenerator>();
    m_tracer = s2e()->getPlugin<MyTracer>();
    //m_forklimiter = s2e()->getPlugin<MyForkLimiter>();
    m_path_merger = s2e()->getPlugin<PathMerger>();
    m_merging_searcher = s2e()->getPlugin<MergingSearcher>();
    
    readConfig();

    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &SymTCP::onStateForkDecide));

    hookFunctions();
    hookAcceptAndDropPoints();

    // Hook checksum validation points
    if (m_genBadCsumCases) {
        for (auto addr : m_vars->addrsChecksumValidation) {
            m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::onChecksumValidation));
        }
    }

    // Hook on connection closed
    //for (auto addr : m_vars->addrsSetTCPStateCloseWait) {
    //    m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::onSetTCPStateCloseWait));
    //}

    // Hook to get address of sock
    // hook the next translation block of socket lookup
    for (auto addr : m_vars->addrsAfterSockLookup) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterSockLookup));
    }

    // Hook to get address of req sock (before v4.4)
    // hook the next translation block of request socket lookup
    for (auto addr : m_vars->addrsAfterReqSockLookup) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterReqSockLookup));
    }

    // Hook to get address of server ISN
    // hook the next translation block of request sock allocation
    for (auto addr : m_vars->addrsAfterReqSockAllocation) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterReqSockAllocation));
    }

    /*
    // hook the next translation block of synack skb allocation
    for (auto addr : m_vars->addrsAfterSynAckSkbAllocation) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterSynAckSkbAllocation));
    }
    // hook the next translation block of synack seq assignment
    for (auto addr : m_vars->addrsAfterSynAckSeqAssignment) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterSynAckSeqAssignment));
    }
    */

    // Hook to get address of newly created full socket
    // hook the next translation block of full socket allocation
    for (auto addr : m_vars->addrsAfterFullSockAllocation) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterFullSockAllocation));
    }

    // Hook to symbolize server ISN
    for (auto addr : m_vars->addrsAfterServerISNAssignment) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::afterServerISNAssignment));
    }

    hookTCPOptionsParsing();

    // tmp : Hook tcp_check_req seq in_window check
    /*
    if (m_vars->offsetSkbIpSummedBit == 5) {
        m_monitor->hookAddress(0xffffffff818b3ca0, sigc::mem_fun(*this, &SymTCP::tcp_check_req_seq_in_window));
    } else {
        m_monitor->hookAddress(0xffffffff81738e7e, sigc::mem_fun(*this, &SymTCP::tcp_check_req_seq_in_window));
    }

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &SymTCP::onTranslateBlockStart));
    */

    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(sigc::mem_fun(*this, &SymTCP::onConcreteDataMemoryAccess));

    //s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &SymTCP::onEngineShutdown));

    // for debug purpose
    // 4.4
    m_monitor->hookAddress(0xffffffff8171fc50, sigc::mem_fun(*this, &SymTCP::on_debug));
    m_monitor->hookAddress(0xffffffff81733a80, sigc::mem_fun(*this, &SymTCP::on_debug));
    m_monitor->hookAddress(0xffffffff81733e50, sigc::mem_fun(*this, &SymTCP::on_debug));
    m_monitor->hookAddress(0xffffffff81734790, sigc::mem_fun(*this, &SymTCP::on_debug));
    // 5.4
    m_monitor->hookAddress(0xffffffff81896540, sigc::mem_fun(*this, &SymTCP::on_debug));
    m_monitor->hookAddress(0xffffffff818ad180, sigc::mem_fun(*this, &SymTCP::on_debug));
    m_monitor->hookAddress(0xffffffff818ad760, sigc::mem_fun(*this, &SymTCP::on_debug));
    m_monitor->hookAddress(0xffffffff818ae1c0, sigc::mem_fun(*this, &SymTCP::on_debug));
}

void SymTCP::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc) {
    /*
    if (m_memrange->isInRange(pc)) {
        if (m_vars->offsetSkbIpSummedBit == 5) {
            if (pc == 0xffffffff818b41f0) {
                signal->connect(sigc::mem_fun(*this, &SymTCP::onExecuteBlockStart));
            }
        } else {
            if (pc == 0xffffffff81739610) {
                signal->connect(sigc::mem_fun(*this, &SymTCP::onExecuteBlockStart));
            }
        }
        signal->connect(sigc::mem_fun(*this, &SymTCP::onExecuteBlockStart));
    }
    */
}

void SymTCP::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    /*
    DECLARE_PLUGINSTATE(SymTCPState, state);
    target_long req_addr, sk_addr;
    uint32_t val;

    if (plgState->m_reqsock_addr) {
        if (!state->mem()->read(plgState->m_reqsock_addr + 0x7c, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from reqsock_addr + 0x7c\n";
            return;
        }
        getDebugStream(state) << "req->rsk_rcv_wnd: " << hexval(val) << "\n";
    }

    if (m_vars->offsetSkbIpSummedBit == 5) {
        if (pc == 0xffffffff818b41f0) {
            if (!state->regs()->read(CPU_OFFSET(regs[R_EDI]), &req_addr, sizeof(req_addr), false)) {
                getWarningsStream(state) << "ERROR: couldn't read reg\n";
                return;
            }
            getDebugStream(state) << "req: " << hexval(req_addr) << "\n";

            if (!state->regs()->read(CPU_OFFSET(regs[R_ESI]), &sk_addr, sizeof(sk_addr), false)) {
                getWarningsStream(state) << "ERROR: couldn't read reg\n";
                return;
            }
            getDebugStream(state) << "sk: " << hexval(sk_addr) << "\n";

            if (!state->mem()->read(sk_addr + 0x10c, &val, sizeof(val))) {
                getWarningsStream(state) << "ERROR: couldn't read mem\n";
                return;
            }
            getDebugStream(state) << "sk->sk_rcvbuf: " << hexval(val) << "\n";
        }
    } else {
        if (pc == 0xffffffff81739610) {
            if (!state->regs()->read(CPU_OFFSET(regs[R_EDI]), &req_addr, sizeof(req_addr), false)) {
                getWarningsStream(state) << "ERROR: couldn't read reg\n";
                return;
            }
            getDebugStream(state) << "req: " << hexval(req_addr) << "\n";

            if (!state->regs()->read(CPU_OFFSET(regs[R_ESI]), &sk_addr, sizeof(sk_addr), false)) {
                getWarningsStream(state) << "ERROR: couldn't read reg\n";
                return;
            }
            getDebugStream(state) << "sk: " << hexval(sk_addr) << "\n";

            if (!state->mem()->read(sk_addr + 0xec, &val, sizeof(val))) {
                getWarningsStream(state) << "ERROR: couldn't read mem\n";
                return;
            }
            getDebugStream(state) << "sk->sk_rcvbuf: " << hexval(val) << "\n";
        }
    }
    */
}

void SymTCP::tcp_check_req_seq_in_window(S2EExecutionState *state, uint64_t pc) {
    target_long reqsock_addr, skb_addr;
    uint32_t val;
    //uint32_t rcv_nxt;
    //uint32_t rsk_rcv_wnd;
    //int offset;
    
    if (m_vars->offsetSkbIpSummedBit == 5) {
        if (!state->regs()->read(CPU_OFFSET(regs[12]), &reqsock_addr, sizeof(reqsock_addr), false)) {
            getWarningsStream(state) << "ERROR: couldn't read reg R12\n";
            return;
        }

        if (!state->regs()->read(CPU_OFFSET(regs[R_EBX]), &skb_addr, sizeof(skb_addr), false)) {
            getWarningsStream(state) << "ERROR: couldn't read reg RBX\n";
            return;
        }

        if (!state->mem()->read(skb_addr + 0x38, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from skb_addr + 0x38\n";
            return;
        }
        getDebugStream(state) << "skb->ack_seq: " << hexval(val) << "\n";

        if (!state->mem()->read(reqsock_addr + 0x120, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from reqsock_addr + 0x120\n";
            return;
        }
        getDebugStream(state) << "req->rcv_nxt: " << hexval(val) << "\n";

        if (!state->mem()->read(reqsock_addr + 0x7c, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from reqsock_addr + 0x7c\n";
            return;
        }
        getDebugStream(state) << "req->rsk_rcv_wnd: " << hexval(val) << "\n";

        if (!state->mem()->read(skb_addr + 0x2c, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from skb_addr + 0x2c\n";
            return;
        }
        getDebugStream(state) << "skb->seq: " << hexval(val) << "\n";
    } else {
        if (!state->regs()->read(CPU_OFFSET(regs[14]), &reqsock_addr, sizeof(reqsock_addr), false)) {
            getWarningsStream(state) << "ERROR: couldn't read reg R12\n";
            return;
        }

        if (!state->regs()->read(CPU_OFFSET(regs[R_EBX]), &skb_addr, sizeof(skb_addr), false)) {
            getWarningsStream(state) << "ERROR: couldn't read reg RBX\n";
            return;
        }

        if (!state->mem()->read(skb_addr + 0x38, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from skb_addr + 0x38\n";
            return;
        }
        getDebugStream(state) << "skb->ack_seq: " << hexval(val) << "\n";

        if (!state->mem()->read(reqsock_addr + 0x13c, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from reqsock_addr + 0x13c\n";
            return;
        }
        getDebugStream(state) << "req->rcv_nxt: " << hexval(val) << "\n";

        if (!state->mem()->read(reqsock_addr + 0x7c, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from reqsock_addr + 0x7c\n";
            return;
        }
        getDebugStream(state) << "req->rsk_rcv_wnd: " << hexval(val) << "\n";

        if (!state->mem()->read(skb_addr + 0x2c, &val, sizeof(val))) {
            getWarningsStream(state) << "ERROR: couldn't read from skb_addr + 0x2c\n";
            return;
        }
        getDebugStream(state) << "skb->seq: " << hexval(val) << "\n";
    }
}

void SymTCP::readConfig() {
    ConfigFile *config = s2e()->getConfig();
    std::string cfgKey = getConfigKey();

    m_concretePacketCounter = config->getInt(cfgKey + ".concretePacketCounter");
    m_symbolicPacketCounter = config->getInt(cfgKey + ".symbolicPacketCounter");
    m_symbolicTCPOptionsLength = config->getInt(cfgKey + ".symbolicTCPOptionsLength", 0);
    m_symbolicTCPOptionsStart = config->getInt(cfgKey + ".symbolicTCPOptionsStart", 0);
    m_symbolicTCPOptionsEnd = config->getInt(cfgKey + ".symbolicTCPOptionsEnd", 0);
    m_optMSSCountLimit = config->getInt(cfgKey + ".optMSSCountLimit", 99);
    m_optWindowCountLimit = config->getInt(cfgKey + ".optWindowCountLimit", 99);
    m_optSACKPermCountLimit = config->getInt(cfgKey + ".optSACKPermCountLimit", 99);
    m_optSACKCountLimit = config->getInt(cfgKey + ".optSACKCountLimit", 99);
    m_optTimestampCountLimit = config->getInt(cfgKey + ".optTimestampCountLimit", 99);
    m_optMD5CountLimit = config->getInt(cfgKey + ".optMD5CountLimit", 99);
    m_optFastopenCountLimit = config->getInt(cfgKey + ".optFastopenCountLimit", 99);
    m_optExpFastopenCountLimit = config->getInt(cfgKey + ".optExpFastopenCountLimit", 99);
    m_optNopCountLimit = config->getInt(cfgKey + ".optNopCountLimit", 99);
    m_optEOLCountLimit = config->getInt(cfgKey + ".optEOLCountLimit", 99);
    m_optOtherCountLimit = config->getInt(cfgKey + ".optOtherCountLimit", 99);
    m_optParsingLoopBackEdgeCountLimit = config->getInt(cfgKey + ".optParsingLoopBackEdgeCountLimit", 99);

    m_terminateAtAP = config->getBool(cfgKey + ".terminateAtAcceptPoint", false);
    m_terminateAtDP = config->getBool(cfgKey + ".terminateAtDropPoint", false);

    m_genBadCsumCases = config->getBool(cfgKey + ".generateBadChecksumCases", false);
}

void SymTCP::hookFunctions() {
    // hook tcp_v4_rcv
    std::unordered_map<std::string, uint64_t>::const_iterator it;
    it = m_vars->functionAddrs.find("tcp_v4_rcv");
    if (it == m_vars->functionAddrs.end()) {
        getWarningsStream() << "Cannot find address of tcp_v4_rcv.\n";
        return;
    }
    m_monitor->hookFunction(it->second, sigc::mem_fun(*this, &SymTCP::on_tcp_v4_rcv), sigc::mem_fun(*this, &SymTCP::on_tcp_v4_rcv_ret));

    // hook tcp_parse_options
    it = m_vars->functionAddrs.find("tcp_parse_options"); 
    if (it != m_vars->functionAddrs.end()) {
        m_monitor->hookFunction(it->second, sigc::mem_fun(*this, &SymTCP::on_tcp_parse_options));
    }

    // hook sk_reset_timer
    it = m_vars->functionAddrs.find("sk_reset_timer");
    if (it != m_vars->functionAddrs.end()) {
        m_monitor->hookFunction(it->second, sigc::mem_fun(*this, &SymTCP::on_sk_reset_timer));
    }

    // hook mod_timer
    it = m_vars->functionAddrs.find("mod_timer");
    if (it != m_vars->functionAddrs.end()) {
        m_monitor->hookFunction(it->second, sigc::mem_fun(*this, &SymTCP::on_mod_timer));
    }

    // hook mod_timer_pinned
    it = m_vars->functionAddrs.find("mod_timer_pinned");
    if (it != m_vars->functionAddrs.end()) {
        m_monitor->hookFunction(it->second, sigc::mem_fun(*this, &SymTCP::on_mod_timer_pinned));
    }
}

void SymTCP::hookAcceptAndDropPoints() {
    for (uint64_t addr : m_vars->acceptAddrs) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::onAcceptAddr));
    }
    for (auto edge : m_vars->acceptEdges) {
        m_monitor->hookEdge(edge.src, edge.dst, sigc::mem_fun(*this, &SymTCP::onAcceptEdge));
    }
    for (uint64_t addr : m_vars->dropAddrs) {
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &SymTCP::onDropAddr));
    }
    for (auto edge : m_vars->dropEdges) {
        m_monitor->hookEdge(edge.src, edge.dst, sigc::mem_fun(*this, &SymTCP::onDropEdge));
    }
}

void SymTCP::hookTCPOptionsParsing() {
    m_monitor->hookEdge(m_vars->edgeTCPOptParsingLoopBackEdge, sigc::mem_fun(*this, &SymTCP::onTCPOptionParsingLoopBackEdge));
    m_monitor->hookEdge(m_vars->edgeTCPOptMSS, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), MSS));
    m_monitor->hookEdge(m_vars->edgeTCPOptWindow, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Window));
    m_monitor->hookEdge(m_vars->edgeTCPOptSACKPerm, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), SACKPerm));
    m_monitor->hookEdge(m_vars->edgeTCPOptSACK, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), SACK));
    m_monitor->hookEdge(m_vars->edgeTCPOptTimestamp, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Timestamp));
    m_monitor->hookEdge(m_vars->edgeTCPOptMD5, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), MD5));
    m_monitor->hookEdge(m_vars->edgeTCPOptFastopen, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Fastopen));
    m_monitor->hookEdge(m_vars->edgeTCPOptExpFastopen, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), ExpFastopen));
    m_monitor->hookEdge(m_vars->edgeTCPOptNop, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Nop));
    m_monitor->hookEdge(m_vars->edgeTCPOptNop2, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Nop));
    m_monitor->hookEdge(m_vars->edgeTCPOptEOL, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), EOL));
    m_monitor->hookEdge(m_vars->edgeTCPOptOther, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Other));
    m_monitor->hookEdge(m_vars->edgeTCPOptOther2, sigc::bind(sigc::mem_fun(*this, &SymTCP::onTCPOption), Other));
}

void SymTCP::onTCPOptionParsingLoopBackEdge(S2EExecutionState *state, uint64_t src, uint64_t dst) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    plgState->m_optParsingLoopBackEdgeCount++;
    getDebugStream(state) << "TCP parsing loop back edge count: " << plgState->m_optParsingLoopBackEdgeCount << "\n";
    if (plgState->m_optParsingLoopBackEdgeCount > m_optParsingLoopBackEdgeCountLimit) {
        getDebugStream(state) << "exceeds TCP option parsing loop back edge count limit. " << plgState->m_optParsingLoopBackEdgeCount << " > " << m_optParsingLoopBackEdgeCountLimit << "\n";
        s2e()->getExecutor()->terminateState(*state, "exceeds TCP Window option parsing loop back edge count limit.");
    }
}

void SymTCP::onTCPOption(S2EExecutionState *state, uint64_t src, uint64_t dst, TCPOption option) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (option != Nop && option != EOL && option != Other) {
        if (plgState->m_opt == None) {
            // set the option
            plgState->m_opt = option;
        } else {
            // check the option
            if (plgState->m_opt != option) {
                getDebugStream(state) << "Different TCP option encountered. " << plgState->m_opt << " != " << option << "\n";
                s2e()->getExecutor()->terminateState(*state, "Different TCP option encountered.");
            }
        }
    }
    switch (option) {
        case MSS:
            plgState->m_optMSSCount++;
            getDebugStream(state) << "Found TCP Option MSS. optMSSCount: " << plgState->m_optMSSCount << "\n";
            if (plgState->m_optMSSCount > m_optMSSCountLimit) {
                getDebugStream(state) << "exceeds TCP MSS option count limit. " << plgState->m_optMSSCount << " > " << m_optMSSCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP MSS option count limit.");
            }
            break;
        case Window:
            plgState->m_optWindowCount++;
            getDebugStream(state) << "Found TCP Option Window. optWindowCount: " << plgState->m_optWindowCount << "\n";
            if (plgState->m_optWindowCount > m_optWindowCountLimit) {
                getDebugStream(state) << "exceeds TCP Window option count limit. " << plgState->m_optWindowCount << " > " << m_optWindowCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP Window option count limit.");
            }
            break;
        case SACKPerm:
            plgState->m_optSACKPermCount++;
            getDebugStream(state) << "Found TCP Option SACKPerm. optSACKPermCount: " << plgState->m_optSACKPermCount << "\n";
            if (plgState->m_optSACKPermCount > m_optSACKPermCountLimit) {
                getDebugStream(state) << "exceeds TCP SACKPerm option count limit. " << plgState->m_optSACKPermCount << " > " << m_optSACKPermCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP SACKPerm option count limit.");
            }
            break;
        case SACK:
            plgState->m_optSACKCount++;
            getDebugStream(state) << "Found TCP Option SACK. optSACKCount: " << plgState->m_optSACKCount << "\n";
            if (plgState->m_optSACKCount > m_optSACKCountLimit) {
                getDebugStream(state) << "exceeds TCP SACK option count limit. " << plgState->m_optSACKCount << " > " << m_optSACKCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP SACK option count limit.");
            }
            break;
        case Timestamp:
            plgState->m_optTimestampCount++;
            getDebugStream(state) << "Found TCP Option Timestamp. optTimestampCount: " << plgState->m_optTimestampCount << "\n";
            if (plgState->m_optTimestampCount > m_optTimestampCountLimit) {
                getDebugStream(state) << "exceeds TCP Timestamp option count limit. " << plgState->m_optTimestampCount << " > " << m_optTimestampCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP Timestamp option count limit.");
            }
            break;
        case MD5:
            plgState->m_optMD5Count++;
            getDebugStream(state) << "Found TCP Option MD5. optMD5Count: " << plgState->m_optMD5Count << "\n";
            if (plgState->m_optMD5Count > m_optMD5CountLimit) {
                getDebugStream(state) << "exceeds TCP MD5 option count limit. " << plgState->m_optMD5Count << " > " << m_optMD5CountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP MD5 option count limit.");
            }
            break;
        case Fastopen:
            plgState->m_optFastopenCount++;
            getDebugStream(state) << "Found TCP Option Fastopen. optFastopenCount: " << plgState->m_optFastopenCount << "\n";
            if (plgState->m_optFastopenCount > m_optFastopenCountLimit) {
                getDebugStream(state) << "exceeds TCP Fastopen option count limit. " << plgState->m_optFastopenCount << " > " << m_optFastopenCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP Fastopen option count limit.");
            }
            break;
        case ExpFastopen:
            plgState->m_optExpFastopenCount++;
            getDebugStream(state) << "Found TCP Option ExpFastopen. optExpFastopenCount: " << plgState->m_optExpFastopenCount << "\n";
            if (plgState->m_optExpFastopenCount > m_optExpFastopenCountLimit) {
                getDebugStream(state) << "exceeds TCP ExpFastopen option count limit. " << plgState->m_optExpFastopenCount << " > " << m_optExpFastopenCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP ExpFastopen option count limit.");
            }
            break;
        case Nop:
            plgState->m_optNopCount++;
            getDebugStream(state) << "Found TCP Option Nop. optNopCount: " << plgState->m_optNopCount << "\n";
            if (plgState->m_optNopCount > m_optNopCountLimit) {
                getDebugStream(state) << "exceeds TCP Nop option count limit. " << plgState->m_optNopCount << " > " << m_optNopCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP Nop option count limit.");
            }
            break;
        case EOL:
            plgState->m_optEOLCount++;
            getDebugStream(state) << "Found TCP Option EOL. optEOLCount: " << plgState->m_optEOLCount << "\n";
            if (plgState->m_optEOLCount > m_optEOLCountLimit) {
                getDebugStream(state) << "exceeds TCP EOL option count limit. " << plgState->m_optEOLCount << " > " << m_optEOLCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP EOL option count limit.");
            }
            break;
        case Other:
            plgState->m_optOtherCount++;
            getDebugStream(state) << "Other TCP option. optOtherCount: " << plgState->m_optOtherCount << "\n";
            if (plgState->m_optOtherCount > m_optOtherCountLimit) {
                getDebugStream(state) << "exceeds TCP Other option count limit. " << plgState->m_optOtherCount << " > " << m_optOtherCountLimit << "\n";
                s2e()->getExecutor()->terminateState(*state, "exceeds TCP Other option count limit.");
            }
            break;
        default:
            break;
    }
}

void SymTCP::onSetTCPStateCloseWait(S2EExecutionState *state, uint64_t pc) {
    // we are in TCP_CLOSE_WAIT state, terminate the state
    // terminate state
    getDebugStream(state) << "tcp_set_state(sk, TCP_CLOSE_WAIT). Killed state.\n";
    s2e()->getExecutor()->terminateState(*state);
}

void SymTCP::onChecksumValidation(S2EExecutionState *state, uint64_t pc) {
    // imitate the output of a normal "reached instruction/edge of interest" case
    std::stringstream ss;
    ss << "Reached drop point: " << hexval(pc) << "\n";

    int sk_state = readSocketState(state);
    getDebugStream(state) << "Socket state: " << sk_state << "\n";

    dumpAcceptPointsReached(state);
    getDebugStream(state) << "Drop points reached: " << hexval(pc) << "\n";

    dumpQuerySMTv2(state);

    m_tcgen->generateTestCases(state, "result", testcases::TC_LOG);
    getDebugStream(state) << "Terminating state: bad checksum case.\n";
}

void SymTCP::on_tcp_v4_rcv(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc) {
    DECLARE_PLUGINSTATE(SymTCPState, state);

    getDebugStream(state) << "Entering tcp_v4_rcv. " << (plgState->m_concretePacketIndex + plgState->m_symbolicPacketIndex - 1) << "\n";

    // reset the sk and req pointers
    plgState->reset();

    // reset fork conuts
    //m_forklimiter->reset(state);

    // Fork the current state
#if 0
    if (m_firstTime) {
        s2e()->getExecutor()->forkAndSave();
        m_firstTime = false;
    }
#endif

    // extract TCP header 
    target_ulong sk_buff;
    if (!state->regs()->read(CPU_OFFSET(regs[R_EDI]), &sk_buff, sizeof(sk_buff), false)) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to tcp_v4_rcv.\n";
        return;
    }  
    getDebugStream(state) << "sk_buff: " << hexval(sk_buff) << "\n";

    int offset = m_vars->offsetSkBuffData;  // offset to sk_buff->data
    target_ulong sk_buff_data;
    //for (offset = 0; offset < 1024; offset++) {
    if (!state->mem()->read(sk_buff + offset, &sk_buff_data, sizeof(sk_buff_data))) {
        getWarningsStream(state) << "ERROR: couldn't read memory " << hexval(sk_buff + offset) << "\n";
        return;
    }
    getDebugStream(state) << "offset: " << offset << ", sk_buff->data: " << hexval(sk_buff_data) << "\n";
    //}

    uint16_t sport, dport;
    if (!state->mem()->read(sk_buff_data, &sport, sizeof(sport))) {
        getWarningsStream(state) << "ERROR: couldn't read src port " << hexval(sk_buff_data) << "\n";
        return;
    }
    sport = ntohs(sport);
    if (!state->mem()->read(sk_buff_data + 2, &dport, sizeof(dport))) {
        getWarningsStream(state) << "ERROR: couldn't read dst port " << hexval(sk_buff_data + 2) << "\n";
        return;
    }
    dport = ntohs(dport);
    getDebugStream(state) << "TCP src port: " << sport << ", dst port: " << dport << "\n";

    uint32_t seq_num;
    if (!state->mem()->read(sk_buff_data + 4, &seq_num, sizeof(seq_num))) {
        getWarningsStream(state) << "ERROR: couldn't read seq num " << hexval(sk_buff_data + 4) << "\n";
        return;
    }
    getDebugStream(state) << "TCP seq num: " << hexval(htonl(seq_num)) << "\n";

    if (dport != SERVER_PORT) {
        return;
    }

    // send concrete packets first, then symbolic packets
    if (plgState->m_concretePacketIndex <= m_concretePacketCounter) {
        plgState->m_concretePacketIndex++;
    } else {
        if (plgState->m_symbolicPacketIndex <= m_symbolicPacketCounter) {
            // always run with klee
            //m_base->alwaysKlee(state, 1);

            // symbolize TCP packet header fields
            m_base->makeSymbolic(state, sk_buff_data + 4, 4, "tcp_seq_num" + std::to_string(plgState->m_symbolicPacketIndex));
            m_base->makeSymbolic(state, sk_buff_data + 8, 4, "tcp_ack_num" + std::to_string(plgState->m_symbolicPacketIndex));
            //m_base->makeSymbolic(state, sk_buff_data + 12, 1, "tcp_doff_reserved_flags" + std::to_string(plgState->m_symbolicPacketIndex));
            m_base->makeSymbolic(state, sk_buff_data + 13, 1, "tcp_flags" + std::to_string(plgState->m_symbolicPacketIndex));
            m_base->makeSymbolic(state, sk_buff_data + 14, 2, "tcp_win" + std::to_string(plgState->m_symbolicPacketIndex));
            //m_base->makeSymbolic(state, sk_buff_data + 16, 2, "tcp_csum" + std::to_string(plgState->m_symbolicPacketIndex));
            m_base->makeSymbolic(state, sk_buff_data + 18, 2, "tcp_urg_ptr" + std::to_string(plgState->m_symbolicPacketIndex));
            if (m_symbolicTCPOptionsLength > 0) {
                m_base->makeSymbolic(state, sk_buff_data + 20, m_symbolicTCPOptionsLength, "tcp_options" + std::to_string(plgState->m_symbolicPacketIndex));
            } else if (m_symbolicTCPOptionsStart > 0 && m_symbolicTCPOptionsEnd > 0 && m_symbolicTCPOptionsEnd - m_symbolicTCPOptionsStart > 0) {
                m_base->makeSymbolic(state, sk_buff_data + 20 + m_symbolicTCPOptionsStart, m_symbolicTCPOptionsEnd - m_symbolicTCPOptionsStart, "tcp_options" + std::to_string(plgState->m_symbolicPacketIndex));
            }
    
            getDebugStream(state) << "TCP packet header symbolized.\n";
            plgState->m_symbolicPacketIndex++;
            
            // slow down clock
            //*g_sqi.exec.clock_scaling_factor = 10000;

            //state->setStateSwitchForbidden(true);
        } 
    }

    // byass checksum validation by setting ip_summed to CHECKSUM_UNNECESSARY
    if (m_vars->offsetSkbIpSummed && m_vars->offsetSkbIpSummedBit) {
        unsigned char byte;
        state->mem()->read(sk_buff + m_vars->offsetSkbIpSummed, &byte, sizeof(byte));
        // clear the bits
        byte &= ~(3 << m_vars->offsetSkbIpSummedBit);
        // set the bits
        byte |= 1 << m_vars->offsetSkbIpSummedBit;
        state->mem()->write(sk_buff + m_vars->offsetSkbIpSummed, &byte, sizeof(byte));
        getDebugStream(state) << "Setting skb->ip_summed to CHECKSUM_UNNECESSARY: " << hexval(byte) << "\n";
    }

    m_tracer->enable(state);

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 1);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 1);
}

void SymTCP::on_tcp_v4_rcv_ret(S2EExecutionState *state, uint64_t returnSite, uint64_t returnTarget) {
    DECLARE_PLUGINSTATE(SymTCPState, state);

    getDebugStream(state) << "Leaving tcp_v4_rcv. " << (plgState->m_concretePacketIndex + plgState->m_symbolicPacketIndex - 2) << "\n";

    if (m_path_merger->inMergeRange(state)) {
        getWarningsStream(state) << "ERROR. State is still in merge ranges.\n";
        assert(false);
    }

    int sk_state = readSocketState(state);
    getDebugStream(state) << "Socket state: " << sk_state << "\n";
    plgState->sk_states.push_back(sk_state);

    // WZJ: concretize all symbolic variables?

    // terminate the state if it has reached any drop point
    if (hasReachedDropPoints(state)) {
        outputResult(state);
        s2e()->getExecutor()->terminateState(*state, "has reached a drop point.");
        // can't get here
        return;
    }

    // terminate the state when packet counter count down to -1 (symbolic packet is done)
    if (plgState->m_concretePacketIndex > m_concretePacketCounter && plgState->m_symbolicPacketIndex > m_symbolicPacketCounter) {
        outputResult(state);
        s2e()->getExecutor()->terminateState(*state, "has received enough packets.");
        // can't get here
        return;
    }   

    //m_tracer->disable(state);

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 0);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 0);
}

void SymTCP::on_tcp_v4_rcv_ret2(S2EExecutionState *state, uint64_t returnSite, uint64_t returnTarget) {
    if (m_merging_searcher->getMergeFlag(state)) {
        m_merging_searcher->clearMergeFlag(state);
        return;
    }

    DECLARE_PLUGINSTATE(SymTCPState, state);

    getDebugStream(state) << "Leaving tcp_v4_rcv. " << (plgState->m_concretePacketIndex + plgState->m_symbolicPacketIndex - 2) << "\n";

    //m_tracer->disable(state);

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 0);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 0);

    if (m_path_merger->inMergeRange(state)) {
        getWarningsStream(state) << "ERROR. State is still in merge ranges.\n";
        assert(false);
    }

    int sk_state = readSocketState(state);
    getDebugStream(state) << "Socket state: " << sk_state << "\n";
    plgState->sk_states.push_back(sk_state);

    // WZJ: concretize all symbolic variables?

    // terminate the state if it has reached any drop point
    if (hasReachedDropPoints(state)) {
        outputResult(state);

        s2e()->getExecutor()->terminateState(*state, "has reached a drop point.");
        // can't get here
        return;
    }

    // terminate the state when packet counter count down to -1 (symbolic packet is done)
    if (plgState->m_concretePacketIndex > m_concretePacketCounter && plgState->m_symbolicPacketIndex > m_symbolicPacketCounter) {
        m_merging_searcher->done(state);
    }

    // merge states
    uint64_t stateGroupId = 99;
    for (auto ss : plgState->sk_states)
        stateGroupId = stateGroupId * 100 + ss;

    m_merging_searcher->setMergeFlag(state);
    m_merging_searcher->mergeByStateGroup(stateGroupId, state);
    // this function may not return...
}

void SymTCP::on_tcp_parse_options(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    plgState->resetTCPOptCount();
}

void SymTCP::on_sk_reset_timer(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc) {
    //getDebugStream(state) << "sk_reset_timer(). callerPc = " << hexval(callerPc) << "\n";
    getDebugStream(state) << "Skip sk_reset_timer().\n";
    state->bypassFunction(0);
}

void SymTCP::on_mod_timer(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc) {
    //getDebugStream(state) << "mod_timer(). callerPc = " << hexval(callerPc) << "\n";
    if (m_memrange->isInRange(callerPc)) {
        getDebugStream(state) << "Skip mod_timer().\n";
        if (!state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), 1)) {
            getWarningsStream(state) << "ERROR: couldn't write R_EAX\n";
        }
        state->bypassFunction(0);
    }
}

void SymTCP::on_mod_timer_pinned(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc) {
    //getDebugStream(state) << "mod_timer_pinned(). callerPc = " << hexval(callerPc) << "\n";
    if (m_memrange->isInRange(callerPc)) {
        getDebugStream(state) << "Skip mod_timer_pinned().\n";
        if (!state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), 1)) {
            getWarningsStream(state) << "ERROR: couldn't write R_EAX\n";
        }
        state->bypassFunction(0);
    }
}

void SymTCP::onStateForkDecide(S2EExecutionState *state, bool *doFork) {
    uint64_t pc = state->regs()->getPc();

    if (!m_memrange->isInRange(pc)) {
        *doFork = false;
    }

    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (plgState->m_concretePacketIndex <= m_concretePacketCounter || plgState->m_symbolicPacketIndex == 1) {
        *doFork = false;
    }
}

void SymTCP::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t vaddr, uint64_t &value, uint8_t size,
                                        unsigned flags) {
    uint64_t pc = state->regs()->getPc();
    if (vaddr == m_vars->addrJiffies) {
        if (m_memrange->isInRange(pc)) {
            getDebugStream(state) << "Orig jiffies: " << value << "\n";
            DECLARE_PLUGINSTATE(SymTCPState, state);
            value = plgState->m_jiffies;
            getDebugStream(state) << "Patch jiffies: " << value << "\n";
        }
    }
}

void SymTCP::onAcceptAddr(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    std::stringstream ss, apss;
    apss << hexval(pc);
    std::string ap = apss.str();
    ss << "Reached accept point: " << ap << "\n";
    plgState->acceptPointReached(ap);
    getDebugStream(state) << ss.str();
    if (m_terminateAtAP) {
        // early terminate the state
        int sk_state = readSocketState(state);
        getDebugStream(state) << "Socket state: " << sk_state << "\n";
        outputResult(state);
    } 
}

void SymTCP::onAcceptEdge(S2EExecutionState *state, uint64_t src, uint64_t dst) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    std::stringstream ss, apss;
    apss << hexval(src) << "->" << hexval(dst);
    std::string ap = apss.str();
    ss << "Reached accept point: " << ap << "\n";
    plgState->acceptPointReached(ap);
    getDebugStream(state) << ss.str();
    if (m_terminateAtAP) {
        // early terminate the state
        int sk_state = readSocketState(state);
        getDebugStream(state) << "Socket state: " << sk_state << "\n";
        outputResult(state);
    } 
}

void SymTCP::onDropAddr(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    std::stringstream ss, dpss;
    dpss << hexval(pc);
    std::string dp = dpss.str();
    ss << "Reached drop point: " << dp << "\n";
    plgState->dropPointReached(dp);
    getDebugStream(state) << ss.str();
    if (m_terminateAtDP) {
        // early terminate the state
        int sk_state = readSocketState(state);
        getDebugStream(state) << "Socket state: " << sk_state << "\n";
        outputResult(state);
    } 
}

void SymTCP::onDropEdge(S2EExecutionState *state, uint64_t src, uint64_t dst) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    std::stringstream ss, dpss;
    dpss << hexval(src) << "->" << hexval(dst);
    std::string dp = dpss.str();
    ss << "Reached drop point: " << dp << "\n";
    plgState->dropPointReached(dp);
    getDebugStream(state) << ss.str();
    if (m_terminateAtDP) {
        // early terminate the state early
        int sk_state = readSocketState(state);
        getDebugStream(state) << "Socket state: " << sk_state << "\n";
        outputResult(state);
    } 
}

void SymTCP::onEngineShutdown() {
    getDebugStream() << "onEngineShutdown\n";
    for (auto const &pair : m_merging_searcher->getStateMergePools()) {
        uint64_t stateGroupId = pair.first;
        S2EExecutionState *state = pair.second.firstState;
        getDebugStream() << "  stateGroupId: " << stateGroupId << ". State " << state->getID() << "\n";
        outputResult(state);
    }
}

void SymTCP::on_debug(S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "on_debug(). pc = " << hexval(pc) << "\n";
}

/*******
 * VMI *
 *******/

void SymTCP::afterSockLookup(S2EExecutionState *state, uint64_t pc) {
    // get socket address
    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (!state->regs()->read(CPU_OFFSET(regs[m_vars->regSockLookup]), &plgState->m_sock_addr, sizeof(plgState->m_sock_addr), false)) {
        assert(false && "sock is symbolic.");
        return;
    }  
    getDebugStream(state) << "sock: " << hexval(plgState->m_sock_addr) << "\n";
}

void SymTCP::afterReqSockLookup(S2EExecutionState *state, uint64_t pc) {
    // get request socket address
    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &plgState->m_reqsock_addr, sizeof(plgState->m_reqsock_addr), false)) {
        assert(false && "request sock is symbolic.");
        return;
    }  
    getDebugStream(state) << "req_sock: " << hexval(plgState->m_reqsock_addr) << "\n";
}

void SymTCP::afterReqSockAllocation(S2EExecutionState *state, uint64_t pc) {
    // get request socket address
    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &plgState->m_reqsock_addr, sizeof(plgState->m_reqsock_addr), false)) {
        assert(false && "request sock is symbolic.");
        return;
    }  
    getDebugStream(state) << "req_sock: " << hexval(plgState->m_reqsock_addr) << "\n";
}

/*
void SymTCP::afterSynAckSkbAllocation(S2EExecutionState *state, uint64_t pc) {
    // get request socket address
    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &plgState->m_synack_skb_addr, sizeof(plgState->m_synack_skb_addr), false)) {
        assert(false && "synack skb is symbolic.");
        return;
    }  
    getDebugStream(state) << "synack skb: " << hexval(plgState->m_synack_skb_addr) << "\n";
}

void SymTCP::afterSynAckSeqAssignment(S2EExecutionState *state, uint64_t pc) {
    // get sequence number in SYN-ACK packet
    DECLARE_PLUGINSTATE(SymTCPState, state);
    assert(plgState->m_synack_skb_addr);
    
    int cb_offset = vars->offsetSkBuffCb;    // control buffer offset in sk_buff
    int data_offset = vars->offsetSkBuffData;   // data offset in sk_buff
    uint32_t cb_seq;
    uint32_t th_seq;

    if (!state->mem()->read(plgState->m_synack_skb_addr + cb_offset, &cb_seq, sizeof(cb_seq))) {
        getWarningsStream(state) << "ERROR: couldn't read cb->seq " << hexval(plgState->m_synack_skb_addr + cb_offset) << "\n";
        return;
    }
    getDebugStream(state) << "synack skb cb->seq: " << hexval(cb_seq) << ", address: " << hexval(plgState->m_synack_skb_addr + cb_offset) << "\n";

    if (!state->mem()->read(plgState->m_synack_skb_addr + data_offset, &plgState->m_synack_data_addr, sizeof(plgState->m_synack_data_addr))) {
        getWarningsStream(state) << "ERROR: couldn't read sk_buff->data " << hexval(plgState->m_synack_skb_addr + data_offset) << "\n";
        return;
    }
    getDebugStream(state) << "synack skb data: " << hexval(plgState->m_synack_data_addr) << ", address: " << hexval(plgState->m_synack_skb_addr + data_offset) << "\n";

    if (!state->mem()->read(plgState->m_synack_data_addr + 4, &th_seq, sizeof(th_seq))) {
        getWarningsStream(state) << "ERROR: couldn't read th->seq " << hexval(plgState->m_synack_data_addr + 4) << "\n";
        return;
    }
    getDebugStream(state) << "synack skb th->seq: " << hexval(th_seq) << ", address: " << hexval(plgState->m_synack_data_addr + 4) << "\n";
}
*/

void SymTCP::afterFullSockAllocation(S2EExecutionState *state, uint64_t pc) {
    // get full socket address
    DECLARE_PLUGINSTATE(SymTCPState, state);
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &plgState->m_fullsock_addr, sizeof(plgState->m_fullsock_addr), false)) {
        assert(false && "full socket is symbolic.");
        return;
    }  
    getDebugStream(state) << "full_sock: " << hexval(plgState->m_fullsock_addr) << "\n";
}

int SymTCP::readSocketState(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(SymTCPState, state);

    target_ulong sock_addr = 0;
    int offset = m_vars->offsetSockState;

    if (plgState->m_fullsock_addr) {
        sock_addr = plgState->m_fullsock_addr;
    }
    else if (plgState->m_reqsock_addr) {
        //sock_addr = plgState->m_reqsock_addr;
        // before v4.4, request sock doesn't have sk_state member, 
        // so we assume it is in TCP_NEW_SYN_RECV state unless we see a full socket
        return 12;
    }
    else if (plgState->m_sock_addr) {
        sock_addr = plgState->m_sock_addr;
    }

    if (!sock_addr) 
        return 0;

    unsigned char sk_state;
    if (state->mem()->symbolic(sock_addr + offset, sizeof(sk_state))) {
        getWarningsStream(state) << "ERROR: sk_state is symbolic.\n";
        return -1;
    }
    if (!state->mem()->read(sock_addr + offset, &sk_state, sizeof(sk_state))) {
        getWarningsStream(state) << "ERROR: couldn't read sk_state " << hexval(sock_addr + offset) << "\n";
        return -1;
    }
    //getDebugStream(state) << "offset: " << offset << ", sk_state: " << int(sk_state) << "\n";
    return sk_state;
}

void SymTCP::afterServerISNAssignment(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    target_ulong reqsock_addr = plgState->m_reqsock_addr;
    assert(reqsock_addr);
    
    int offset = m_vars->offsetReqSockSntIsn;
    uint32_t isn;
    //for (offset = 0; offset <= 500; offset++) {
    if (!state->mem()->read(reqsock_addr + offset, &isn, sizeof(isn))) {
        getWarningsStream(state) << "ERROR: couldn't read req->snt_isn " << hexval(reqsock_addr + offset) << "\n";
        return;
    }
    isn = ntohl(isn);
    getDebugStream(state) << "offset: " << offset << ", req->snt_isn: " << hexval(isn) << "\n";
    //}

    // use a fixed server ISN
    //isn = 0xaaaaaaaa;
    //getDebugStream(state) << "Rewrite req->snt_isn with " << hexval(isn) << "\n";
    //if (!state->mem()->write(reqsock_addr + offset, &isn, sizeof(isn))) {
    //    getWarningsStream(state) << "ERROR: couldn't write req->snt_isn " << hexval(reqsock_addr + offset) << "\n";
    //    return;
    //}

    // symbolize server ISN
    //m_base->makeSymbolic(state, reqsock_addr + offset, 4, "tcp_svr_isn");
}

int SymTCP::getPacketNum(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    return plgState->m_concretePacketIndex + plgState->m_symbolicPacketIndex - 2;
}

void SymTCP::outputResult(S2EExecutionState *state) {
    dumpAcceptAndDropPointsReached(state);
    dumpQuerySMTv2(state);
    m_tcgen->generateTestCases(state, "result", testcases::TC_LOG);
}

void SymTCP::dumpQuerySMTv2(S2EExecutionState *state) {
    klee::ExprSMTLIBPrinter printer;
    printer.setOutput(getDebugStream(state));

    // Extract symbolic objects
    klee::ArrayVec symbObjects;
    for (unsigned i = 0; i < state->symbolics.size(); ++i) {
        symbObjects.push_back(state->symbolics[i]);
    }
    printer.setArrayValuesToGet(symbObjects);

    klee::Query query(state->constraints(), klee::ConstantExpr::alloc(0, klee::Expr::Bool));
    printer.setQuery(query);

    printer.generateOutput();
}

/***********************
 * SymTCPState methods *
 ***********************/

SymTCPState::SymTCPState() {
    m_concretePacketIndex = 1;
    m_symbolicPacketIndex = 1;

    m_jiffies = 2021;

    m_opt = None;
    
    reset();
}

SymTCPState::~SymTCPState() {
}

SymTCPState *SymTCPState::clone() const {
    return new SymTCPState(*this);
}

PluginState *SymTCPState::factory(Plugin *p, S2EExecutionState *s) {
    return new SymTCPState();
}

void SymTCPState::reset() {
    m_sock_addr = 0;
    m_reqsock_addr = 0;
    m_fullsock_addr = 0;
    m_synack_skb_addr = 0;
    m_synack_data_addr = 0;

    resetTCPOptCount();
}

void SymTCPState::resetTCPOptCount() {
    m_optCount = 0;

    m_optMSSCount = 0;
    m_optWindowCount = 0;
    m_optSACKPermCount = 0;
    m_optSACKCount = 0;
    m_optTimestampCount = 0;
    m_optMD5Count = 0;
    m_optFastopenCount = 0;
    m_optExpFastopenCount = 0;
    m_optNopCount = 0;
    m_optEOLCount = 0;
    m_optOtherCount = 0;

    m_optParsingLoopBackEdgeCount = 0;
}

void SymTCPState::acceptPointReached(std::string ap) {
    m_acceptPointsReached.push_back(ap);
}

void SymTCPState::dropPointReached(std::string dp) {
    m_dropPointsReached.push_back(dp);
}

std::vector<std::string> &SymTCPState::getAcceptPointsReached() {
    return m_acceptPointsReached;
}

std::vector<std::string> &SymTCPState::getDropPointsReached() {
    return m_dropPointsReached;
}

bool SymTCPState::hasReachedDropPoints() {
    return !m_dropPointsReached.empty();
}

void SymTCP::acceptPointReached(S2EExecutionState *state, std::string ap) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    plgState->acceptPointReached(ap);
}

void SymTCP::dropPointReached(S2EExecutionState *state, std::string dp) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    plgState->dropPointReached(dp);
}

bool SymTCP::hasReachedDropPoints(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    return plgState->hasReachedDropPoints();
}

void SymTCP::dumpAcceptPointsReached(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    std::vector<std::string> aps = plgState->getAcceptPointsReached();

    std::stringstream ss;
    ss << "Accept points reached: ";
    for (auto iter = aps.cbegin(); iter != aps.cend(); ++iter) {
        ss << *iter << ' ';
    }
    getDebugStream(state) << ss.str() << "\n";
}

void SymTCP::dumpDropPointsReached(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(SymTCPState, state);
    std::vector<std::string> dps = plgState->getDropPointsReached();

    std::stringstream ss;
    ss << "Drop points reached: ";
    for (auto iter = dps.cbegin(); iter != dps.cend(); ++iter) {
        ss << *iter << ' ';
    }
    getDebugStream(state) << ss.str() << "\n";
}

} // namespace plugins
} // namespace s2e
