
#ifndef S2E_PLUGINS_SYMTCP_H
#define S2E_PLUGINS_SYMTCP_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/Plugins/MyPlugins/MemRangeDetector.h>
#include <s2e/Plugins/MyPlugins/MyExecutionMonitor.h>
//#include <s2e/Plugins/MyPlugins/MyForkLimiter.h>
#include <s2e/Plugins/MyPlugins/MyTracer.h>
#include <s2e/Plugins/MyPlugins/MyVariables.h>
#include <s2e/Plugins/MyPlugins/PathMerger.h>
#include <s2e/Plugins/Searchers/MergingSearcher.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>

#include <klee/Internal/ADT/ImmutableSet.h>


enum TCPOption {
    None,
    EOL,
    Nop,
    MSS,
    Window,
    SACKPerm,
    SACK,
    Timestamp,
    MD5,
    Fastopen,
    ExpFastopen,
    Other
};


namespace s2e {
namespace plugins {


class SymTCP : public Plugin {
    S2E_PLUGIN
public:
    SymTCP(S2E *s2e) : Plugin(s2e) {
        m_terminateAtAP = false;
        m_terminateAtDP = true;
    }

    void initialize();

private:
    BaseInstructions *m_base;
    MemRangeDetector *m_memrange;
    MyExecutionMonitor *m_monitor;
    MyVariables *m_vars;
    testcases::TestCaseGenerator *m_tcgen;
    MyTracer *m_tracer;
    //MyForkLimiter *m_forklimiter;
    PathMerger *m_path_merger;
    MergingSearcher *m_merging_searcher;

    bool m_terminateAtAP;
    bool m_terminateAtDP;

    int m_concretePacketCounter;
    int m_symbolicPacketCounter;
    int m_symbolicTCPOptionsLength;
    int m_symbolicTCPOptionsStart;
    int m_symbolicTCPOptionsEnd;

    int m_optWindowCountLimit;
    int m_optMSSCountLimit;
    int m_optTimestampCountLimit;
    int m_optSACKPermCountLimit;
    int m_optSACKCountLimit;
    int m_optMD5CountLimit;
    int m_optFastopenCountLimit;
    int m_optExpFastopenCountLimit;
    int m_optNopCountLimit;
    int m_optEOLCountLimit;
    int m_optOtherCountLimit;
    int m_optParsingLoopBackEdgeCountLimit;

    bool m_genBadCsumCases;

    void readConfig();
    void hookFunctions();
    void hookAcceptAndDropPoints();
    void hookTCPOptionsParsing();

    void onChecksumValidation(S2EExecutionState *state, uint64_t pc);

    void on_tcp_v4_rcv(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc);
    void on_tcp_v4_rcv_ret(S2EExecutionState *state, uint64_t returnSite, uint64_t returnTarget);
    void on_tcp_v4_rcv_ret2(S2EExecutionState *state, uint64_t returnSite, uint64_t returnTarget);

    void on_tcp_parse_options(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc);
    void on_sk_reset_timer(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc);
    void on_mod_timer(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc);
    void on_mod_timer_pinned(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc);

    void onStateForkDecide(S2EExecutionState *state, bool *doFork);

    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t vaddr, uint64_t &value, uint8_t size,
                                    unsigned flags);

    void onEngineShutdown();

    // VMI
    void afterSockLookup(S2EExecutionState *state, uint64_t pc);
    void afterReqSockLookup(S2EExecutionState *state, uint64_t pc);
    void afterReqSockAllocation(S2EExecutionState *state, uint64_t pc);
    void afterSynAckSkbAllocation(S2EExecutionState *state, uint64_t pc);
    void afterSynAckSeqAssignment(S2EExecutionState *state, uint64_t pc);
    void afterFullSockAllocation(S2EExecutionState *state, uint64_t pc);
    void afterServerISNAssignment(S2EExecutionState *state, uint64_t pc);

    // debug
    void tcp_check_req_seq_in_window(S2EExecutionState *state, uint64_t pc);
    void on_debug(S2EExecutionState *state, uint64_t pc);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

    int readSocketState(S2EExecutionState *state);

    void onSetTCPStateCloseWait(S2EExecutionState *state, uint64_t pc);

    // accept/drop points
    void onAcceptAddr(S2EExecutionState *state, uint64_t pc);
    void onAcceptEdge(S2EExecutionState *state, uint64_t src, uint64_t dst);
    void onDropAddr(S2EExecutionState *state, uint64_t pc);
    void onDropEdge(S2EExecutionState *state, uint64_t src, uint64_t dst);

    void acceptPointReached(S2EExecutionState *state, std::string ap);
    void dropPointReached(S2EExecutionState *state, std::string dp);

    bool hasReachedDropPoints(S2EExecutionState *state);

    void dumpAcceptPointsReached(S2EExecutionState *state);
    void dumpDropPointsReached(S2EExecutionState *state);
    void dumpAcceptAndDropPointsReached(S2EExecutionState *state) {
        dumpAcceptPointsReached(state);
        dumpDropPointsReached(state);
    }

    // bound TCP options
    void onTCPOptionParsingLoopBackEdge(S2EExecutionState *state, uint64_t src, uint64_t dst);
    void onTCPOption(S2EExecutionState *state, uint64_t src, uint64_t dst, TCPOption option);

    int getPacketNum(S2EExecutionState *state);
    void dumpQuerySMTv2(S2EExecutionState *state);

    void outputResult(S2EExecutionState *state);
};

class SymTCPState : public PluginState {
public:
    SymTCPState();
    virtual ~SymTCPState();

    virtual SymTCPState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    unsigned m_concretePacketIndex; 
    unsigned m_symbolicPacketIndex; 

    std::vector<int> sk_states;

    target_ulong m_sock_addr;
    target_ulong m_reqsock_addr;
    target_ulong m_synack_skb_addr;
    target_ulong m_synack_data_addr;
    target_ulong m_fullsock_addr;

    int m_optCount;
    int m_optWindowCount;
    int m_optMSSCount;
    int m_optTimestampCount;
    int m_optSACKPermCount;
    int m_optSACKCount;
    int m_optMD5Count;
    int m_optFastopenCount;
    int m_optExpFastopenCount;
    int m_optNopCount;
    int m_optEOLCount;
    int m_optOtherCount;
    int m_optParsingLoopBackEdgeCount;

    TCPOption m_opt;

    uint64_t m_jiffies;

    void reset();
    void resetTCPOptCount();

    void acceptPointReached(std::string ap);
    void dropPointReached(std::string dp);

    std::vector<std::string> &getAcceptPointsReached();
    std::vector<std::string> &getDropPointsReached();

    bool hasReachedDropPoints();

private:
    std::vector<std::string> m_acceptPointsReached;
    std::vector<std::string> m_dropPointsReached;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SYMTCP_H
