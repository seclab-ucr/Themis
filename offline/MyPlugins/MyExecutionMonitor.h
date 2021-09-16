
#ifndef S2E_PLUGINS_MYEXECUTIONMONITOR_H
#define S2E_PLUGINS_MYEXECUTIONMONITOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/MyPlugins/Edge.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>

#include <klee/Internal/ADT/ImmutableSet.h>


namespace s2e {
namespace plugins {

class MyExecutionMonitor : public Plugin {
    S2E_PLUGIN
public:
    MyExecutionMonitor(S2E *s2e) : Plugin(s2e) {
    }

    typedef sigc::signal<void, S2EExecutionState *,
                         uint64_t /* PC */>
        AddressSignal;

    typedef sigc::signal<void, S2EExecutionState *,
                         uint64_t /* source PC */,
                         uint64_t /* dest PC */>
        EdgeSignal;

    typedef sigc::signal<void, S2EExecutionState *, 
                         uint64_t /* caller PC */,
                         uint64_t /* callee PC */>
        CallSignal;

    typedef sigc::signal<void, S2EExecutionState * /* state after return is completed */,
                         uint64_t /* return site */,
                         uint64_t /* return target */>
        ReturnSignal;

    typedef std::shared_ptr<ReturnSignal> ReturnSignalPtr;

    AddressSignal onAddress;
    EdgeSignal onEdge;
    CallSignal onCall;

    void initialize();

    void hookAddress(uint64_t pc, AddressSignal::func_t cb);
    void hookEdge(uint64_t src, uint64_t dst, EdgeSignal::func_t cb);
    void hookEdge(const Edge &edge, EdgeSignal::func_t cb);
    void hookFunction(uint64_t pc, CallSignal::func_t callCb, ReturnSignal::func_t retCb=nullptr);

private:
    BaseInstructions *m_base;

    sigc::connection m_ins_start_connection;
    sigc::connection m_ins_end_connection;
    sigc::connection m_block_end_connection;

    std::unordered_map<uint64_t, std::vector<AddressSignal::func_t>> m_addrCbs;
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::vector<EdgeSignal::func_t>>> m_edgeCbs;
    std::unordered_map<uint64_t, std::vector<std::pair<CallSignal::func_t, ReturnSignal::func_t>>> m_funcCbs;

    std::unordered_map<uint64_t, std::string> bypassFunctions;

    void onTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, 
                             uint64_t endPc, bool staticTarget, uint64_t targetPc);
    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
    void onEdgeInternal(S2EExecutionState *state, uint64_t sourcePc);
    void onFunctionCall(S2EExecutionState *state, uint64_t callerPc);
    void onFunctionReturn(S2EExecutionState *state, uint64_t returnPc);

    void onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> addr,
                                          klee::ref<klee::Expr> value, bool isWrite);
    void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                         klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                         unsigned flags);

    void bypassFunction(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc, std::string funcName, bool hasRetVal, uint64_t retVal);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MYEXECUTIONMONITOR_H
