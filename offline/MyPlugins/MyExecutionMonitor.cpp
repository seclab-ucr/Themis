
#include <s2e/cpu.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "MyExecutionMonitor.h"


namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MyExecutionMonitor, "My Execution Monitor", "", "BaseInstructions", "MemRangeDetector");

namespace {
class MyExecutionMonitorState : public PluginState {
    // Maps a stack pointer containing a return address to the return signal
    using ReturnSignals = std::unordered_map<uint64_t, MyExecutionMonitor::ReturnSignalPtr>;
    using PidRetSignals = std::unordered_map<uint64_t /* pid */, ReturnSignals>;

    PidRetSignals m_signals;

public:
    MyExecutionMonitorState() {
    }
    virtual ~MyExecutionMonitorState() {
    }
    virtual MyExecutionMonitorState *clone() const {
        return new MyExecutionMonitorState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new MyExecutionMonitorState();
    }

    void setReturnSignal(uint64_t pid, uint64_t sp, MyExecutionMonitor::ReturnSignalPtr &signal) {
        m_signals[pid][sp] = signal;
    }

    MyExecutionMonitor::ReturnSignalPtr getReturnSignal(uint64_t pid, uint64_t sp) const {
        auto pit = m_signals.find(pid);
        if (pit == m_signals.end()) {
            return nullptr;
        }

        auto sit = pit->second.find(sp);
        if (sit == pit->second.end()) {
            return nullptr;
        }

        return sit->second;
    }

    void eraseReturnSignal(uint64_t pid, uint64_t sp) {
        auto it = m_signals.find(pid);
        if (it == m_signals.end()) {
            return;
        }
        it->second.erase(sp);
    }

    void eraseReturnSignals(uint64_t pid, uint64_t stackBottom, uint64_t stackSize) {
        auto sit = m_signals.find(pid);
        if (sit == m_signals.end()) {
            return;
        }

        llvm::DenseSet<uint64_t> toErase;
        auto end = stackBottom + stackSize;
        for (const auto &it : m_signals) {
            if (it.first >= stackBottom && it.first < end) {
                toErase.insert(it.first);
            }
        }

        for (auto sp : toErase) {
            sit->second.erase(sp);
        }
    }

    void erasePid(uint64_t pid) {
        m_signals.erase(pid);
    }
};
} // namespace

void MyExecutionMonitor::initialize() {
    m_base = s2e()->getPlugin<BaseInstructions>();

    auto config = s2e()->getConfig();
    auto cfgKey = getConfigKey();
    bool ok;

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &MyExecutionMonitor::onTranslateBlockStart));

    //s2e()->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.connect(sigc::mem_fun(*this, &MyExecutionMonitor::onBeforeSymbolicDataMemoryAccess));

    // hook functions that need to be bypassed
    std::vector<std::string> sections = config->getListKeys(cfgKey + ".bypassFunctions");
    foreach2 (it, sections.begin(), sections.end()) {
        uint64_t addr = config->getInt(cfgKey + ".bypassFunctions." + *it + ".addr", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find addr for '" << *it << "'\n";
            exit(-1);
        } 
        bool hasRetVal = config->getBool(cfgKey + ".bypassFunctions." + *it + ".hasRetVal", false);
        if (hasRetVal) {
            uint64_t retVal = config->getInt(cfgKey + ".bypassFunctions." + *it + ".retVal", 0);
            getDebugStream() << "bypassFunction: " << *it << " (" << hexval(addr) << "), hasRetVal: " << hasRetVal << ", retVal: " << retVal << "\n";
            hookFunction(addr, sigc::bind(sigc::mem_fun(*this, &MyExecutionMonitor::bypassFunction), *it, hasRetVal, retVal));
        } else {
            getDebugStream() << "bypassFunction: " << *it << " (" << hexval(addr) << "), hasRetVal: " << hasRetVal << "\n";
            hookFunction(addr, sigc::bind(sigc::mem_fun(*this, &MyExecutionMonitor::bypassFunction), *it, hasRetVal, 0));
        }
    }
}

void MyExecutionMonitor::hookAddress(uint64_t pc, AddressSignal::func_t cb) {
    m_addrCbs[pc].push_back(cb);
}

void MyExecutionMonitor::hookEdge(uint64_t src, uint64_t dst, EdgeSignal::func_t cb) {
    m_edgeCbs[src][dst].push_back(cb);
}

void MyExecutionMonitor::hookEdge(const Edge &edge, EdgeSignal::func_t cb) {
    m_edgeCbs[edge.src][edge.dst].push_back(cb);
}

void MyExecutionMonitor::hookFunction(uint64_t pc, CallSignal::func_t callCb, ReturnSignal::func_t retCb) {
    m_funcCbs[pc].push_back(std::make_pair(callCb, retCb));
}

void MyExecutionMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, 
                                               TranslationBlock *tb, uint64_t pc) {
    /* Disconnect any stale handlers */
    m_ins_start_connection.disconnect();
    m_ins_end_connection.disconnect();
    m_block_end_connection.disconnect();

    //getDebugStream(state) << "onTranslateBlockStart. pc = " << hexval(pc) << "\n";

    m_ins_start_connection = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &MyExecutionMonitor::onTranslateInstructionStart));

    m_ins_end_connection = s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
            sigc::mem_fun(*this, &MyExecutionMonitor::onTranslateInstructionEnd));

    m_block_end_connection = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &MyExecutionMonitor::onTranslateBlockEnd));
}

void MyExecutionMonitor::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, 
                                                     TranslationBlock *tb, uint64_t pc) {
    auto it = m_addrCbs.find(pc);
    if (it != m_addrCbs.end()) {
        for (auto const &cb : it->second) {
            signal->connect(cb);
        }
    }
}

void MyExecutionMonitor::onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, 
                                                   TranslationBlock *tb, uint64_t pc) {
    if (m_edgeCbs.find(pc) != m_edgeCbs.end()) {
        signal->connect(sigc::mem_fun(*this, &MyExecutionMonitor::onEdgeInternal));
    }
}

void MyExecutionMonitor::onEdgeInternal(S2EExecutionState *state, uint64_t sourcePc) {
    uint64_t destPc = state->regs()->getPc();

    auto it = m_edgeCbs.find(sourcePc);
    if (it != m_edgeCbs.end()) {
        auto it2 = it->second.find(destPc);
        if (it2 != it->second.end()) {
            for (auto const &cb : it2->second) {
                cb->operator()(state, sourcePc, destPc);
            }
        }
    }
}

void MyExecutionMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, bool isStatic, uint64_t staticTarget) {
    //getDebugStream(state) << "onTranslateBlockEnd. pc = " << hexval(pc) << ", isStatic = " << isStatic << ", staticTarget = " << hexval(staticTarget) << "\n";

    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        if (staticTarget == 0 || m_funcCbs.find(staticTarget) != m_funcCbs.end()) 
            signal->connect(sigc::mem_fun(*this, &MyExecutionMonitor::onFunctionCall));
    } else if (tb->se_tb_type == TB_RET) {
        signal->connect(sigc::mem_fun(*this, &MyExecutionMonitor::onFunctionReturn));
    } else if (tb->se_tb_type == TB_JMP || tb->se_tb_type == TB_JMP_IND) {
        // sometimes function call uses JMP instruction instead of CALL instruction
        if (m_funcCbs.find(staticTarget) != m_funcCbs.end()) 
            signal->connect(sigc::mem_fun(*this, &MyExecutionMonitor::onFunctionCall));
    }
}

void MyExecutionMonitor::onFunctionCall(S2EExecutionState *state, uint64_t callerPc) {

    uint64_t calleePc = state->regs()->getPc();
    auto it = m_funcCbs.find(calleePc);
    if (it != m_funcCbs.end()) {
        for (auto const &pair : it->second) {
            auto callCb = pair.first;
            auto retCb = pair.second;
            if (retCb) {
                auto onRetSig = new MyExecutionMonitor::ReturnSignal();
                auto onRetSigPtr = std::shared_ptr<MyExecutionMonitor::ReturnSignal>(onRetSig);
                onRetSig->connect(retCb);
                if (!onRetSigPtr->empty()) {
                    DECLARE_PLUGINSTATE(MyExecutionMonitorState, state);
                    // only handle kernel function calls 
                    auto pid = 0; //m_monitor->getPid(state);
                    plgState->setReturnSignal(pid, state->regs()->getSp(), onRetSigPtr);
                }
            }
            callCb->operator()(state, callerPc, calleePc);
        }
    }
}

void MyExecutionMonitor::onFunctionReturn(S2EExecutionState *state, uint64_t returnPc) {
    DECLARE_PLUGINSTATE(MyExecutionMonitorState, state);
    auto sp = state->regs()->getSp() - state->getPointerSize();
    // only handle kernel function calls
    auto pid = 0; //m_monitor->getPid(state);
    auto signal = plgState->getReturnSignal(pid, sp);
    if (!signal) {
        return;
    }
    uint64_t returnDestPc = state->regs()->getPc();
    signal->emit(state, returnPc, returnDestPc);
    plgState->eraseReturnSignal(pid, sp);
}

void MyExecutionMonitor::onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                                          klee::ref<klee::Expr> value, bool isWrite) {
    unsigned numBytes = klee::Expr::getMinBytesForWidth(value->getWidth());
    //klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(address));
    //uint64_t concreteAddress = ce->getZExtValue();
    //g_s2e->getDebugStream(state) << "onBeforeSymbolicDataMemoryAccess(). address: " << hex(concreteAddress) << ", size: " << numBytes << "\n";
    g_s2e->getDebugStream(state) << "onBeforeSymbolicDataMemoryAccess(). address: " << address << ", size: " << numBytes << "\n";
    g_s2e->getDebugStream(state) << "onBeforeSymbolicDataMemoryAccess(). value: " << value << "\n";
}

void MyExecutionMonitor::onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                                         klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                                         unsigned flags) {
    unsigned numBytes = klee::Expr::getMinBytesForWidth(value->getWidth());
    //klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(address));
    //uint64_t concreteAddress = ce->getZExtValue();
    //klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(hostAddress));
    //uint64_t concreteHostAddress = ce->getZExtValue();
    //g_s2e->getDebugStream(state) << "onAfterSymbolicDataMemoryAccess(). address: " << hex(concreteAddress) << ", hostAddress = " << hexval(concreteHostAddress) << ", size: " << numBytes << "\n";
    g_s2e->getDebugStream(state) << "onAfterSymbolicDataMemoryAccess(). address: " << address << ", hostAddress: " << hostAddress << ", size: " << numBytes << "\n";
    g_s2e->getDebugStream(state) << "onAfterSymbolicDataMemoryAccess(). value: " << value << "\n";
}

void MyExecutionMonitor::bypassFunction(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc, std::string funcName, bool hasRetVal, uint64_t retVal) {
    getDebugStream(state) << "Function " << funcName << " bypassed.\n";
    if (hasRetVal) {
        if (!state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retVal)) {
            getWarningsStream(state) << "ERROR: couldn't write R_EAX\n";
            exit(-1);
        }
    }
    state->bypassFunction(0);
}

} // namespace plugins
} // namespace s2e
