
#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "MyForkLimiter.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MyForkLimiter, "My Fork Limiter", "");

void MyForkLimiter::initialize() {
    auto config = s2e()->getConfig();
    auto cfgKey = getConfigKey();

    // load pre-configured fork points
    std::vector<std::string> sections = config->getListKeys(cfgKey);
    foreach2 (it, sections.begin(), sections.end()) {
        bool ok;
        uint64_t pc = config->getInt(cfgKey + "." + *it + ".pc", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find pc in section '" << *it << "'\n";
            exit(-1);
        } 
        uint64_t limit = config->getInt(cfgKey + "." + *it + ".limit", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find limit in section '" << *it << "'\n";
            exit(-1);
        } 
        addForkLimit(pc, limit);
    }

    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &MyForkLimiter::onStateForkDecide));
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &MyForkLimiter::onFork));
}

void MyForkLimiter::addForkLimit(uint64_t pc, int limit) {
    g_s2e->getDebugStream() << "Fork limit on pc " << hexval(pc) << ": " << limit << "\n";
    m_forkLimits[pc] = limit;
}

void MyForkLimiter::onStateForkDecide(S2EExecutionState *state, bool *doFork) {
    DECLARE_PLUGINSTATE(MyForkLimiterState, state);

    uint64_t pc = state->regs()->getPc();
    getDebugStream(state) << "onStateForkDecide pc = " << hexval(pc) << "\n";
    auto iter = m_forkLimits.find(pc);
    if (iter != m_forkLimits.end()) {
        if (plgState->m_forkCounts[pc] >= m_forkLimits[pc]) {
            *doFork = false;
        }
    }
}

void MyForkLimiter::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                           const std::vector<klee::ref<klee::Expr>> &newConditions) {
    DECLARE_PLUGINSTATE(MyForkLimiterState, state);

    uint64_t pc = state->regs()->getPc();
    getDebugStream(state) << "onFork pc = " << hexval(pc) << "\n";
    if (m_forkLimits.find(pc) != m_forkLimits.end())
        plgState->m_forkCounts[pc]++;
}

void MyForkLimiter::reset(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MyForkLimiterState, state);
    plgState->reset();
}

/////////////////////////////////////////////////////////

MyForkLimiterState::MyForkLimiterState() {
}

MyForkLimiterState::~MyForkLimiterState() {
}

void MyForkLimiterState::reset() {
    m_forkCounts.clear();
}

MyForkLimiterState *MyForkLimiterState::clone() const {
    return new MyForkLimiterState(*this);
}

PluginState *MyForkLimiterState::factory(Plugin *p, S2EExecutionState *s) {
    return new MyForkLimiterState();
}

} // namespace plugins
} // namespace s2e
