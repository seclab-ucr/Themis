
#ifndef S2E_PLUGINS_MYFORKLIMITER_H
#define S2E_PLUGINS_MYFORKLIMITER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>

#include <klee/Internal/ADT/ImmutableSet.h>


namespace s2e {
namespace plugins {

class MyForkLimiter : public Plugin {
    S2E_PLUGIN
public:
    MyForkLimiter(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    void addForkLimit(uint64_t pc, int limit);

    void reset(S2EExecutionState *state);

private:
    std::unordered_map<uint64_t, int> m_forkLimits;

    void onStateForkDecide(S2EExecutionState *state, bool *doFork);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
};

class MyForkLimiterState : public PluginState {
public:
    std::unordered_map<uint64_t, int> m_forkCounts;

    MyForkLimiterState();
    virtual ~MyForkLimiterState();

    virtual MyForkLimiterState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void reset();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MYTRACER_H
