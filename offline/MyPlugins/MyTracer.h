
#ifndef S2E_PLUGINS_MYTRACER_H
#define S2E_PLUGINS_MYTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/MyPlugins/MemRangeDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>

#include <klee/Internal/ADT/ImmutableSet.h>


namespace s2e {
namespace plugins {

class MyTracer : public Plugin {
    S2E_PLUGIN
public:
    MyTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    void enable(S2EExecutionState *state);
    void disable(S2EExecutionState *state);

private:
    MemRangeDetector *m_memrange;
    ModuleExecutionDetector *m_detector;

    bool m_traceBlockTranslation;
    bool m_traceBlockExecution;
    bool m_traceInstructionTranslation;
    bool m_traceInstructionExecution;

    bool m_alwaysEnabled;
    bool m_traceInRange;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);
    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onExecuteInstructionStart(S2EExecutionState *state, uint64_t pc);
};

class MyTracerState : public PluginState {
public:
    MyTracerState();
    virtual ~MyTracerState();

    virtual MyTracerState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void enable();
    void disable();
    bool isEnabled();

private:
    bool m_enabled;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MYTRACER_H
