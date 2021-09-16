
#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "MyTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MyTracer, "My Tracer", "MyTracer", "MemRangeDetector", "ModuleExecutionDetector");

void MyTracer::initialize() {
    m_memrange = s2e()->getPlugin<MemRangeDetector>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    auto config = s2e()->getConfig();
    auto cfgKey = getConfigKey();

    m_traceBlockTranslation = config->getBool(cfgKey + ".traceBlockTranslation", false);
    m_traceBlockExecution = config->getBool(cfgKey + ".traceBlockExecution", false);
    m_traceInstructionTranslation = config->getBool(cfgKey + ".traceInstructionTranslation", false);
    m_traceInstructionExecution = config->getBool(cfgKey + ".traceInstructionExecution", false);
    m_alwaysEnabled = config->getBool(cfgKey + ".alwaysEnabled", false);
    m_traceInRange = config->getBool(cfgKey + ".traceInRange", true);

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &MyTracer::onTranslateBlockStart));
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &MyTracer::onTranslateInstructionStart));

    // dynamically add module address range to mem ranges
    m_detector->onModuleLoad.connect(sigc::mem_fun(*this, &MyTracer::onModuleLoad));
}

void MyTracer::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    for (auto &section : module.Sections) {
        m_memrange->addRange(section.runtimeLoadBase, section.runtimeLoadBase + section.size, false);
    }
}

void MyTracer::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
    if (m_traceInRange && !m_memrange->isInRange(pc)) {
        return;
    }

    if (m_traceBlockTranslation) {
        DECLARE_PLUGINSTATE(MyTracerState, state);
        if (m_alwaysEnabled || plgState->isEnabled()) {
            getDebugStream(state) << "onTranslateBlockStart. pc = " << hexval(pc) << "\n";
        }
    }

    if (m_traceBlockExecution) {
        signal->connect(sigc::mem_fun(*this, &MyTracer::onExecuteBlockStart));
    }
}

void MyTracer::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
    if (m_traceInRange && !m_memrange->isInRange(pc)) {
        return;
    }

    if (m_traceInstructionTranslation) {
        DECLARE_PLUGINSTATE(MyTracerState, state);
        if (m_alwaysEnabled || plgState->isEnabled()) {
            getDebugStream(state) << "onTranslateInstructionStart. pc = " << hexval(pc) << "\n";
        }
    }

    if (m_traceInstructionExecution) {
        signal->connect(sigc::mem_fun(*this, &MyTracer::onExecuteInstructionStart));
    }
}

void MyTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(MyTracerState, state);
    if (m_alwaysEnabled || plgState->isEnabled()) {
        getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << "\n";
    }
}

void MyTracer::onExecuteInstructionStart(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(MyTracerState, state);
    if (m_alwaysEnabled || plgState->isEnabled()) {
        getDebugStream(state) << "onExecuteInstructionStart. pc = " << hexval(pc) << "\n";
    }
}

void MyTracer::enable(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MyTracerState, state);
    plgState->enable();
}

void MyTracer::disable(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MyTracerState, state);
    plgState->disable();
}

/////////////////////////////////////////////////////////

MyTracerState::MyTracerState() {
    m_enabled = false;
}

MyTracerState::~MyTracerState() {
}

MyTracerState *MyTracerState::clone() const {
    return new MyTracerState(*this);
}

PluginState *MyTracerState::factory(Plugin *p, S2EExecutionState *s) {
    return new MyTracerState();
}

void MyTracerState::enable() {
    m_enabled = true;
}

void MyTracerState::disable() {
    m_enabled = false;
}

bool MyTracerState::isEnabled() {
    return m_enabled;
}

} // namespace plugins
} // namespace s2e
