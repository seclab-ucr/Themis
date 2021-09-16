
#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>

#include "PathMerger.h"

namespace s2e {
namespace plugins {

using namespace llvm;

S2E_DEFINE_PLUGIN(PathMerger, "This plugin decides when to start and end merge, and invokes ", "PathMerger", "MergingSearcher");

void PathMerger::initialize() {
    m_searcher = s2e()->getPlugin<MergingSearcher>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    ConfigFile *config = s2e()->getConfig();
    std::string cfgKey = getConfigKey();
    bool ok;

    m_enableNestedMergeRanges = config->getBool(cfgKey + ".enableNestedMergeRanges", false);

    // load merge start/end points
    std::vector<std::string> merge_ranges = config->getListKeys(cfgKey + ".mergeRanges");
    g_s2e->getDebugStream() << "mergeRanges:\n";
    for (std::string name : merge_ranges) {
        uint64_t startAddr = config->getInt(cfgKey + ".mergeRanges." + name + ".startAddr", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find startAddr in section '" << name << "'\n";
            exit(-1);
        } 
        uint64_t endAddr = config->getInt(cfgKey + ".mergeRanges." + name + ".endAddr", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find endAddr in section '" << name << "'\n";
            exit(-1);
        }
        m_mergeRanges[startAddr] = endAddr;
        m_mergeStartPoints.insert(startAddr);
        m_mergeEndPoints.insert(endAddr);
        g_s2e->getDebugStream() << "  " << name << ": " << hexval(startAddr) << ", " << hexval(endAddr) << "\n";
    }

    // for test purpose
    //m_detector->onModuleLoad.connect(sigc::mem_fun(*this, &PathMerger::onModuleLoad));

    //s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &PathMerger::onTranslateBlockStart));
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &PathMerger::onTranslateInstructionStart));
}

void PathMerger::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    // for test purpose
    if (module.Name == "test") {
        uint64_t mergeStartAddr, mergeEndAddr;
        module.ToRuntime(0x87c, mergeStartAddr);
        module.ToRuntime(0x889, mergeEndAddr);
        m_mergeRanges[mergeStartAddr] = mergeEndAddr;
        g_s2e->getDebugStream() << "Added merge point for test: " << hexval(mergeStartAddr) << ", " << hexval(mergeEndAddr) << "\n";
    }
}

//void PathMerger::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
void PathMerger::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
    if (m_mergeStartPoints.find(pc) != m_mergeStartPoints.end()) {
        // this is a merge start point
        signal->connect(sigc::mem_fun(*this, &PathMerger::onMergePoint));
    } else if (m_mergeEndPoints.find(pc) != m_mergeEndPoints.end()) {
        // this is a merge end point
        signal->connect(sigc::mem_fun(*this, &PathMerger::onMergePoint));
    }
}

void PathMerger::onMergePoint(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(PathMergerState, state);
    getDebugStream(state) << "onMergePoint: " << hexval(pc) << "\n";

    if (m_mergeStartPoints.find(pc) != m_mergeStartPoints.end()) {
        // this is a merge start point
        if (plgState->isMergeStarted()) {
            if (pc == plgState->getCurrMergeStartPoint()) {
                // Sometimes the merge start point is visited multiple times consecutively
                // (maybe due to interrupts)
                return;
            } else {
                if (m_enableNestedMergeRanges) {
                    getDebugStream(state) << "Start merging. Nested.\n";
                    plgState->pushMergeRange();

                    plgState->setCurrMergeStartPoint(pc);
                    plgState->setCurrMergeEndPoint(m_mergeRanges[pc]);

                    m_searcher->mergeStart(state);
                } else {
                    getDebugStream(state) << "Suppressed nested merge range.\n";
                    return;
                }
            }
        } else {
            // start merging
            getDebugStream(state) << "Start merging.\n";

            plgState->setCurrMergeStartPoint(pc);
            plgState->setCurrMergeEndPoint(m_mergeRanges[pc]);

            plgState->setMergeStarted(true);

            m_searcher->mergeStart(state);
        }
    } else if (m_mergeEndPoints.find(pc) != m_mergeEndPoints.end()) {
        // this is a merge end point
        if (pc == plgState->getCurrMergeEndPoint()) {
            // end merging
            if (plgState->popMergeRange()) {
                // go back to the previous merge range
                getDebugStream(state) << "End merging. Nested.\n";
            } else {
                getDebugStream(state) << "End merging.\n";
                // all merge ranges have finished
                plgState->setCurrMergeStartPoint(0);
                plgState->setCurrMergeEndPoint(0);
                plgState->setMergeStarted(false);
            }
                
            // because the first state in the merge pool is yielded and its pc is set to dummyMain,
            // we need to manually set the pc all other states to dummyMain as well
            g_s2e->getExecutor()->cleanupTranslationBlock(state);

            // mergeEnd may not return, so we shouldn't do anything after this function call...
            m_searcher->mergeEnd(state, false, false);

        } else {
            // After merging, it will revisit the same instruction, which falls into this case.
            return;
        }
    }
}

bool PathMerger::inMergeRange(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(PathMergerState, state);
    return plgState->inMergeRange();
}

PathMergerState::PathMergerState() {
    m_mergeStarted = false;
    m_currMergeStartPoint = 0;
    m_currMergeEndPoint = 0;
}

PathMergerState::~PathMergerState() {
}

PathMergerState *PathMergerState::clone() const {
    return new PathMergerState(*this);
}

PluginState *PathMergerState::factory(Plugin *p, S2EExecutionState *s) {
    return new PathMergerState();
}

} // namespace plugins
} // namespace s2e
