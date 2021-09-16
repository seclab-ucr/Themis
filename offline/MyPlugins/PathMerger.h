
#ifndef S2E_PLUGINS_PATHMERGER_H
#define S2E_PLUGINS_PATHMERGER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/Searchers/MergingSearcher.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseSet.h>

#include <klee/Searcher.h>

namespace s2e {
namespace plugins {

class PathMerger : public Plugin {
    S2E_PLUGIN

public:
    PathMerger(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    bool inMergeRange(S2EExecutionState *state);

private:
    MergingSearcher *m_searcher;
    ModuleExecutionDetector *m_detector;

    bool m_enableNestedMergeRanges;

    // a mapping from start addresses to end addresses
    std::unordered_map<uint64_t, uint64_t> m_mergeRanges;
    std::unordered_set<uint64_t> m_mergeStartPoints;
    std::unordered_set<uint64_t> m_mergeEndPoints;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
    void onMergePoint(S2EExecutionState *state, uint64_t pc);
};

class PathMergerState : public PluginState {
public:
    PathMergerState();
    virtual ~PathMergerState();
    virtual PathMergerState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    bool isMergeStarted() {
        return m_mergeStarted;
    }
    
    void setMergeStarted(bool b) {
        m_mergeStarted = b;
    }

    bool inMergeRange() {
        return m_mergeStarted;
    }

    uint64_t getCurrMergeStartPoint() {
        return m_currMergeStartPoint;
    }

    uint64_t getCurrMergeEndPoint() {
        return m_currMergeEndPoint;
    }

    void setCurrMergeStartPoint(uint64_t addr) {
        m_lastMergeStartPoint = m_currMergeStartPoint;
        m_currMergeStartPoint = addr;
    }

    void setCurrMergeEndPoint(uint64_t addr) {
        m_lastMergeEndPoint = m_currMergeEndPoint;
        m_currMergeEndPoint = addr;
    }

    uint64_t getLastMergeStartPoint() {
        return m_lastMergeStartPoint;
    }

    uint64_t getLastMergeEndPoint() {
        return m_lastMergeEndPoint;
    }
 
    void pushMergeRange() {
        m_mergeStartPointStack.push_back(m_currMergeStartPoint);
        m_mergeEndPointStack.push_back(m_currMergeEndPoint);
    }

    bool popMergeRange() {
        if (m_mergeStartPointStack.size() == 0 && m_mergeEndPointStack.size() == 0)
            return false;

        setCurrMergeStartPoint(m_mergeStartPointStack.back());
        m_mergeStartPointStack.pop_back();
        setCurrMergeEndPoint(m_mergeEndPointStack.back());
        m_mergeEndPointStack.pop_back();
        return true;
    }

private:
    bool m_mergeStarted;
    uint64_t m_currMergeStartPoint;
    uint64_t m_currMergeEndPoint;
    uint64_t m_lastMergeStartPoint;
    uint64_t m_lastMergeEndPoint;

    // to handle nested merge ranges
    std::vector<uint64_t> m_mergeStartPointStack;
    std::vector<uint64_t> m_mergeEndPointStack;
};

} // namespace plugins
} // namespace s2e

#endif
