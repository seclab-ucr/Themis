///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <s2e/cpu.h>

//#include <cxxabi.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>

//#include <klee/UserSearcher.h>

//#include <algorithm>
//#include <random>

#include "DFSSearcher.h"


namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(DFSSearcher, "DFS searcher", "", "MultiSearcher");

void DFSSearcher::initialize() {
    m_searchers = s2e()->getPlugin<MultiSearcher>();

    //ConfigFile *cfg = s2e()->getConfig();

    m_searchers->registerSearcher("DFSSearcher", this);

    m_currentState = nullptr;
}

void DFSSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                         const klee::StateSet &removedStates) {
    for (klee::StateSet::const_iterator it = addedStates.begin(), ie = addedStates.end(); it != ie; ++it) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states.push_back(es);
    }

    for (klee::StateSet::const_iterator it = removedStates.begin(), ie = removedStates.end(); it != ie; it++) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        if (es == m_currentState) {
            m_currentState = nullptr;
        }
        if (es == m_states.back()) {
            m_states.pop_back();
        } else {
            bool ok = false;
            for (std::vector<S2EExecutionState *>::iterator it2 = m_states.begin(), ie2 = m_states.end(); it2 != ie2; ++it2) {
                if (es == *it2) {
                    m_states.erase(it2);
                    ok = true;
                    break;
                }
            }
            assert(ok && "invalid state removed");
        }
    }
}

klee::ExecutionState &DFSSearcher::selectState() {
    if (m_currentState == nullptr) {
        m_currentState = m_states[0];
    }
    return *m_currentState;
}

} // namespace plugins
} // namespace s2e
