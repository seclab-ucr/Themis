///
/// Copyright (C) 2014, Cyberhaven
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

#ifndef S2E_PLUGINS_MyLuaFunctionInstrumentation_H
#define S2E_PLUGINS_MyLuaFunctionInstrumentation_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/MyPlugins/MyExecutionMonitor.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class FunctionMonitor;
class FunctionMonitorState;
class KeyValueStore;
class ModuleExecutionDetector;
class OSMonitor;
class ModuleMap;
class ProcessExecutionDetector;

class MyLuaFunctionInstrumentation : public Plugin {
    S2E_PLUGIN

public:
    MyLuaFunctionInstrumentation(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    struct Instrumentation {
        enum CallingConvention { STDCALL, CDECL, MAX_CONV };

        const std::string moduleName;
        const uint64_t pc;
        const unsigned paramCount;
        const std::string instrumentationName;
        const CallingConvention convention;
        const bool fork;

        Instrumentation(const std::string &moduleName, uint64_t pc_, unsigned pCount, const std::string &name,
                        CallingConvention cc, bool fork_)
            : moduleName(moduleName), pc(pc_), paramCount(pCount), instrumentationName(name), convention(cc),
              fork(fork_) {
        }

        bool operator==(const Instrumentation &a1) const {
            return moduleName == a1.moduleName && pc == a1.pc && paramCount == a1.paramCount &&
                   instrumentationName == a1.instrumentationName && convention == a1.convention;
        }
    };

    using InstrumentationPtr = std::shared_ptr<Instrumentation>;

    typedef std::vector<InstrumentationPtr> Instrumentations;
    Instrumentations m_instrumentations;

    MyExecutionMonitor *m_monitor;
    KeyValueStore *m_kvs;

    sigc::connection m_block_end_connection;

    bool registerInstrumentation(const Instrumentation &instrumentation);
    void invokeInstrumentation(S2EExecutionState *state, const Instrumentation &entry, bool isCall);
    void forkInstrumentation(S2EExecutionState *state, const Instrumentation &entry);

    void onCall(S2EExecutionState *state, uint64_t callerPc, uint64_t calleePc, Instrumentation instrumentation);

    void onRet(S2EExecutionState *state, uint64_t returnSite, uint64_t returnTarget, Instrumentation instrumentation);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MyLuaFunctionInstrumentation_H
