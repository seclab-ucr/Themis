
#ifndef S2E_PLUGINS_MEMRANGEDETECTOR_H
#define S2E_PLUGINS_MEMRANGEDETECTOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>

#include <klee/Internal/ADT/ImmutableSet.h>

#include <vector>


namespace s2e {
namespace plugins {

class MemRangeDetector : public Plugin {
    S2E_PLUGIN
public:
    MemRangeDetector(S2E *s2e) : Plugin(s2e) {
    }
    
    struct MemRange {
        uint64_t start;
        uint64_t end;

        MemRange(uint64_t _start, uint64_t _end) : start(_start), end(_end) {
        }
    };

    void addRange(uint64_t startAddr, uint64_t endAddr, bool isBlacklist);

    bool isInRange(uint64_t address);

    void initialize();

private:
    std::vector<MemRange> m_whitelist;
    std::vector<MemRange> m_blacklist;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MEMRANGEDETECTOR_H
