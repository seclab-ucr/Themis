
#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "MemRangeDetector.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemRangeDetector, "Detect if an address is in the memory range of interest.", "");

void MemRangeDetector::initialize() {
    ConfigFile *config = s2e()->getConfig();
    std::string cfgKey = getConfigKey();
    bool ok;

    std::vector<std::string> sections = config->getListKeys(cfgKey);
    foreach2 (it, sections.begin(), sections.end()) {
        bool isBlacklist = config->getBool(cfgKey + "." + *it + ".isBlacklist", false);
        uint64_t startAddr = config->getInt(cfgKey + "." + *it + ".startAddr", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find startAddr in section '" << *it << "'\n";
            exit(-1);
        } 
        uint64_t endAddr = config->getInt(cfgKey + "." + *it + ".endAddr", 0, &ok);
        if (!ok) {
            g_s2e->getWarningsStream() << "Cannot find endAddr in section '" << *it << "'\n";
            exit(-1);
        } 
        g_s2e->getDebugStream() << "Enabled branch coverage for section '" << *it << "' from " << hexval(startAddr) << " to " << hexval(endAddr) << "\n";
        addRange(startAddr, endAddr, isBlacklist);
    }
}

void MemRangeDetector::addRange(uint64_t startAddr, uint64_t endAddr, bool isBlacklist) {
    if (isBlacklist) {
        m_blacklist.push_back(MemRange(startAddr, endAddr));
    } else {
        m_whitelist.push_back(MemRange(startAddr, endAddr));
    }
}

bool MemRangeDetector::isInRange(uint64_t address) {
    for (int i = 0; i < m_blacklist.size(); i++) {
        if (address >= m_blacklist[i].start && address <= m_blacklist[i].end) {
            return false;
        }
    }
    for (int i = 0; i < m_whitelist.size(); i++) {
        if (address >= m_whitelist[i].start && address <= m_whitelist[i].end) {
           return true;
        }
    }
    return false;
}


} // namespace plugins
} // namespace s2e
