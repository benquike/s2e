///
/// Copyright (C) 2020, Vitaly Chipounov
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

#ifndef S2E_PLUGINS_CFICHECKER_H
#define S2E_PLUGINS_CFICHECKER_H

#include <s2e/Plugin.h>
#include <s2e/cpu.h>

extern "C" {
void helper_se_call(target_ulong pc);
void helper_se_ret(target_ulong pc, int retim_value);
}

namespace s2e {

struct ModuleDescriptor;

namespace plugins {

class AddressTracker;
class ProcessExecutionDetector;
class WindowsMonitor;
class ModuleMap;
class MemoryMap;

struct CFIStatistics {
    uint64_t DirectCallCount = 0;
    uint64_t IndirectCallCount = 0;
    uint64_t RetCount = 0;
    uint64_t CallViolationCount = 0;
    uint64_t RetViolationCount = 0;

    // TODO: move these two out of here?
    uint64_t SegFaultCount = 0;
    uint64_t WerFaultCount = 0;

    uint64_t RetFromUnknownExecRegionCount = 0;
    uint64_t RetToUnknownExecRegionCount = 0;

    uint64_t MissingReturnAddressCount = 0;
    uint64_t CallAndReturnMatchCount = 0;
    uint64_t WhitelistedReturnCount = 0;
    uint64_t PendingViolationsCount = 0;
    uint64_t WhitelistedCallPatternCount = 0;
    uint64_t RetToParentWithDisplacement = 0;

    uint64_t CallToUnknownExecRegionCount = 0;

    void print(llvm::raw_ostream &os) const;
};

class CFIChecker : public Plugin {
    S2E_PLUGIN

    AddressTracker *m_tracker;
    ProcessExecutionDetector *m_process;
    WindowsMonitor *m_monitor;
    ModuleMap *m_modules;
    MemoryMap *m_memory;

public:
    CFIChecker(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    sigc::signal<void, S2EExecutionState *, bool /* isReturn violation */
                 >
        onCFIViolation;

    const CFIStatistics &getStats(S2EExecutionState *state);

private:
    void onTimer();
    void onMonitorLoad(S2EExecutionState *state);
    void onProcessOrThreadSwitch(S2EExecutionState *state);
    void onCall(S2EExecutionState *state, uint64_t pc);
    void onRet(S2EExecutionState *state, uint64_t pc, int retim_value);
    void onCallReturnTranslate(S2EExecutionState *state, uint64_t pc, bool isCall, bool *instrument);

    bool isKnownFunctionPattern(S2EExecutionState *state, uint64_t pc);
    bool isExecutableTarget(S2EExecutionState *state, uint64_t pid, uint64_t pc);

    void reportPendingViolations(S2EExecutionState *state);

    friend void ::helper_se_call(target_ulong pc);
    friend void ::helper_se_ret(target_ulong pc, int retim_value);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CFICHECKER_H
