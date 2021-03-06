//===-- Timer.h -------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_TIMER_H
#define KLEE_TIMER_H

#include <chrono>
#include <stdint.h>

namespace klee {
class WallTimer {
    std::chrono::steady_clock::time_point m_start;

public:
    WallTimer();

    /// check - Return the delta since the timer was created, in microseconds.
    uint64_t check();
};
} // namespace klee

#endif
