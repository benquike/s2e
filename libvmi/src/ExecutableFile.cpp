///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
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

#include <vmi/DecreeFile.h>
#include <vmi/ELFFile.h>
#include <vmi/PEFile.h>

namespace vmi {

ExecutableFile::ExecutableFile(std::shared_ptr<FileProvider> file, bool loaded, uint64_t loadAddress)
    : m_file(file), m_loaded(loaded), m_loadAddress(loadAddress), m_functionsInited(false) {
}

ExecutableFile::~ExecutableFile() {
}

std::shared_ptr<ExecutableFile> ExecutableFile::get(std::shared_ptr<FileProvider> file, bool loaded,
                                                    uint64_t loadAddress) {
    std::shared_ptr<ExecutableFile> ret;

    ret = PEFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = DecreeFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = ELFFile32::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = ELFFile64::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    return nullptr;
}

// push    ebp
// mov     ebp, esp
// sub     esp, ...
static const uint8_t s_prolog1[] = {0x55, 0x8b, 0xec, 0x81, 0xec};

const FunctionAddresses &ExecutableFile::guessFunctionAddresses() const {
    if (m_functionsInited) {
        return m_functions;
    }

    for (auto &s : getSections()) {
        if (!s.executable) {
            continue;
        }

        for (auto i = 0; i < s.size; ++i) {
            uint8_t buffer[sizeof(s_prolog1)];
            auto size = sizeof(buffer);
            if (read(buffer, size, s.start + i) != size) {
                break;
            }

            if (!memcmp(buffer, s_prolog1, sizeof(s_prolog1))) {
                m_functions.push_back(s.start + i);
            }
        }
    }

    m_functionsInited = true;
    return m_functions;
}

} // namespace vmi
