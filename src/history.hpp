#pragma once
#include "shared.hpp"
#include <deque>
namespace fs {
class History {
    struct Sample { LONG64 tick; std::string text; };
    std::deque<Sample> samples;
    size_t bytes = 0;
    DWORD window;
public:
    explicit History(DWORD milliseconds) : window(milliseconds) {}
    void add(std::string text);
    std::string text() const;
    void clear() { samples.clear(); bytes = 0; }
};
}
