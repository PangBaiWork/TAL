//
// Created by pangb on 26-5-22.
//

#ifndef SPARSEBITMAP_H
#define SPARSEBITMAP_H


#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>

class SparseBitmap {
private:
    using L2Atomic = std::atomic<uint64_t>;

    static constexpr uint64_t L1_BITS  = 18;
    static constexpr uint64_t L2_BITS  = 18;

    static constexpr uint64_t L1_SIZE  = 1ULL << L1_BITS;
    static constexpr uint64_t L2_SIZE  = 1ULL << L2_BITS;

    static constexpr uint64_t WORD_BITS = 64;

    static constexpr uint64_t L2_WORDS =
        L2_SIZE / WORD_BITS;

public:

    SparseBitmap() {
        l1_ = new std::atomic<L2Atomic*>[L1_SIZE];

        for (uint64_t i = 0; i < L1_SIZE; ++i) {
            l1_[i].store(
                nullptr,
                std::memory_order_relaxed);
        }
    }

    ~SparseBitmap() {
        if (!l1_)
            return;

        for (uint64_t i = 0; i < L1_SIZE; ++i) {

            auto p =
                l1_[i].load(
                    std::memory_order_relaxed);

            delete[] p;
        }

        delete[] l1_;
    }

    SparseBitmap(const SparseBitmap&) = delete;
    SparseBitmap& operator=(const SparseBitmap&) = delete;

public:

    inline void set(uint64_t bit) {
        auto l2 = getL2(bit, true);
        if (l2) l2[wordIndex(bit)].fetch_or(
            bitMask(bit),
            std::memory_order_relaxed);
    }

    inline void clear(uint64_t bit) {
        auto l2 = getL2(bit, false);

        if (!l2)
            return;

        l2[wordIndex(bit)].fetch_and(
            ~bitMask(bit),
            std::memory_order_relaxed);
    }

    inline bool test(uint64_t bit) const {
        auto l2 = getL2(bit, false);

        if (!l2)
            return false;

        return (l2[wordIndex(bit)].load(
            std::memory_order_relaxed) &
            bitMask(bit)) != 0;
    }

private:

    std::atomic<L2Atomic*>* l1_ = nullptr;

private:

    static inline uint64_t l1Index(uint64_t bit) {
        return bit >> L2_BITS;
    }

    static inline uint64_t l2Index(uint64_t bit) {
        return bit & (L2_SIZE - 1);
    }

    static inline uint64_t wordIndex(uint64_t bit) {
        return l2Index(bit) >> 6;
    }

    static inline uint64_t bitMask(uint64_t bit) {
        return 1ULL << (bit & 63);
    }

    L2Atomic* getL2(
        uint64_t bit,
        bool alloc) const {

        uint64_t idx = l1Index(bit);

        if (idx >= L1_SIZE)
            return nullptr;

        auto p =
            l1_[idx].load(
                std::memory_order_acquire);

        if (!p && alloc) {

            auto np =
                new L2Atomic[L2_WORDS];

            for (uint64_t i = 0; i < L2_WORDS; ++i) {
                np[i].store(
                    0,
                    std::memory_order_relaxed);
            }

            L2Atomic* expected = nullptr;

            if (!l1_[idx].compare_exchange_strong(
                    expected,
                    np,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire)) {

                delete[] np;
                p = expected;
            }
            else {
                p = np;
            }
        }

        return p;
    }
};



#include <cstddef>

#if defined(_WIN32)

#include <windows.h>

inline size_t pageBits() {
    static const size_t bits = [] {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        size_t n = 0;

        for (size_t x = si.dwPageSize; x > 1; x >>= 1)
            ++n;

        return n;
    }();

    return bits;
}

#else
#include <unistd.h>

inline size_t pageBits() {
    static const size_t bits = [] {
        size_t n = 0;

        for (size_t x = sysconf(_SC_PAGESIZE); x > 1; x >>= 1)
            ++n;

        return n;
    }();

    return bits;
}

#endif

#endif //SPARSEBITMAP_H
