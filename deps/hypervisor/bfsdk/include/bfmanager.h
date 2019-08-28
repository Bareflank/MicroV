//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BFMANAGER_H
#define BFMANAGER_H

#include <mutex>
#include <memory>
#include <unordered_map>

#include <bfgsl.h>
#include <bfobject.h>

/// Manager
///
/// A generic class for creating, destroying, running and stopping T given a
/// T_factory to actually instantiate T, and a tid to identify which T to
/// interact with.
///
template<typename T, typename T_factory, typename tid>
class bfmanager
{
public:

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~bfmanager() = default;

    /// Get Singleton Instance
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of bfmanager
    ///
    static bfmanager *instance() noexcept
    {
        static bfmanager self;
        return &self;
    }

    /// Create T
    ///
    /// Creates T. Note that the T is actually created by the
    /// T factory's make_t function.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the T to initialize
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void create(tid id, bfobject *obj = nullptr)
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        expects(m_ts.count(id) == 0);

        try {
            auto t = m_T_factory->make(id, obj);
            if (!t) {
                throw std::runtime_error("bfmanager: make failed");
            }

            t->init(obj);
            m_ts[id] = std::make_pair(
                           std::move(t),
                           std::make_unique<refcount>(0));
        }
        catch (...) {
            m_ts.erase(id);
            throw std::runtime_error("bfmanager: create failed");
        }
    }

    /// Destroy T
    ///
    /// Deletes T.
    ///
    /// @param id the T to destroy
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void destroy(tid id, bfobject *obj = nullptr)
    {
        std::lock_guard<std::mutex> guard(m_mutex);

        auto ti = m_ts.find(id);
        if (ti != m_ts.end()) {
            auto refcount = ti->second.second.get();
            while (refcount->load() != 0) {
                asm volatile("pause");
            }

            m_ts.erase(id);
            m_refcounts.erase(id);
            asm volatile("mfence");
        }
    }

    T *acquire(tid id) noexcept
    {
        try {
            std::lock_guard<std::mutex> guard(m_mutex);

            auto ti = m_ts.find(id);
            if (ti != m_ts.end()) {
                auto refcount = ti->second.second.get();
                refcount->fetch_add(1);

                {
                    std::lock_guard<std::mutex> refguard(m_ref_mutex);
                    if (m_refcounts.count(id) == 0) {
                        m_refcounts[id] = refcount;
                    }
                }
                asm volatile("mfence");

                return ti->second.first.get();
            } else {
                return nullptr;
            }
        } catch (...) {
            bferror_nhex(0, "bfmanager::acquire threw exception, id =", id);
            return nullptr;
        }
    }

    template<typename U>
    U *acquire(tid id) noexcept
    {
        U *ret = nullptr;

        try {
            ret = dynamic_cast<U *>(acquire(id));
        } catch (...) {
            bferror_nhex(0, "bfmanager::acquire bad_cast, id =", id);
            ret = nullptr;
        }

        return ret;
    }

    void release(tid id) noexcept
    {
        try {
            std::lock_guard<std::mutex> refguard(m_ref_mutex);

            auto itr = m_refcounts.find(id);
            if (itr != m_refcounts.end()) {
                itr->second->fetch_sub(1);
            }
        } catch (...) {
            bferror_nhex(0, "bfmanager::release threw exception, id =", id);
        }
    }

    /// Run T
    ///
    /// Executes T.
    ///
    /// @expects t exists
    /// @ensures none
    ///
    /// @param id the T to run
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void run(tid id, bfobject *obj = nullptr)
    {
        if (auto t = get(id)) {
            t->run(obj);
        }
    }

    /// Halt T
    ///
    /// Halts T.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the T to halt
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    void hlt(tid id, bfobject *obj = nullptr)
    {
        if (auto t = get(id)) {
            t->hlt(obj);
        }
    }

    /// Get
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the T to get
    /// @param err the error to display
    /// @return returns a pointer to the T associated with tid
    ///
    gsl::not_null<T *> get(tid id, const char *err = nullptr)
    {
        std::lock_guard<std::mutex> guard(m_mutex);

        if (auto iter = m_ts.find(id); iter != m_ts.end()) {
            return iter->second.first.get();
        }

        if (err != nullptr) {
            throw std::runtime_error(err);
        }
        else {
            throw std::runtime_error("bfmanager: failed to get T");
        }
    }

    /// Get (Dynamic Cast)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the T to get
    /// @param err the error to display
    /// @return returns a pointer to the T associated with tid
    ///
    template<typename U>
    gsl::not_null<U> get(tid id, const char *err = nullptr)
    { return dynamic_cast<U>(get(id, err).get()); }

private:

    bfmanager() noexcept :
        m_T_factory(std::make_unique<T_factory>())
    { }

private:
    using refcount = std::atomic<uint64_t>;
    using mapped_t = std::pair<std::unique_ptr<T>, std::unique_ptr<refcount>>;

    std::unique_ptr<T_factory> m_T_factory;
    std::unordered_map<tid, mapped_t> m_ts;
    std::unordered_map<tid, refcount *> m_refcounts;

    mutable std::mutex m_mutex;
    mutable std::mutex m_ref_mutex;

public:

    /// @cond

    void set_factory(std::unique_ptr<T_factory> factory)
    { m_T_factory = std::move(factory); }

    bfmanager(bfmanager &&) noexcept = delete;
    bfmanager &operator=(bfmanager &&) noexcept = delete;

    bfmanager(const bfmanager &) = delete;
    bfmanager &operator=(const bfmanager &) = delete;

    /// @endcond
};

#endif
