//
//  metrics.h
//
//  Created by Jon Gabilondo on 19/10/2022.
//  Copyright © 2022 Zscaler. All rights reserved.
//

#pragma once

#include <atomic>
#include <vector>
#include <zstd/EnumTypeInfo.h>

namespace zep::zmetrics
{

class SerialOrder {
public:
    SerialOrder(const std::string& name);
    ~SerialOrder() = default;
    
    void processSN(const uint64_t sn);
    uint64_t increment();

private:
    const std::string mName;
    std::atomic_ulong mSerialNumber;
    std::atomic_ulong mOutOfOrderCnt;
    std::atomic_ulong mHandledCnt;
};

class Counter {
public:
    Counter();
    Counter(const std::string& name, const std::vector<std::string>& subcounters, bool keepPeak = false);
    ~Counter() = default;
    
    uint64_t increment(bool log = false);
    uint64_t decrement(bool log = false);
    uint64_t incrementSubcounter(int subcounterIndex);
    uint64_t decrementSubcounter(int subcounterIndex);
    uint64_t getCount() const { return mCount;};
    uint64_t getPeak() const { return mPeak;};
    std::string getName() const { return mName;};
    void    setName(const std::string& name) { mName = name; };
    void    setKeepPeak(bool val) { mKeepPeak = val; };

private:
    std::string mName;
    std::atomic_ulong mCount;
    std::atomic_ulong mPeak;
    bool mKeepPeak;
    std::vector<Counter*> mSubcounters;
    
    void trace();
};

class MultiCounter {
public:
    MultiCounter();
    MultiCounter(const std::string& name, const std::vector<std::string>&counters, bool keepPeak = false);
    ~MultiCounter() = default;
    
    uint64_t incrementCounter(int counterIndex, bool log = false);
    uint64_t decrementCounter(int counterIndex, bool log = false);
    std::string getName() const { return mName;};
    void    setName(const std::string& name) { mName = name; };
    void    setKeepPeak(bool val) { mKeepPeak = val; };

private:
    std::string mName;
    bool mKeepPeak;
    std::vector<Counter*> mCounters;
    
    void trace();
};


template <class T>
class ValueRange {
public:
    ValueRange(const std::string& name = "");
    ~ValueRange() = default;
    
    void newValue(T val);
    T val() { return mVal;}
    T minVal() { return mMinVal;}
    T maxVal() { return mMaxVal;}

private:
    const std::string mName;
    std::atomic<T> mVal;
    std::atomic<T> mMinVal;
    std::atomic<T> mMaxVal;
};

template <class T>
ValueRange<T>::ValueRange(const std::string& name): mName(name), mVal(0), mMaxVal(0), mMinVal(99999999)
{
}

template<class T>
void ValueRange<T>::newValue(T val)
{
    mVal = val;
    if (mVal < mMinVal) {
        mMinVal.store(mVal);
    } else if (mVal > mMaxVal) {
        mMaxVal.store(mVal);
    }
}

class Duration {
public:
    Duration() = default;
    Duration(const std::string &name, const std::vector<std::string>& subClocks);
    ~Duration() = default;
    
    void start();
    void stop(bool trace);
    void startSubclock(int index);
    void stopSubclock(int index);
    void setName(const std::string& name) { mName = name;};
    std::string getName() const { return mName;};
    uint64_t getDuration() const { return mDuration; };
    uint64_t getDurationPeek() const { return mDurationPeak; };

    uint64_t getDurationUntilNow() const;
    uint64_t getMicroDurationUtilNow() const;
    uint64_t getNanoDurationUntilNow() const;

private:
    std::string mName;
    std::chrono::high_resolution_clock::time_point mStartTime;
    std::atomic_ullong mDuration = 0;
    std::atomic_ullong mDurationPeak = 0;
    std::vector<Duration*> mSubclocks;

    void trace();

};


class EventDuration {
public:
    typedef enum {
        PrinterEvent= 0,
        FileEvent,
        ProcessStartEvent,
        ProcessExitEvent
    } EventType;
    
    EventDuration(EventType eType, const std::string &functionName);
    ~EventDuration();
    
    uint64_t getDuration();

private:
    const EventType mEventType;
    const std::string mFunction;
    const std::chrono::high_resolution_clock::time_point mStartTime;
    
    std::atomic_ulong mDurationPeak;
    std::atomic_ulong mFileDurationPeak;
    std::atomic_ulong mPrinterDurationPeak;
    std::atomic_ulong mProcessStartDurationPeak;
    std::atomic_ulong mProcessExitDurationPeak;
};

class Throughput {
public:
    Throughput(const std::string &logLineId);
    ~Throughput() = default;
    
    void newEvent(const char* process = nullptr, bool showLog = true);
    void setPeriod(uint64_t period);
    
private:
    std::chrono::high_resolution_clock::time_point mPeriodStartTime;
    std::atomic_ulong mPeriod;
    std::atomic_ulong mEventCount;
    std::atomic_ulong mEventCountPeak;
    std::atomic_ulong mEventCountAvg;    
    std::string mLogLineId;

};


}

