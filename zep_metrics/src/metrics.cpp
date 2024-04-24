//
//  metrics.cpp
//
//  Created by Jon Gabilondo on 19/10/2022.
//  Copyright © 2022 Zscaler. All rights reserved.
//

#include <stdio.h>
#include <sstream>
#include <zlog/zlog.h>
#include "metrics.h"

namespace zep::zmetrics
{

Counter::Counter(): mName(""), mCount(0), mPeak(0), mKeepPeak(0)
{
    
}

Counter::Counter(const std::string& name, const std::vector<std::string>& subcounters, bool keepPeak): mName(name), mCount(0), mPeak(0), mKeepPeak(keepPeak)
{
    for (const auto & subCounterName: subcounters) {
        mSubcounters.push_back(new Counter(subCounterName, {}));
    }
}

uint64_t Counter::increment(bool log)
{
    mCount++;
    
    if (mKeepPeak && (mCount > mPeak)) {
        mPeak.store(mCount);
    }

    if (log) {
        trace();
    }
    return mCount;
}

uint64_t Counter::decrement(bool log)
{
    mCount--;
    if (log) {
        trace();
    }
    return mCount;
}

uint64_t Counter::incrementSubcounter(int subcounterIndex)
{
    if (mSubcounters.size() > subcounterIndex)
    {
        mSubcounters[subcounterIndex]->increment();
        return increment(true);
    }
    return 0;
}

uint64_t Counter::decrementSubcounter(int subcounterIndex)
{
    if (mSubcounters.size() > subcounterIndex)
    {
        mSubcounters[subcounterIndex]->decrement();
        return decrement(true);
    }
    return 0;
}

void Counter::trace()
{
    std::stringstream log_msg;
    log_msg << mName << " Total:" << mCount;
    if (mKeepPeak) {
        log_msg << " Peak:" << mPeak;
    }
    
    if (mSubcounters.size())
    {
        for(const auto & subcounter: mSubcounters) {
            log_msg << " " << subcounter->getName() << ":" << subcounter->getCount();
        }
    }
    log_msg << std::endl;
    LOG_DEBUG(ZMETRICS_CATEGORY, "{}", log_msg.str());
}

#pragma mark -

MultiCounter::MultiCounter(): mName(""), mKeepPeak(0)
{
    
}

MultiCounter::MultiCounter(const std::string& name, const std::vector<std::string>& counters, bool keepPeak): mName(name), mKeepPeak(keepPeak)
{
    for (const auto & counterName: counters) {
        mCounters.push_back(new Counter(counterName, {}, mKeepPeak));
    }
}


uint64_t MultiCounter::incrementCounter(int counterIndex, bool log)
{
    if (mCounters.size() > counterIndex)
    {
        mCounters[counterIndex]->increment();
        if (log)
            trace();
        return mCounters[counterIndex]->getCount();
    }
    return 0;
}

uint64_t MultiCounter::decrementCounter(int counterIndex, bool log)
{
    if (mCounters.size() > counterIndex)
    {
        mCounters[counterIndex]->decrement();
        if (log)
            trace();
    }
    return 0;
}

void MultiCounter::trace()
{
    std::stringstream log_msg;
    
    log_msg << mName << ".";

    if (mCounters.size())
    {
        for(const auto & counter: mCounters) {
            log_msg << " " << counter->getName() << ":" << counter->getCount();
            if (mKeepPeak) {
                log_msg << " Peak:" << counter->getPeak();
            }
        }
    }
    log_msg << std::endl;
    LOG_DEBUG(ZMETRICS_CATEGORY, "{}", log_msg.str());
}

#pragma mark -

SerialOrder::SerialOrder(const std::string& name): mName(name), mSerialNumber(0), mOutOfOrderCnt(0), mHandledCnt(0)
{
}

uint64_t SerialOrder::increment()
{
    return ++mSerialNumber;
}

void SerialOrder::processSN(const uint64_t sn)
{
    uint64_t sn_prev = mSerialNumber.exchange(sn);
    
    mHandledCnt++;
    
    if (sn_prev+1 != sn) {
        LOG_WARN(ZMETRICS_CATEGORY, "{} Inconsistency. SN:{} Prev:{}", mName, sn, sn_prev);
        mOutOfOrderCnt++;
    }
    
    float out_of_order_pct = ((float)mOutOfOrderCnt/(float)mHandledCnt)*100;
    
    std::stringstream log_msg;
    log_msg << mName << " Event:" << sn << " (Prev.:" << sn_prev << ") Err%:" << out_of_order_pct << "% (Errors:" << mOutOfOrderCnt << ")" << " Total:" << mHandledCnt << std::endl;
    LOG_DEBUG(ZMETRICS_CATEGORY, "{}", log_msg.str());
}

#pragma mark -

Duration::Duration(const std::string &name, const std::vector<std::string>& subClocks) : mName(name)
{
    for (const auto & subClockName: subClocks) {
        mSubclocks.push_back(new Duration(subClockName, {}));
    }
}

void Duration::start()
{
    mStartTime = std::chrono::steady_clock::now();
}

void Duration::stop(bool doTrace)
{
    mDuration = getDurationUntilNow();
    if (mDuration > mDurationPeak) {
        mDurationPeak.store(mDuration);
    }
    if (doTrace)
        trace();
}

void Duration::startSubclock(int index)
{
    if (mSubclocks.size() > index)
    {
        mSubclocks[index]->start();
    }
}

void Duration::stopSubclock(int index)
{
    if (mSubclocks.size() > index)
    {
        mSubclocks[index]->stop(false);
    }
}

uint64_t Duration::getDurationUntilNow() const {
     return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-mStartTime).count();
}

uint64_t Duration::getMicroDurationUtilNow() const {
     return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-mStartTime).count();
}

uint64_t Duration::getNanoDurationUntilNow() const {
     return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-mStartTime).count();
}


void Duration::trace()
{
    std::stringstream log_msg;
    log_msg << mName << " Total duration(ms):" << mDuration;
    log_msg << " peak(ms):" << mDurationPeak;
    
    for(const auto & subclock: mSubclocks) {
        log_msg << " " << subclock->getName() << " duration(ms):" << subclock->getDuration();
        log_msg << " peak(ms):" << subclock->getDurationPeek();
    }

    log_msg << std::endl;
    LOG_DEBUG(ZMETRICS_CATEGORY, "{}", log_msg.str());
}


#pragma mark -

EventDuration::EventDuration(EventType eType, const std::string &functionName) : mEventType(eType), mFunction(functionName), mStartTime( std::chrono::steady_clock::now())
{
}

EventDuration::~EventDuration()
{
     auto d = getDuration();
     if (d > mDurationPeak) {
         mDurationPeak = d;
     }
     switch (mEventType) {
         case PrinterEvent:
             if (d > mPrinterDurationPeak) {
                 mPrinterDurationPeak = d;
             }
             break;
         case FileEvent:
             if (d > mFileDurationPeak) {
                 mFileDurationPeak = d;
             }
             break;
         case ProcessStartEvent:
             if (d > mProcessStartDurationPeak) {
                 mProcessStartDurationPeak = d;
             }
             break;
         case ProcessExitEvent:
             if (d > mProcessExitDurationPeak) {
                 mProcessExitDurationPeak = d;
             }
             break;
         default:
             break;
     }
    LOG_DEBUG(ZMETRICS_CATEGORY, "Function: {} Duration:{}(ms) DurationPeak:{} FileDurPeak:{} PrStartPeak:{} PrExitPeak:{}", mFunction, d, mDurationPeak, mFileDurationPeak, mProcessStartDurationPeak, mProcessExitDurationPeak);
}

uint64_t EventDuration::getDuration() {
     return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-mStartTime).count();
}

#pragma mark -

Throughput::Throughput(const std::string &logLineId):
mLogLineId(logLineId),
mPeriod(1000),
mEventCount(0),
mEventCountPeak(0),
mEventCountAvg(0),
mPeriodStartTime(std::chrono::steady_clock::now())
{
    LOG_DEBUG(ZMETRICS_CATEGORY, "Throughput. START.");
}

void Throughput::newEvent(const char* process, bool showLog)
{
    std::string action;
    mEventCount++;
    
    std::chrono::high_resolution_clock::time_point now = std::chrono::steady_clock::now();
    uint64_t lapse = std::chrono::duration_cast<std::chrono::milliseconds>(now-mPeriodStartTime).count();
    if (lapse >= mPeriod) {
        if (mEventCount > mEventCountPeak) {
            mEventCountPeak.store(mEventCount);
        }
        if (showLog) {
            LOG_DEBUG(ZMETRICS_CATEGORY, "{} Events:{} EventsPeak/s:{}", mLogLineId, mEventCount, mEventCountPeak);
        }

        mEventCount = 0;
        mPeriodStartTime = now;
    }
}
    
void Throughput::setPeriod(uint64_t period)
{
    mPeriod = period;
}


};
