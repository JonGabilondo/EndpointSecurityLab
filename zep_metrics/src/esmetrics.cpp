//
//  esmetrics.cpp
//
//  Created by Jon Gabilondo on 19/10/2022.
//  Copyright © 2022 Zscaler. All rights reserved.
//

#include <stdio.h>
#include <sstream>
#include <zlog/zlog.h>
#include "metrics.h"
#include "esmetrics.h"

namespace zep::zmetrics
{

ESEventThroughput::ESEventThroughput():
mPeriod(1000),
mEventCount(0),
mNotifyEventCount(0),
mAuthEventCount(0),
mEventCountPeak(0),
mEventCountAvg(0),
mTotalAuthEventCount(0),
mTotalNotifyEventCount(0),
mXPCSendEventCount(0),
mPeriodStartTime(std::chrono::steady_clock::now())
{
    LOG_DEBUG(ZMETRICS_CATEGORY, "ESEventThroughput. START.");
}

void ESEventThroughput::newEvent(LogEventActionType actionType, ESEvent eventType, const std::string &logLineId, const char* process, bool showLog)
{
    std::string action;
    mEventCount++;
    if (actionType == LogEventActionType::LOG_EVENT_ES_CLIENT_IN_TYPE_NOTIFY) {
        mTotalNotifyEventCount++;
        mNotifyEventCount++;
        action = "Notify";
    } else if (actionType == LogEventActionType::LOG_EVENT_ES_CLIENT_IN_TYPE_AUTH) {
        mTotalAuthEventCount++;
        mAuthEventCount++;
        action = "Auth";
    } else if (actionType == LogEventActionType::LOG_EVENT_XPC_SEND) {
        mXPCSendEventCount++;
        action = "XPCSend";
    } else {
        LOG_ASSERT(ZMETRICS_CATEGORY, 0, "Who is sending unknown events ?");
    }

    if (showLog) {
//        std::stringstream log_msg;
//        log_msg << logLineId << "Action:\t" << action << "\tType:\t" << eventType << "\tNtfy:\t" << mTotalNotifyEventCount << "\tAuth:\t" << mTotalAuthEventCount << "\tTotal:\t" <<  mTotalAuthEventCount+mTotalNotifyEventCount << "\tProc:\t" << (process ?process :"") << std::endl;
//        LOG_DEBUG(ZMETRICS_CATEGORY, "{} Action:\t {} \tType:\t {} \tNtfy:\t {} \tAuth:\t {} \tTotal:\t {} \tProc:\t {}", logLineId, action, zep::zstd::EnumUtils<ESEvent>::to_string(eventType), mTotalNotifyEventCount, mTotalAuthEventCount, mTotalAuthEventCount+mTotalNotifyEventCount, (process ?process :""));
    }
    
    std::chrono::high_resolution_clock::time_point now = std::chrono::steady_clock::now();
    uint64_t lapse = std::chrono::duration_cast<std::chrono::milliseconds>(now-mPeriodStartTime).count();
    if (lapse >= mPeriod) {
        if (mEventCount > mEventCountPeak) {
            mEventCountPeak.store(mEventCount);
        }
        if (showLog) {
            std::stringstream log_msg;
            log_msg << logLineId << "ESEventThroughput\tEvents:\t" << mEventCount << "\tNtfy/s:\t" << mNotifyEventCount << "\tAuth/s:\t" << mAuthEventCount << "\tEventsPeak/s:\t" << mEventCountPeak << "\tXPCSend/s:\t"  << mXPCSendEventCount << "\tTotal:\t" << (mTotalAuthEventCount+mTotalNotifyEventCount) << std::endl;
            LOG_DEBUG(ZMETRICS_CATEGORY, "{}", log_msg.str());
        }

        mEventCount = 0;
        mNotifyEventCount = 0;
        mAuthEventCount = 0;
        mXPCSendEventCount = 0;
        mPeriodStartTime = now;
    }
}
    
void ESEventThroughput::setPeriod(uint64_t period)
{
    mPeriod = period;
}


#pragma mark -

ESEventCounter::ESEventCounter(const std::string &logLineId):
mLogLineId(logLineId),
mPeriod(5000),
mPeriodStartTime(std::chrono::steady_clock::now())
{
    
}

void ESEventCounter::newEvent(LogEventActionType actionType, ESEvent eventType, const char* processPath, bool showLog)
{
    if (!processPath)
        return;
    
    unsigned long count = 1;
    
    std::string eventName = zep::zstd::EnumUtils<ESEvent>::to_string(eventType);
    if (mEvents.contains(eventName))
    {
        count = mEvents[eventName];
        mEvents[eventName] = ++count;
    }
    else
    {
        mEvents[eventName] = 1;
    }

    unsigned long procCount = 1;
    if (mEventsPerProcess.contains(processPath))
    {
        procCount = mEventsPerProcess[processPath];
        mEventsPerProcess[processPath] = ++procCount;
    }
    else
    {
        mEventsPerProcess[processPath] = procCount;
    }
    
    if (showLog)
    {
        if (mPrevProcess != processPath)
        {
            LOG_DEBUG(ZMETRICS_CATEGORY, "Proc. Count. {} Proc:'{}' Count:'{}'", mLogLineId, processPath, procCount);
        }
        mPrevProcess = processPath;
    }

    std::chrono::high_resolution_clock::time_point now = std::chrono::steady_clock::now();
    uint64_t lapse = std::chrono::duration_cast<std::chrono::milliseconds>(now-mPeriodStartTime).count();
    if (lapse >= mPeriod)
    {
        if (showLog)
        {
            std::stringstream events;
            std::stringstream counts;
            size_t prefixCount = sizeof("ES_EVENT_TYPE_") - 1;

            std::for_each(mEvents.begin(), mEvents.end(),
                          [&events, &counts, prefixCount](std::pair<std::string, unsigned long> p)
                          {
                            events << p.first.substr(prefixCount) << ",";
                            counts << p.second << ",";
                          }
                          );
            
            LOG_DEBUG(ZMETRICS_CATEGORY, "{} Events:'{}' Counts:'{}'", mLogLineId, events.str(), counts.str());
        }

        mPeriodStartTime = now;
    }
}

//#if defined (__APPLE__)
//
//void ThreadNum::logInfo()
//{
//    NSUInteger num = [[NSThread.currentThread valueForKeyPath:@"private.seqNum"] integerValue];
//    LOG_DEBUG(ZMETRICS_CATEGORY, "ThreadNum:%llu",  num);
//}
//
//#endif

};
