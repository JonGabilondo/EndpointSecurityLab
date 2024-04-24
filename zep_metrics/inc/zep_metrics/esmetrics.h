//
//  esmetrics.h
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

enum class LogEventActionType : uint32_t
{
    LOG_EVENT_ES_CLIENT_IN_TYPE_NOTIFY,
    LOG_EVENT_ES_CLIENT_IN_TYPE_AUTH,
    LOG_EVENT_XPC_SEND
};

enum class ESEvent : uint32_t
{
    ES_EVENT_TYPE_AUTH_EXEC
    , ES_EVENT_TYPE_AUTH_OPEN
    , ES_EVENT_TYPE_AUTH_KEXTLOAD
    , ES_EVENT_TYPE_AUTH_MMAP
    , ES_EVENT_TYPE_AUTH_MPROTECT
    , ES_EVENT_TYPE_AUTH_MOUNT
    , ES_EVENT_TYPE_AUTH_RENAME
    , ES_EVENT_TYPE_AUTH_SIGNAL
    , ES_EVENT_TYPE_AUTH_UNLINK
    , ES_EVENT_TYPE_NOTIFY_EXEC
    , ES_EVENT_TYPE_NOTIFY_OPEN
    , ES_EVENT_TYPE_NOTIFY_FORK
    , ES_EVENT_TYPE_NOTIFY_CLOSE
    , ES_EVENT_TYPE_NOTIFY_CREATE
    , ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA
    , ES_EVENT_TYPE_NOTIFY_EXIT
    , ES_EVENT_TYPE_NOTIFY_GET_TASK
    , ES_EVENT_TYPE_NOTIFY_KEXTLOAD
    , ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD
    , ES_EVENT_TYPE_NOTIFY_LINK
    , ES_EVENT_TYPE_NOTIFY_MMAP
    , ES_EVENT_TYPE_NOTIFY_MPROTECT
    , ES_EVENT_TYPE_NOTIFY_MOUNT
    , ES_EVENT_TYPE_NOTIFY_UNMOUNT
    , ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN
    , ES_EVENT_TYPE_NOTIFY_RENAME
    , ES_EVENT_TYPE_NOTIFY_SETATTRLIST
    , ES_EVENT_TYPE_NOTIFY_SETEXTATTR
    , ES_EVENT_TYPE_NOTIFY_SETFLAGS
    , ES_EVENT_TYPE_NOTIFY_SETMODE
    , ES_EVENT_TYPE_NOTIFY_SETOWNER
    , ES_EVENT_TYPE_NOTIFY_SIGNAL
    , ES_EVENT_TYPE_NOTIFY_UNLINK
    , ES_EVENT_TYPE_NOTIFY_WRITE
    , ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE
    , ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE
    , ES_EVENT_TYPE_AUTH_READLINK
    , ES_EVENT_TYPE_NOTIFY_READLINK
    , ES_EVENT_TYPE_AUTH_TRUNCATE
    , ES_EVENT_TYPE_NOTIFY_TRUNCATE
    , ES_EVENT_TYPE_AUTH_LINK
    , ES_EVENT_TYPE_NOTIFY_LOOKUP
    , ES_EVENT_TYPE_AUTH_CREATE
    , ES_EVENT_TYPE_AUTH_SETATTRLIST
    , ES_EVENT_TYPE_AUTH_SETEXTATTR
    , ES_EVENT_TYPE_AUTH_SETFLAGS
    , ES_EVENT_TYPE_AUTH_SETMODE
    , ES_EVENT_TYPE_AUTH_SETOWNER
      // The following events are available beginning in macOS 10.15.1
    , ES_EVENT_TYPE_AUTH_CHDIR
    , ES_EVENT_TYPE_NOTIFY_CHDIR
    , ES_EVENT_TYPE_AUTH_GETATTRLIST
    , ES_EVENT_TYPE_NOTIFY_GETATTRLIST
    , ES_EVENT_TYPE_NOTIFY_STAT
    , ES_EVENT_TYPE_NOTIFY_ACCESS
    , ES_EVENT_TYPE_AUTH_CHROOT
    , ES_EVENT_TYPE_NOTIFY_CHROOT
    , ES_EVENT_TYPE_AUTH_UTIMES
    , ES_EVENT_TYPE_NOTIFY_UTIMES
    , ES_EVENT_TYPE_AUTH_CLONE
    , ES_EVENT_TYPE_NOTIFY_CLONE
    , ES_EVENT_TYPE_NOTIFY_FCNTL
    , ES_EVENT_TYPE_AUTH_GETEXTATTR
    , ES_EVENT_TYPE_NOTIFY_GETEXTATTR
    , ES_EVENT_TYPE_AUTH_LISTEXTATTR
    , ES_EVENT_TYPE_NOTIFY_LISTEXTATTR
    , ES_EVENT_TYPE_AUTH_READDIR
    , ES_EVENT_TYPE_NOTIFY_READDIR
    , ES_EVENT_TYPE_AUTH_DELETEEXTATTR
    , ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
    , ES_EVENT_TYPE_AUTH_FSGETPATH
    , ES_EVENT_TYPE_NOTIFY_FSGETPATH
    , ES_EVENT_TYPE_NOTIFY_DUP
    , ES_EVENT_TYPE_AUTH_SETTIME
    , ES_EVENT_TYPE_NOTIFY_SETTIME
    , ES_EVENT_TYPE_NOTIFY_UIPC_BIND
    , ES_EVENT_TYPE_AUTH_UIPC_BIND
    , ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT
    , ES_EVENT_TYPE_AUTH_UIPC_CONNECT
    , ES_EVENT_TYPE_AUTH_EXCHANGEDATA
    , ES_EVENT_TYPE_AUTH_SETACL
    , ES_EVENT_TYPE_NOTIFY_SETACL
      // The following events are available beginning in macOS 10.15.4
    , ES_EVENT_TYPE_NOTIFY_PTY_GRANT
    , ES_EVENT_TYPE_NOTIFY_PTY_CLOSE
    , ES_EVENT_TYPE_AUTH_PROC_CHECK
    , ES_EVENT_TYPE_NOTIFY_PROC_CHECK
    , ES_EVENT_TYPE_AUTH_GET_TASK
      // The following events are available beginning in macOS 11.0
    , ES_EVENT_TYPE_AUTH_SEARCHFS
    , ES_EVENT_TYPE_NOTIFY_SEARCHFS
    , ES_EVENT_TYPE_AUTH_FCNTL
    , ES_EVENT_TYPE_AUTH_IOKIT_OPEN
    , ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME
    , ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME
    , ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
    , ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME
    , ES_EVENT_TYPE_NOTIFY_TRACE
    , ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE
    , ES_EVENT_TYPE_AUTH_REMOUNT
    , ES_EVENT_TYPE_NOTIFY_REMOUNT
    // The following events are available beginning in macOS 11.3
    , ES_EVENT_TYPE_AUTH_GET_TASK_READ
    , ES_EVENT_TYPE_NOTIFY_GET_TASK_READ
    , ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT
    // The following events are available beginning in macOS 12.0
    , ES_EVENT_TYPE_NOTIFY_SETUID
    , ES_EVENT_TYPE_NOTIFY_SETGID
    , ES_EVENT_TYPE_NOTIFY_SETEUID
    , ES_EVENT_TYPE_NOTIFY_SETEGID
    , ES_EVENT_TYPE_NOTIFY_SETREUID
    , ES_EVENT_TYPE_NOTIFY_SETREGID
    , ES_EVENT_TYPE_AUTH_COPYFILE
    , ES_EVENT_TYPE_NOTIFY_COPYFILE
    // The following events are available beginning in macOS 13.0
    , ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
    , ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
    , ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
    , ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
    , ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
    , ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
    , ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
    , ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
    , ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
    , ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
    , ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
    , ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
      // ES_EVENT_TYPE_LAST is not a valid event type but a convenience
      // value for operating on the range of defined event types.
      // This value may change between releases and was available
      // beginning in macOS 10.15
    , ES_EVENT_TYPE_LAST
};


class ESEventThroughput {
public:
    ESEventThroughput();
    ~ESEventThroughput() = default;
    
    void newEvent(LogEventActionType actionType, ESEvent eventType, const std::string &logLineId, const char* process = nullptr, bool showLog = true);
    void setPeriod(uint64_t period);
    
private:
    std::chrono::high_resolution_clock::time_point mPeriodStartTime;
    std::atomic_ulong mPeriod;
    std::atomic_ulong mEventCount;
    std::atomic_ulong mNotifyEventCount;
    std::atomic_ulong mAuthEventCount;
    std::atomic_ulong mEventCountPeak;
    std::atomic_ulong mEventCountAvg;
    std::atomic_ulong mTotalAuthEventCount;
    std::atomic_ulong mTotalNotifyEventCount;
    std::atomic_ulong mXPCSendEventCount;
};

class ESEventCounter {
public:
    ESEventCounter(const std::string &logLineId);
    ~ESEventCounter() = default;
    
    void newEvent(LogEventActionType actionType, ESEvent eventType, const char* processPath = nullptr, bool showLog = true);
    
private:
    std::unordered_map<std::string, unsigned long> mEvents;
    std::unordered_map<std::string, unsigned long> mEventsPerProcess;
    std::chrono::high_resolution_clock::time_point mPeriodStartTime;
    std::atomic_ulong mPeriod;
    std::atomic_ulong mEventCount;
    std::string mLogLineId;
    std::string mPrevProcess;
};

}

namespace zep::zstd
{

template<>
class EnumTypeInfo<zep::zmetrics::ESEvent>
{
public:
    static const EnumStrings<zep::zmetrics::ESEvent> GetStrings()
    {
        return
        {
            {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_EXEC, "ES_EVENT_TYPE_AUTH_EXEC"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_OPEN, "ES_EVENT_TYPE_AUTH_OPEN"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_KEXTLOAD, "ES_EVENT_TYPE_AUTH_KEXTLOAD"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_MMAP, "ES_EVENT_TYPE_AUTH_MMAP"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_MPROTECT, "ES_EVENT_TYPE_AUTH_MPROTECT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_MOUNT, "ES_EVENT_TYPE_AUTH_MOUNT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_RENAME, "ES_EVENT_TYPE_AUTH_RENAME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SIGNAL, "ES_EVENT_TYPE_AUTH_SIGNAL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_UNLINK, "ES_EVENT_TYPE_AUTH_SIGNAL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_EXEC, "ES_EVENT_TYPE_NOTIFY_EXEC"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_OPEN, "ES_EVENT_TYPE_NOTIFY_OPEN"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_FORK, "ES_EVENT_TYPE_NOTIFY_FORK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_CLOSE, "ES_EVENT_TYPE_NOTIFY_CLOSE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_CREATE, "ES_EVENT_TYPE_NOTIFY_CREATE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, "ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_EXIT, "ES_EVENT_TYPE_NOTIFY_EXIT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_GET_TASK, "ES_EVENT_TYPE_NOTIFY_GET_TASK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_KEXTLOAD, "ES_EVENT_TYPE_NOTIFY_KEXTLOAD"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD, "ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LINK, "ES_EVENT_TYPE_NOTIFY_LINK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_MMAP, "ES_EVENT_TYPE_NOTIFY_MMAP"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_MPROTECT, "ES_EVENT_TYPE_NOTIFY_MPROTECT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_MOUNT, "ES_EVENT_TYPE_NOTIFY_MOUNT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_UNMOUNT, "ES_EVENT_TYPE_NOTIFY_UNMOUNT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_RENAME, "ES_EVENT_TYPE_NOTIFY_RENAME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETATTRLIST, "ES_EVENT_TYPE_NOTIFY_SETATTRLIST"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETEXTATTR, "ES_EVENT_TYPE_NOTIFY_SETEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETFLAGS, "ES_EVENT_TYPE_NOTIFY_SETFLAGS"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETMODE, "ES_EVENT_TYPE_NOTIFY_SETMODE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETOWNER, "ES_EVENT_TYPE_NOTIFY_SETOWNER"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SIGNAL, "ES_EVENT_TYPE_NOTIFY_SIGNAL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_UNLINK, "ES_EVENT_TYPE_NOTIFY_UNLINK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_WRITE, "ES_EVENT_TYPE_NOTIFY_WRITE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE, "ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, "ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE, "ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE, "ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_READLINK, "ES_EVENT_TYPE_AUTH_READLINK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_READLINK, "ES_EVENT_TYPE_NOTIFY_READLINK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_TRUNCATE, "ES_EVENT_TYPE_AUTH_TRUNCATE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_TRUNCATE, "ES_EVENT_TYPE_NOTIFY_TRUNCATE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_LINK, "ES_EVENT_TYPE_AUTH_LINK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LOOKUP, "ES_EVENT_TYPE_NOTIFY_LOOKUP"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_CREATE, "ES_EVENT_TYPE_NOTIFY_LOOKUP"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETATTRLIST, "ES_EVENT_TYPE_AUTH_SETATTRLIST"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETEXTATTR, "ES_EVENT_TYPE_AUTH_SETEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETFLAGS, "ES_EVENT_TYPE_AUTH_SETFLAGS"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETMODE, "ES_EVENT_TYPE_AUTH_SETMODE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETOWNER, "ES_EVENT_TYPE_AUTH_SETOWNER"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_CHDIR, "ES_EVENT_TYPE_AUTH_CHDIR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_CHDIR, "ES_EVENT_TYPE_NOTIFY_CHDIR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_GETATTRLIST, "ES_EVENT_TYPE_AUTH_GETATTRLIST"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_GETATTRLIST, "ES_EVENT_TYPE_NOTIFY_GETATTRLIST"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_STAT, "ES_EVENT_TYPE_NOTIFY_STAT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_ACCESS, "ES_EVENT_TYPE_NOTIFY_ACCESS"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_CHROOT, "ES_EVENT_TYPE_AUTH_CHROOT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_CHROOT, "ES_EVENT_TYPE_NOTIFY_CHROOT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_UTIMES, "ES_EVENT_TYPE_AUTH_UTIMES"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_UTIMES, "ES_EVENT_TYPE_AUTH_UTIMES"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_CLONE, "ES_EVENT_TYPE_AUTH_CLONE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_CLONE, "ES_EVENT_TYPE_NOTIFY_CLONE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_FCNTL, "ES_EVENT_TYPE_NOTIFY_FCNTL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_GETEXTATTR, "ES_EVENT_TYPE_AUTH_GETEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_GETEXTATTR, "ES_EVENT_TYPE_NOTIFY_GETEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_LISTEXTATTR, "ES_EVENT_TYPE_AUTH_LISTEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, "ES_EVENT_TYPE_NOTIFY_LISTEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_READDIR, "ES_EVENT_TYPE_AUTH_READDIR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_READDIR, "ES_EVENT_TYPE_NOTIFY_READDIR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_DELETEEXTATTR, "ES_EVENT_TYPE_AUTH_DELETEEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_FSGETPATH, "ES_EVENT_TYPE_AUTH_FSGETPATH"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_FSGETPATH, "ES_EVENT_TYPE_NOTIFY_FSGETPATH"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_DUP, "ES_EVENT_TYPE_NOTIFY_DUP"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETTIME, "ES_EVENT_TYPE_AUTH_SETTIME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETTIME, "ES_EVENT_TYPE_NOTIFY_SETTIME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "ES_EVENT_TYPE_NOTIFY_UIPC_BIND"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_UIPC_BIND, "ES_EVENT_TYPE_AUTH_UIPC_BIND"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_UIPC_CONNECT, "ES_EVENT_TYPE_AUTH_UIPC_CONNECT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_EXCHANGEDATA, "ES_EVENT_TYPE_AUTH_EXCHANGEDATA"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SETACL, "ES_EVENT_TYPE_AUTH_SETACL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETACL, "ES_EVENT_TYPE_NOTIFY_SETACL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_PTY_GRANT, "ES_EVENT_TYPE_NOTIFY_PTY_GRANT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_PTY_CLOSE, "ES_EVENT_TYPE_NOTIFY_PTY_CLOSE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_PROC_CHECK, "ES_EVENT_TYPE_NOTIFY_PTY_CLOSE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_PROC_CHECK, "ES_EVENT_TYPE_NOTIFY_PROC_CHECK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_GET_TASK, "ES_EVENT_TYPE_AUTH_GET_TASK"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_SEARCHFS, "ES_EVENT_TYPE_AUTH_SEARCHFS"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SEARCHFS, "ES_EVENT_TYPE_NOTIFY_SEARCHFS"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_FCNTL, "ES_EVENT_TYPE_AUTH_FCNTL"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_IOKIT_OPEN, "ES_EVENT_TYPE_AUTH_IOKIT_OPEN"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, "ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME, "ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, "ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME, "ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_TRACE, "ES_EVENT_TYPE_NOTIFY_TRACE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_REMOUNT, "ES_EVENT_TYPE_AUTH_REMOUNT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_REMOUNT, "ES_EVENT_TYPE_NOTIFY_REMOUNT"}
            // The following events are available beginning in macOS 12.0
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETUID, "ES_EVENT_TYPE_NOTIFY_SETUID"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETGID, "ES_EVENT_TYPE_NOTIFY_SETGID"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETEUID, "ES_EVENT_TYPE_NOTIFY_SETEUID"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETEGID, "ES_EVENT_TYPE_NOTIFY_SETEGID"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETREUID, "ES_EVENT_TYPE_NOTIFY_SETREUID"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SETREGID, "ES_EVENT_TYPE_NOTIFY_SETREGID"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_AUTH_COPYFILE, "ES_EVENT_TYPE_AUTH_COPYFILE"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_COPYFILE, "ES_EVENT_TYPE_NOTIFY_COPYFILE"}
            // The following events are available beginning in macOS 13.0
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, "ES_EVENT_TYPE_NOTIFY_AUTHENTICATION" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, "ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, "ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT" }
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD"}
            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE"}

            , {zep::zmetrics::ESEvent::ES_EVENT_TYPE_LAST, "ES_EVENT_TYPE_LAST"}
        };
    };

};
}

