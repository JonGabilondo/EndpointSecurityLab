//
//  LabESEventTypes.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 04/04/2024.
//

import Foundation
import EndpointSecurity

public let ESEventTypes = [
    ES_EVENT_TYPE_AUTH_EXEC.rawValue : "AUTH_EXEC",
    ES_EVENT_TYPE_AUTH_OPEN.rawValue : "AUTH_OPEN",
    ES_EVENT_TYPE_AUTH_KEXTLOAD.rawValue : "AUTH_KEXTLOAD",
    ES_EVENT_TYPE_AUTH_MMAP.rawValue : "AUTH_MMAP",
    ES_EVENT_TYPE_AUTH_MPROTECT.rawValue : "AUTH_MPROTECT",
    ES_EVENT_TYPE_AUTH_MOUNT.rawValue : "AUTH_MOUNT",
    ES_EVENT_TYPE_AUTH_RENAME.rawValue : "AUTH_RENAME",
    ES_EVENT_TYPE_AUTH_SIGNAL.rawValue : "AUTH_SIGNAL",
    ES_EVENT_TYPE_AUTH_UNLINK.rawValue : "AUTH_UNLINK",
    ES_EVENT_TYPE_NOTIFY_EXEC.rawValue : "NOTIFY_EXEC",
    ES_EVENT_TYPE_NOTIFY_OPEN.rawValue : "NOTIFY_OPEN",
    ES_EVENT_TYPE_NOTIFY_FORK.rawValue : "NOTIFY_FORK",
    ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue : "NOTIFY_CLOSE",
    ES_EVENT_TYPE_NOTIFY_CREATE.rawValue : "NOTIFY_CREATE",
    ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA.rawValue : "NOTIFY_EXCHANGEDATA",
    ES_EVENT_TYPE_NOTIFY_EXIT.rawValue : "NOTIFY_EXIT",
    ES_EVENT_TYPE_NOTIFY_GET_TASK.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_KEXTLOAD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LINK.rawValue : "NOTIFY_LINK",
    ES_EVENT_TYPE_NOTIFY_MMAP.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_MPROTECT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_MOUNT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_UNMOUNT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_RENAME.rawValue : "NOTIFY_RENAME",
    ES_EVENT_TYPE_NOTIFY_SETATTRLIST.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETEXTATTR.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETFLAGS.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETOWNER.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SIGNAL.rawValue : "NOTIFY_SIGNAL",
    ES_EVENT_TYPE_NOTIFY_UNLINK.rawValue : "NOTIFY_UNLINK",
    ES_EVENT_TYPE_NOTIFY_WRITE.rawValue : "NOTIFY_WRITE",
    ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE.rawValue : "AUTH_FILE_PROVIDER_MATERIALIZE",
    ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE.rawValue : "",
    ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE.rawValue : "AUTH_FILE_PROVIDER_UPDATE",
    ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE.rawValue : "",
    ES_EVENT_TYPE_AUTH_READLINK.rawValue : "AUTH_READLINK",
    ES_EVENT_TYPE_NOTIFY_READLINK.rawValue : "NOTIFY_READLINK",
    ES_EVENT_TYPE_AUTH_TRUNCATE.rawValue : "AUTH_TRUNCATE",
    ES_EVENT_TYPE_NOTIFY_TRUNCATE.rawValue : "",
    ES_EVENT_TYPE_AUTH_LINK.rawValue : "AUTH_LINK",
    ES_EVENT_TYPE_NOTIFY_LOOKUP.rawValue : "",
    ES_EVENT_TYPE_AUTH_CREATE.rawValue : "AUTH_CREATE",
    ES_EVENT_TYPE_AUTH_SETATTRLIST.rawValue : "AUTH_SETATTRLIST",
    ES_EVENT_TYPE_AUTH_SETEXTATTR.rawValue : "AUTH_SETEXTATTR",
    ES_EVENT_TYPE_AUTH_SETFLAGS.rawValue : "AUTH_SETFLAGS",
    ES_EVENT_TYPE_AUTH_SETMODE.rawValue : "AUTH_SETMODE",
    ES_EVENT_TYPE_AUTH_SETOWNER.rawValue : "AUTH_SETOWNER",
    // The following events are available beginning in macOS 10.15.1
    ES_EVENT_TYPE_AUTH_CHDIR.rawValue : "AUTH_CHDIR",
    ES_EVENT_TYPE_NOTIFY_CHDIR.rawValue : "",
    ES_EVENT_TYPE_AUTH_GETATTRLIST.rawValue : "AUTH_GETATTRLIST",
    ES_EVENT_TYPE_NOTIFY_GETATTRLIST.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_STAT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_ACCESS.rawValue : "",
    ES_EVENT_TYPE_AUTH_CHROOT.rawValue : "AUTH_CHROOT",
    ES_EVENT_TYPE_NOTIFY_CHROOT.rawValue : "",
    ES_EVENT_TYPE_AUTH_UTIMES.rawValue : "AUTH_UTIMES",
    ES_EVENT_TYPE_NOTIFY_UTIMES.rawValue : "",
    ES_EVENT_TYPE_AUTH_CLONE.rawValue : "AUTH_CLONE",
    ES_EVENT_TYPE_NOTIFY_CLONE.rawValue : "NOTIFY_CLONE",
    ES_EVENT_TYPE_NOTIFY_FCNTL.rawValue : "",
    ES_EVENT_TYPE_AUTH_GETEXTATTR.rawValue : "AUTH_GETEXTATTR",
    ES_EVENT_TYPE_NOTIFY_GETEXTATTR.rawValue : "",
    ES_EVENT_TYPE_AUTH_LISTEXTATTR.rawValue : "AUTH_LISTEXTATTR",
    ES_EVENT_TYPE_NOTIFY_LISTEXTATTR.rawValue : "",
    ES_EVENT_TYPE_AUTH_READDIR.rawValue : "AUTH_READDIR",
    ES_EVENT_TYPE_NOTIFY_READDIR.rawValue : "",
    ES_EVENT_TYPE_AUTH_DELETEEXTATTR.rawValue : "AUTH_DELETEEXTATTR",
    ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR.rawValue : "",
    ES_EVENT_TYPE_AUTH_FSGETPATH.rawValue : "AUTH_FSGETPATH",
    ES_EVENT_TYPE_NOTIFY_FSGETPATH.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_DUP.rawValue : "",
    ES_EVENT_TYPE_AUTH_SETTIME.rawValue : "AUTH_SETTIME",
    ES_EVENT_TYPE_NOTIFY_SETTIME.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_UIPC_BIND.rawValue : "",
    ES_EVENT_TYPE_AUTH_UIPC_BIND.rawValue : "AUTH_UIPC_BIND",
    ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT.rawValue : "",
    ES_EVENT_TYPE_AUTH_UIPC_CONNECT.rawValue : "AUTH_UIPC_CONNECT",
    ES_EVENT_TYPE_AUTH_EXCHANGEDATA.rawValue : "AUTH_EXCHANGEDATA",
    ES_EVENT_TYPE_AUTH_SETACL.rawValue : "AUTH_SETACL",
    ES_EVENT_TYPE_NOTIFY_SETACL.rawValue : "",
    // The following events are available beginning in macOS 10.15.4
    ES_EVENT_TYPE_NOTIFY_PTY_GRANT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_PTY_CLOSE.rawValue : "",
    ES_EVENT_TYPE_AUTH_PROC_CHECK.rawValue : "AUTH_PROC_CHECK",
    ES_EVENT_TYPE_NOTIFY_PROC_CHECK.rawValue : "",
    ES_EVENT_TYPE_AUTH_GET_TASK.rawValue : "AUTH_GET_TASK",
    // The following events are available beginning in macOS 11.0
    ES_EVENT_TYPE_AUTH_SEARCHFS.rawValue : "AUTH_SEARCHFS",
    ES_EVENT_TYPE_NOTIFY_SEARCHFS.rawValue : "",
    ES_EVENT_TYPE_AUTH_FCNTL.rawValue : "AUTH_FCNTL",
    ES_EVENT_TYPE_AUTH_IOKIT_OPEN.rawValue : "AUTH_IOKIT_OPEN",
    ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME.rawValue : "AUTH_PROC_SUSPEND_RESUME",
    ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_TRACE.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE.rawValue : "",
    ES_EVENT_TYPE_AUTH_REMOUNT.rawValue : "AUTH_REMOUNT",
    ES_EVENT_TYPE_NOTIFY_REMOUNT.rawValue : "",
    // The following events are available beginning in macOS 11.3
    ES_EVENT_TYPE_AUTH_GET_TASK_READ.rawValue : "AUTH_GET_TASK_READ",
    ES_EVENT_TYPE_NOTIFY_GET_TASK_READ.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT.rawValue : "",
    // The following events are available beginning in macOS 12.0
    ES_EVENT_TYPE_NOTIFY_SETUID.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETGID.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETEUID.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETEGID.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETREUID.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SETREGID.rawValue : "",
    ES_EVENT_TYPE_AUTH_COPYFILE.rawValue : "AUTH_COPYFILE",
    ES_EVENT_TYPE_NOTIFY_COPYFILE.rawValue : "NOTIFY_COPYFILE",
    // The following events are available beginning in macOS 13.0
    ES_EVENT_TYPE_NOTIFY_AUTHENTICATION.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE.rawValue : "",
    // The following events are available beginning in macOS 14.0
    ES_EVENT_TYPE_NOTIFY_PROFILE_ADD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SU.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_SUDO.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP.rawValue : "",
    ES_EVENT_TYPE_NOTIFY_XPC_CONNECT.rawValue : ""
]
