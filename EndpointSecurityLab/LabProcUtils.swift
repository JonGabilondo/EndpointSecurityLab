//
//  LabProcUtils.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 15/05/2024.
//

import Foundation
import EndpointSecurity
import System

func getProcessPath(pid : pid_t) -> String {
    
    let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
    defer {
            pathBuffer.deallocate()
        }
    
    var procPath = ""
    let pathLength = proc_pidpath(pid, pathBuffer, UInt32(MAXPATHLEN))
    if pathLength > 0 {
        procPath = String(cString: pathBuffer)
    }
    
    return procPath
}


func getProcessTree(process: UnsafePointer<es_process_t>) -> String {
    let procPath = String(cString: UnsafePointer(process.pointee.executable.pointee.path.data))
    let pid = audit_token_to_pid(process.pointee.audit_token)
    let ppid = process.pointee.ppid
    let oppid = process.pointee.original_ppid
    let rpid = audit_token_to_pid(process.pointee.responsible_audit_token)
    let pb = process.pointee.is_platform_binary
    
    var ppath = ""
    if ppid != 1 {
        ppath = getProcessPath(pid: ppid)
    }

    var rpath = ""
    if rpid == ppid {
        rpath = ppath
    } else {
        rpath = getProcessPath(pid: rpid)
    }

    return String(format: "Proc[pid:\(pid) path:\(procPath)] Parent[pid:\(ppid) ppath:\(ppath) pb:\(pb)] Resp[pid:\(rpid) rpath:\(rpath)]", arguments: [])
}

func collectExecArgs(message: UnsafePointer<es_message_t>) -> String
{
    var argc : UInt32 = 0
    withUnsafePointer(to: message.pointee.event.exec) { pointer in
        argc = es_exec_arg_count(pointer)
    }
     
    var argv : [String] = []
    for i in 0..<argc { //argv[0] - process name
       
        var param : es_string_token_t = es_string_token_t()
        withUnsafePointer(to: message.pointee.event.exec) { pointer in
            param = es_exec_arg(pointer, i)
        }
        let arg : String = String(cString: UnsafePointer(param.data))
        argv.append(arg)
    }
    
    var cmd = ""
    if (argc >= 1)
    {
        argv.forEach { arg in
            cmd.append(arg)
            cmd.append(" ")
        }
    }

    return cmd;
}

func collectExecArgsArray(message: UnsafePointer<es_message_t>) -> [String]
{
    var argc : UInt32 = 0
    withUnsafePointer(to: message.pointee.event.exec) { pointer in
        argc = es_exec_arg_count(pointer)
    }
     
    var argv : [String] = []
    for i in 0..<argc { //argv[0] - process name
       
        var param : es_string_token_t = es_string_token_t()
        withUnsafePointer(to: message.pointee.event.exec) { pointer in
            param = es_exec_arg(pointer, i)
        }
        let arg : String = String(cString: UnsafePointer(param.data))
        argv.append(arg)
    }

    return argv;
}


func isAppleProcess(process: UnsafePointer<es_process_t>) -> Bool {

    return process.pointee.is_platform_binary
}

func isLaunchdProcess(process: UnsafePointer<es_process_t>) -> Bool {

    return audit_token_to_pid(process.pointee.audit_token) == 1  || // sbin/launchd
            (process.pointee.signing_id.data != nil && String( cString: process.pointee.signing_id.data) == "com.apple.launchservicesd")
}

func isZscalerProcess(process: UnsafePointer<es_process_t>) -> Bool {

    if  process.pointee.team_id.data != nil && String( cString: process.pointee.team_id.data) == "PCBCQZJ7S7" {
        return true
    }
    
    if String( cString: process.pointee.executable.pointee.path.data).starts(with: "/Library/Application Support/Zscaler/") { // quick hack
        return true
    }
        
    return false
}

func isZEPProcess(process: UnsafePointer<es_process_t>) -> Bool {

    if  process.pointee.signing_id.data != nil && String( cString: process.pointee.signing_id.data) == "com.zscaler.zep.app" {
        return true
    }
            
    return false
}

func isZscalerResponsibleProcess(process: UnsafePointer<es_process_t>) -> Bool {

    let responsiblePath = getProcessPath(pid: audit_token_to_pid(process.pointee.responsible_audit_token))
    
    if responsiblePath.starts(with: "/Library/Application Support/Zscaler/") { // quick hack
        return true
    }

    if responsiblePath.starts(with: "/Applications/Zscaler/") { // quick hack
        return true
    }

    return false
}

func isProcessTrusted(process: UnsafePointer<es_process_t>) -> Bool {

    if process.pointee.is_platform_binary {
        return true
    }
    
    if  process.pointee.team_id.data != nil && String( cString: process.pointee.team_id.data) == "PCBCQZJ7S7" {
        return true
    }
    
    if  process.pointee.signing_id.data != nil && String( cString: process.pointee.signing_id.data).starts(with: "com.apple.") { // quick hack
        return true
    }

    if String( cString: process.pointee.executable.pointee.path.data).starts(with: "/Library/Application Support/Zscaler/") { // quick hack
        return true
    }
        
    return false
}

func isProcessTrusted(auditToken: audit_token_t) -> Bool {

    let processPath = getProcessPath(pid: audit_token_to_pid(auditToken))
    
    if processPath.starts(with: "/Library/Application Support/Zscaler/") { // quick hack
        return true
    }

    if processPath.starts(with: "/Applications/Zscaler/") { // quick hack
        return true
    }

    if processPath.contains("EPSdkInvoke") { // quick hack
        return true
    }

    return false
}


func isResponsibleProcessTrusted(process: UnsafePointer<es_process_t>) -> Bool {

    // the responsible must be a Zscaler
    
//        let rpid = audit_token_to_pid(process.pointee.responsible_audit_token)
    
    let responsiblePath = getProcessPath(pid: audit_token_to_pid(process.pointee.responsible_audit_token))
    
    if responsiblePath.starts(with: "/Library/Application Support/Zscaler/") { // quick hack
        return true
    }

    if responsiblePath.starts(with: "/Applications/Zscaler/") { // quick hack
        return true
    }
    
    // ugly hacks !
    if responsiblePath.contains("/Finder.app/") { // ugly quick hack
        return true
    }
    
    if responsiblePath.contains("/Terminal.app/") { // allow Terminal.app to do launchctl
        return true
    }

    return false
    
//        if !isAlive(targetPID: rpid) {
//            os_log("PROCESS NOT ALIVE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
//            return false
//        }
    
//        return false
    
//        if installerProcess != nil {
//            if rpid == audit_token_to_pid(installerProcess!.audit_token) {
//                os_log("INSTALLER FILE OPERATION DETECTED !")
//                return true
//            }
//        }
                    
//        if responsibleApp == nil {
//            return false
//        }
//
//        if responsibleApp!.bundleIdentifier!.starts(with: "com.apple.finder") {
//            return true // it helps to have problems in the finder
//        }
//
//        if responsibleApp!.bundleIdentifier!.starts(with: "com.apple.Terminal") {
//            return true // Terminal will be the only process from where the installer will be allowed to run
//        }
//
//        let rpath = responsibleApp!.executableURL?.absoluteString ?? ""
//        return rpath.starts(with: "/Library/Application Support/Zscaler/") || rpath.starts(with: "/Applications/Zscaler/")
}

func isCupsFilterProcess(process: UnsafePointer<es_process_t>) -> Bool {
    
    let exeFilePath = FilePath(String(cString: UnsafePointer(process.pointee.executable.pointee.path.data)))
    
    return exeFilePath.starts(with: "/usr/libexec/cups/filter/")
}

func isCupsBackendProcess(process: UnsafePointer<es_process_t>) -> Bool {
    
    let exeFilePath = FilePath(String(cString: UnsafePointer(process.pointee.executable.pointee.path.data)))
    
    return exeFilePath.starts(with: "/usr/libexec/cups/backend/")
}

func isCupsBackendOrFilterProcess(process: UnsafePointer<es_process_t>) -> Bool {
    
    return isCupsFilterProcess(process: process) || isCupsBackendProcess(process: process)
}

func isProcessAlive(targetPID :pid_t) -> Bool
{
    //flag
    var isAlive = true
    
    //reset errno
    errno = 0
    
    //'management info base' array
    var mib : [Int32] = [0,0,0,0]
    
    //kinfo proc
    var procInfo = kinfo_proc()
    
    //try 'kill' with 0
    // ->no harm done, but will fail with 'ESRCH' if process is dead
    kill(targetPID, 0);
    
    //dead proc -> 'ESRCH'
    // ->'No such process'
    if(ESRCH == errno)
    {
        return false
    }
    
    //size
//        var sizes : size_t  = 0
    
    //init mib
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = targetPID;
    
    //init size
//        size = size(ofValue: procInfo)

    let sizeOfMib = MemoryLayout.size(ofValue: mib)
    let sizeOfMib2 = MemoryLayout.size(ofValue: mib)
    
    //get task's flags
    // ->allows to check for zombies
//        public func sysctl(_: UnsafeMutablePointer<Int32>!, _: u_int, _: UnsafeMutableRawPointer!, _: UnsafeMutablePointer<Int>!, _: UnsafeMutableRawPointer!, _: Int) -> Int32

    var size : Int = 0
    if(0 == sysctl(&mib, u_int(sizeOfMib/sizeOfMib2), &procInfo, &size, nil, 0))
    {
        //check for zombies
        if(( Int32(procInfo.kp_proc.p_stat) & SZOMB) == SZOMB)
        {
            isAlive = false
            return false
        }
    }
    
    return isAlive;
}

