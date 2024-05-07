//
//  LabAncestors.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 02/05/2024.
//

import Foundation
import EndpointSecurity
import OSLog
import System

class LabAncestorsJob : LabESClientListenerProtocol {
    
    var subcribeEvents: [es_event_type_t] = []
    var labEsClient : LabESClient? = nil
    static let sharedInstance = LabAncestorsJob()
//    var installerProcess : es_process_t? = nil
    
    init() {
        self.subcribeEvents = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CLONE ,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA
//            ES_EVENT_TYPE_NOTIFY_FORK, 
//            ES_EVENT_TYPE_NOTIFY_EXEC,
//            ES_EVENT_TYPE_NOTIFY_UNLINK, 
//            ES_EVENT_TYPE_NOTIFY_CREATE,
//            ES_EVENT_TYPE_NOTIFY_OPEN
        ]
        self.labEsClient = LabESClient(listener: self, name: "Ancestors")
    }
    
    func start() -> Bool {
        if labEsClient == nil {
            return false
        }
        return labEsClient!.start()
    }
    
    func stop() -> Bool {
        if labEsClient == nil {
            return false
        }
        return labEsClient!.stop()
    }
    
    // MARK: Protocol
    
    func handleNotify(message : UnsafePointer<es_message_t>) -> Void {
        
        var process = message.pointee.process
        var parentProcessPath = ""
        if (message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
            parentProcessPath = String(cString: UnsafePointer(process.pointee.executable.pointee.path.data))
            process = message.pointee.event.fork.child
        }
        
        var args = ""
        if (message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
            args = collectExecArgs(message: message)
            parentProcessPath = String(cString: UnsafePointer(process.pointee.executable.pointee.path.data))
            process = message.pointee.event.exec.target
        }
        
        let procPathString = String(cString: UnsafePointer(process.pointee.executable.pointee.path.data))
        let pid = audit_token_to_pid(process.pointee.audit_token)
        let rpid = audit_token_to_pid(process.pointee.responsible_audit_token)
        let ppid = process.pointee.ppid
        let oppid = process.pointee.original_ppid

        var filePath = ""
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            if message.pointee.event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                filePath = String(cString: UnsafePointer(message.pointee.event.create.destination.existing_file.pointee.path.data))
            } else {
                filePath = String(cString: UnsafePointer(message.pointee.event.create.destination.new_path.filename.data))
            }
            break
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            filePath = String(cString: UnsafePointer(message.pointee.event.open.file.pointee.path.data))
            break
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            filePath = String(cString: UnsafePointer(message.pointee.event.unlink.target.pointee.path.data))
            break
        default:
            break
        }
            
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
        os_log("EVENT:%{public}s  proc_path:'%{public}s' parent_proc_path:'%{public}s' pid:%d rpid:%d rpath:'%{public}s' ppid:%d ppath:'%{public}s' oppid:%d args:'%{public}s' file:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, procPathString, parentProcessPath, pid, rpid, rpath, ppid, ppath, oppid, args, filePath)
    }
    
    func handleAuth(message : UnsafePointer<es_message_t>) -> Void {
        
//        os_log("EVENT:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!)

        // Allow anything coming from Zscaler
        if isZscalerProcess(process: message.pointee.process) || isZscalerResponsibleProcess(process: message.pointee.process) {
            if (message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN)  {
                es_respond_flags_result((labEsClient?.esClientPtr)!, message, UINT32_MAX, true)
            }  else {
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, true)
            }
            return
        }
        
        var filePath = FilePath()
        
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            
            let targetProc = message.pointee.event.exec.target
            
            // do not allow launchctl on our daemons
            if (targetProc.pointee.is_platform_binary &&
                String(cString: UnsafePointer(targetProc.pointee.signing_id.data)) == String("com.apple.xpc.launchctl"))  &&
                !isResponsibleProcessTrusted(process: targetProc) {
                
                let args = collectExecArgs(message: message)

                os_log("EVENT:%{public}s args:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, args)
                
                if args.contains("com.zscaler.zdp.agent") || args.contains("com.zscaler.zdp.pd") || args.contains("com.zscaler.zdp.esd") {
                    os_log("EVENT:%{public}s DENIED args:'%{public}s' signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, args, String(cString: UnsafePointer(targetProc.pointee.signing_id.data)))
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                    return
                }
            }
            
            if (targetProc.pointee.is_platform_binary &&
                String(cString: UnsafePointer(targetProc.pointee.signing_id.data)) == String("com.apple.systemextensionsctl"))  &&
                !isResponsibleProcessTrusted(process: targetProc) {
                
                let args = collectExecArgs(message: message)

                os_log("EVENT:%{public}s args:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, args)

                if args.contains("com.zscaler.zep.at") {
                    os_log("EVENT:%{public}s DENIED args:'%{public}s' signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, args, String(cString: UnsafePointer(targetProc.pointee.signing_id.data)))
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                    return
                }
            }
            
            // Find if ZDP installer launched. NOT necesary ! The installer's file-operations responsible is the App from where it was launched,
//            if (targetProc.pointee.is_platform_binary &&
//                String(cString: UnsafePointer(targetProc.pointee.signing_id.data)) == String("com.apple.installer")) &&
//                isResponsibleProcessTrusted(process: targetProc) {
//                
//                let args = collectExecArgs(message: message)
//                if args.contains("-pkg") && args.contains("ZDP-mac-")  { // quick hack
//                    
//                    installerProcess?.audit_token = targetProc.pointee.audit_token
//                    
//                    os_log("EVENT:%{public}s ZDP PKG install start by proc pid:%d  id:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, audit_token_to_pid(targetProc.pointee.audit_token), String(cString: UnsafePointer(targetProc.pointee.signing_id.data)))
//                }
//
//            }
                        
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            break
        case ES_EVENT_TYPE_AUTH_CLONE:
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.clone.source.pointee.path.data)))
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                break
            }
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.clone.target_dir.pointee.path.data)))
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                break
            }
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            break
        case ES_EVENT_TYPE_AUTH_OPEN:
            // There are so many processes that open our files : com.apple.mdworker_shared, com.apple.sharedfilelistd, com.apple.CodeSigningHelper, com.apple.mds, com.apple.endpointsecurityd, pid=1 ...
            // We have to let pid=1 to open the file, "com.apple.xpc.proxy" as well, the icons daemons too !
            // How about allowing all opens ?
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.open.file.pointee.path.data)))
            // launchd pid 1 is opening out daemons plists, we have to allow it
            if  !(isAppleProcess(process: message.pointee.process) && (message.pointee.process.pointee.ppid == 1)) &&  // we think that processes from apple that have ppid == 1 are processes that can open our files
                !isLaunchdProcess(process: message.pointee.process) &&
                isFileOperationInZDPDeployment(filePath: filePath) &&
                isResponsibleProcessTrusted(process: message.pointee.process) == false &&
                String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)) != "com.apple.endpointsecurityd" &&
                String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)) != "com.apple.xpc.proxy"
            {
                os_log("EVENT:%{public}s DENIED pid:%d ppid:%d rpid:%d file:'%{public}s' signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, audit_token_to_pid(message.pointee.process.pointee.audit_token), audit_token_to_pid(message.pointee.process.pointee.parent_audit_token),  audit_token_to_pid(message.pointee.process.pointee.responsible_audit_token), filePath.string, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_flags_result((labEsClient?.esClientPtr)!, message, 0, false)
            } else {
                es_respond_flags_result((labEsClient?.esClientPtr)!, message, UINT32_MAX, false)
            }
            break
        case ES_EVENT_TYPE_AUTH_CREATE:
            if message.pointee.event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.create.destination.existing_file.pointee.path.data)))
            } else {
                filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.create.destination.new_path.filename.data)))
            }
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
            } else {
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            }
            break
        case ES_EVENT_TYPE_AUTH_UNLINK:
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.unlink.target.pointee.path.data)))
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
            } else {
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            }
            break
        case ES_EVENT_TYPE_AUTH_RENAME:
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.rename.source.pointee.path.data)))
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                break
            }
            if message.pointee.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.rename.destination.existing_file.pointee.path.data)))
            } else {
                filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.rename.destination.new_path.dir.pointee.path.data)))
            }
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                break
            }
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            break
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.exchangedata.file1.pointee.path.data)))
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                break
            }
            filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.exchangedata.file2.pointee.path.data)))
            if isFileOperationInZDPDeployment(filePath: filePath) && !isResponsibleProcessTrusted(process: message.pointee.process) {
                os_log("EVENT:%{public}s DENIED signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                break
            }
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            break
        default:
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }
    
    // MARK: Private
    private func collectExecArgs(message: UnsafePointer<es_message_t>) -> String
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
    
    private func isFileOperationInZDPDeployment(filePath: FilePath) -> Bool {
        return filePath.starts(with: "/Library/Application Support/Zscaler/")
    }
    
    private func isAppleProcess(process: UnsafePointer<es_process_t>) -> Bool {

        return process.pointee.is_platform_binary
    }
    
    private func isLaunchdProcess(process: UnsafePointer<es_process_t>) -> Bool {

        return audit_token_to_pid(process.pointee.audit_token) == 1
    }


    private func isZscalerProcess(process: UnsafePointer<es_process_t>) -> Bool {

        if  process.pointee.team_id.data != nil && String( cString: process.pointee.team_id.data) == "PCBCQZJ7S7" {
            return true
        }
        
        if String( cString: process.pointee.executable.pointee.path.data).starts(with: "/Library/Application Support/Zscaler/") { // quick hack
            return true
        }
            
        return false
    }
    
    private func isZscalerResponsibleProcess(process: UnsafePointer<es_process_t>) -> Bool {

        let responsiblePath = getProcessPath(pid: audit_token_to_pid(process.pointee.responsible_audit_token))
        
        if responsiblePath.starts(with: "/Library/Application Support/Zscaler/") { // quick hack
            return true
        }

        if responsiblePath.starts(with: "/Applications/Zscaler/") { // quick hack
            return true
        }

        return false
    }
    
    private func isProcessTrusted(process: UnsafePointer<es_process_t>) -> Bool {

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
    
    private func isResponsibleProcessTrusted(process: UnsafePointer<es_process_t>) -> Bool {

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
        
        if responsiblePath.contains("/Terminal.app/") { // ugly quick hack
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
    
    private func isAlive(targetPID :pid_t) -> Bool
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
    
    
}
