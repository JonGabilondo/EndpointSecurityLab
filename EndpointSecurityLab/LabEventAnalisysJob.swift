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

class LabEventAnalisysJob : LabESClientListenerProtocol {
    
    var subcribeEvents: [es_event_type_t] = []
    var labEsClient : LabESClient? = nil
    static let sharedInstance = LabEventAnalisysJob()
    
    init() {
        self.subcribeEvents = [
            ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_UNLINK, 
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_OPEN
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
        
        var processesInfo = ""
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
        
        if (message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_SIGNAL) {
            
            // launchd (1) is sending signals to our procs on uninstall, they mustbe allowed
            
            // zdpd is sending signals to zdpclassifier, if sending process is zscaler process then allow it
            // EVENT:NOTIFY_SIGNAL 19 Proc[pid:35072 path:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd] Parent[pid:1 ppath:] Resp[pid:35072 rpath:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd] TARGET[Proc[pid:35095 path:/Library/Application Support/Zscaler/ZDP/bin/zdpclassifier] Parent[pid:35072 ppath:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd] Resp[pid:35072 rpath:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd]]
            
            // crash ?  allow if proc is aple's and ppid==1 ? and pid == rpid ?
            // EVENT:NOTIFY_SIGNAL Proc[pid:774 path:/usr/sbin/spindump] Parent[pid:1 ppath:] Resp[pid:774 rpath:/usr/sbin/spindump] TARGET[Proc[pid:28890 path:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd] Parent[pid:1 ppath:] Resp[pid:28890 rpath:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd]]
            
            // kill from terminal
            // EVENT:NOTIFY_SIGNAL Proc[pid:28988 path:/bin/kill] Parent[pid:28987 ppath:] Resp[pid:627 rpath:/Applications/iTerm.app/Contents/MacOS/iTerm2] TARGET[Proc[pid:28952 path:/Library/Application Support/Zscaler/ZDP/bin/zdpd.app/Contents/MacOS/zdpd] Parent[pid:1 ppath:] Resp[pid:28952 rpath:]]
            
            // on zccc dlp disable
            // EVENT:NOTIFY_SIGNAL Proc[pid:1 path:/sbin/launchd] Parent[pid:0 ppath:] Resp[pid:1 rpath:/sbin/launchd] TARGET[Proc[pid:33520 path:/Library/Application Support/Zscaler/ZDP/bin/zdpagent.app/Contents/MacOS/zdpagent] Parent[pid:1 ppath:] Resp[pid:33520 rpath:]]
            
            let process = message.pointee.process
            let str1 = getProcessTree(process: process)
            let str2 = getProcessTree(process: message.pointee.event.signal.target)
            os_log("EVENT:%{public}s %d %{public}s TARGET[%{public}s]", ESEventTypes[message.pointee.event_type.rawValue]!, message.pointee.event.signal.sig, str1, str2)
            return
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
            let process = message.pointee.process
            let str1 = getProcessTree(process: process)
            os_log("EVENT:%{public}s %{public}s file:%{public}s]", ESEventTypes[message.pointee.event_type.rawValue]!, str1, filePath)
            return
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
        

    }
    
    // MARK: Private
        

    
    private func isFileOperationInZDPDeployment(filePath: FilePath) -> Bool {
        return filePath.starts(with: "/Library/Application Support/Zscaler/")
    }
        
    
}
