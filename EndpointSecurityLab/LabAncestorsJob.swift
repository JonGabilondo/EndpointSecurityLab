//
//  LabAncestors.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 02/05/2024.
//

import Foundation
import EndpointSecurity
import OSLog

class LabAncestorsJob : LabESClientListenerProtocol {
    
    var subcribeEvents: [es_event_type_t] = []
    var labEsClient : LabESClient? = nil
    static let sharedInstance = LabAncestorsJob()
    
    init() {
        self.subcribeEvents = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK]
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
        let res = labEsClient!.stop()
        labEsClient = nil
        return res
    }
    
    // MARK: Protocol
    
    func handleNotify(message : UnsafePointer<es_message_t>) -> Void {
        
        let procPathString = String(cString: UnsafePointer(message.pointee.process.pointee.executable.pointee.path.data))
        let pid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
        let rpid = audit_token_to_pid(message.pointee.process.pointee.responsible_audit_token)
        let ppid = message.pointee.process.pointee.ppid
        let oppid = message.pointee.process.pointee.original_ppid

        os_log("PROC path:%s pid:%d rpid:%d ppid:%d oppid:%d", procPathString, pid, rpid, ppid, oppid)
    }
    
    func handleAuth(message : UnsafePointer<es_message_t>) -> Void {
        
    }
    
}
