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

class LabAntitamperingJob : LabESClientListenerProtocol {
    
    var subcribeEvents: [es_event_type_t] = []
    var labEsClient : LabESClient? = nil
    static let sharedInstance = LabAntitamperingJob()
    
    init() {
        self.subcribeEvents = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CLONE ,
            ES_EVENT_TYPE_AUTH_CLONE ,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_SIGNAL,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA
        ]
        self.labEsClient = LabESClient(listener: self, name: "Antitampering Job")
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
                    let procs1 = getProcessTree(process: message.pointee.process)
                    let procs2 = getProcessTree(process: message.pointee.event.exec.target)

                    os_log("EVENT:%{public}s DENIED args:'%{public}s' %{public}s TARGET[%{public}s]", ESEventTypes[message.pointee.event_type.rawValue]!, args, procs1, procs2)
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                    return
                }
            }
            
            // do not allow systemextensionsctl on our extensions
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

            // allow calling ZEP activate/deactivate only if parent or resp is Zscaler
            if (isZEPProcess(process: targetProc)) {
                if !isProcessTrusted(auditToken: message.pointee.process.pointee.parent_audit_token) && !isResponsibleProcessTrusted(process: targetProc) {
                    let args = collectExecArgs(message: message)
                    os_log("EVENT:%{public}s DENIED args:'%{public}s' signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, args, String(cString: UnsafePointer(targetProc.pointee.signing_id.data)))
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
                    return
                } else {
                    let args = collectExecArgs(message: message)
                    os_log("EVENT:%{public}s ALLOWED args:'%{public}s' signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, args, String(cString: UnsafePointer(targetProc.pointee.signing_id.data)))
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
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
        case ES_EVENT_TYPE_AUTH_OPEN: do {
            // There are so many processes that open our files : com.apple.mdworker_shared, com.apple.sharedfilelistd, com.apple.CodeSigningHelper, com.apple.mds, com.apple.endpointsecurityd, pid=1 ...
            // We have to let pid=1 to open the file, "com.apple.xpc.proxy" as well, the icons daemons too !
            // How about allowing all opens ?
            // IMPORTANT :
            //      launchd pid 1 is opening out daemons plists, we have to allow it
            //      FILEOP:ES_EVENT_TYPE_AUTH_OPEN proc:com.apple.xpc.launchd pid:1  rpid:1 ppid:0 uid:0 file1:'/Library/Application Support/Zscaler/ZDP/LaunchPlists/com.zscaler.zdp.esd.plist' file2:''
            
            /*
             filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.open.file.pointee.path.data)))
             // IMPORTANT : launchd pid 1 is opening out daemons plists, we have to allow it
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
             */
            
            
            // make it simpler allow all read-only modes, NO ! we dont have to let read some files, like the sdk libs
            // allow modify open only to trusted apps
            if (hasFileModificationFlags(fflag: message.pointee.event.open.fflag)) {

                filePath = FilePath(String(cString: UnsafePointer(message.pointee.event.open.file.pointee.path.data)))
                if isFileOperationInZDPDeployment(filePath: filePath) && isResponsibleProcessTrusted(process: message.pointee.process) == false {
                    
                    // we have to let certain open for modification like file:'/Library/Application Support/Zscaler/Logs/com.zscaler.UPMServiceController_stdout.log' signing_id:com.apple.xpc.proxy
                    if String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)) != "com.apple.xpc.proxy" {
                        
                        os_log("EVENT:%{public}s DENIED pid:%d ppid:%d rpid:%d file:'%{public}s' signing_id:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, audit_token_to_pid(message.pointee.process.pointee.audit_token), audit_token_to_pid(message.pointee.process.pointee.parent_audit_token),  audit_token_to_pid(message.pointee.process.pointee.responsible_audit_token), filePath.string, String(cString: UnsafePointer(message.pointee.process.pointee.signing_id.data)))
                        es_respond_flags_result((labEsClient?.esClientPtr)!, message, 0, false)
                    }
                    break
                }
            }
            es_respond_flags_result((labEsClient?.esClientPtr)!, message, UINT32_MAX, false)
            break
        }
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
                let procs = getProcessTree(process: message.pointee.process)
                os_log("EVENT:%{public}s DENIED %{public}s file:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, procs, filePath.string)
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
            } else if (isFileOperationInZEPSysex(filePath: filePath)) {
                let procs = getProcessTree(process: message.pointee.process)
                os_log("EVENT:%{public}s DENIED %{public}s file:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, procs, filePath.string)
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
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            let sendingProcess = message.pointee.process
            let targetProcess = message.pointee.event.signal.target
            
            var authResult = ES_AUTH_RESULT_ALLOW
            if (isZscalerProcess(process: targetProcess)) {
                if isZscalerProcess(process: sendingProcess) {
                    // allow
                } else if isLaunchdProcess(process: sendingProcess) && sendingProcess.pointee.ppid == 0 {
                    // allow. the launchctl from the disable scripts executed by ZCC arrive here.  no rpid !
                } else if isAppleProcess(process: sendingProcess) && isLaunchdProcess(process: sendingProcess) && audit_token_to_pid(sendingProcess.pointee.audit_token) == audit_token_to_pid(sendingProcess.pointee.responsible_audit_token) { // spinlock like
                    // allow launchd or launchservicesd
                } else {
                    os_log("EVENT:%{public}s DENIED sig:%d from:%{public}s to:%{public}s", ESEventTypes[message.pointee.event_type.rawValue]!, message.pointee.event.signal.sig, String(cString: UnsafePointer(sendingProcess.pointee.signing_id.data)), String(cString: UnsafePointer(targetProcess.pointee.signing_id.data)))
                    authResult = ES_AUTH_RESULT_DENY
                }
            }
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, authResult, false)

            break;
        default:
            es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }
    
    // MARK: Private

    
    private func isFileOperationInZDPDeployment(filePath: FilePath) -> Bool {
        return filePath.starts(with: "/Library/Application Support/Zscaler/") // ZDP or the whole Zscaler ?
    }

    private func isFileOperationInZEPSysex(filePath: FilePath) -> Bool {
        return filePath.starts(with: "/Library/SystemExtensions/") && filePath.string.contains("com.zscaler.zep.at.systemextension")
    }

    
    func hasFileModificationFlags( fflag : Int32) -> Bool
    {
        let flags = FWRITE|O_APPEND|O_EXLOCK|O_SHLOCK|O_CREAT|O_TRUNC;
        return ((fflag & flags) != 0);
    }
    
    
}
