

import Foundation
import EndpointSecurity
import OSLog
import System
import CUPS

class LabPrintingBlockJob : LabESClientListenerProtocol {
    
    var subcribeEvents: [es_event_type_t] = []
    var labEsClient : LabESClient? = nil
    var cupsProcesses : Dictionary<pid_t, String> = [:]
    private let syncQueue = DispatchQueue(label: "sync queue")
    static let sharedInstance = LabPrintingBlockJob()
    var ticsPerSecond : UInt64 = 0
    var clockTimebase : mach_timebase_info_data_t = mach_timebase_info_data_t()

    init() {
        self.subcribeEvents = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_EXEC
//            ES_EVENT_TYPE_AUTH_CLONE ,
//            ES_EVENT_TYPE_AUTH_CLONE ,
//            ES_EVENT_TYPE_AUTH_CREATE,
//            ES_EVENT_TYPE_AUTH_RENAME,
//            ES_EVENT_TYPE_AUTH_UNLINK,
//            ES_EVENT_TYPE_AUTH_SIGNAL,
//            ES_EVENT_TYPE_AUTH_EXCHANGEDATA
        ]
        self.labEsClient = LabESClient(listener: self, name: "Printing Block Job")
    }
    
    func start() -> Bool {
        clockTimebase = mach_timebase_info();
        mach_timebase_info(&clockTimebase);
        ticsPerSecond = UInt64( Double(1e9) / (Double(clockTimebase.numer) / Double(clockTimebase.denom)))

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
        
        switch (message.pointee.event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            if isCupsBackendOrFilterProcess(process: message.pointee.event.exec.target) {
                
                let procs1 = getProcessTree(process: message.pointee.process)
                let procs2 = getProcessTree(process: message.pointee.event.exec.target)

                let args = collectExecArgs(message: message)

                os_log("EVENT:%{public}s %{public}s TARGET[%{public}s] args:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, procs1, procs2, args)

                if isCupsBackendProcess(process: message.pointee.event.exec.target) {
                    let argsArray = collectExecArgsArray(message: message)
                    os_log("EVENT:%{public}s BACKEND JobId:%{public}s args-count:%d", ESEventTypes[message.pointee.event_type.rawValue]!, argsArray[1], argsArray.count)
                    
//                    let jobID = Int32(argsArray[1])
//                    let dest = cups_dest_t()//name: "", instance: "", is_default: 0, num_options: 0, options: NULL)
//                    let http = http_t()
                                        
//                    let status = cupsCancelJob("Brother_HL_1210W_series", jobID!);
//                    os_log("EVENT:%{public}s BACKEND CANCELLED JOB status:%d JobId:%{public}s args-count:%d", ESEventTypes[message.pointee.event_type.rawValue]!, status, argsArray[1], argsArray.count)
//                    let status = cupsCancelDestJob(NULL, dest.instance, jobID);

                }
                
                syncQueue.sync {
                    let cupsProcPid = audit_token_to_pid(message.pointee.event.exec.target.pointee.audit_token)
                    cupsProcesses[cupsProcPid] = args
                    os_log("EVENT '%{public}s' target-proc:'%{public}s' args:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.event.exec.target.pointee.executable.pointee.path.data)), args)
                }
            }
            break
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            if isCupsFilterProcess(process: message.pointee.process) {
                syncQueue.sync {
                    _ = cupsProcesses.removeValue(forKey: audit_token_to_pid(message.pointee.process.pointee.audit_token))
                }
            }
            break
        default:
            break;
        }
        
        
    }
    
    func handleAuth(message : UnsafePointer<es_message_t>) -> Void {
        
        switch (message.pointee.event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
            if isCupsBackendProcess(process: message.pointee.event.exec.target) {
                
                let deadline = message.pointee.deadline;
                let deadline_nanos = (deadline * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)
                let time_now_tics = mach_absolute_time();
                let time_now_nanos = (time_now_tics * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)
                let deadline_delta_nano = deadline_nanos - time_now_nanos
                let deadline_delta_secs = deadline_delta_nano/UInt64(1e9);
                
                let argsArray = collectExecArgsArray(message: message)
                let jobID = Int32(argsArray[1])
                os_log("EVENT:%{public}s BACKEND JobId:%d args-count:%d timeout(s):%d", ESEventTypes[message.pointee.event_type.rawValue]!, jobID!, argsArray.count, deadline_delta_secs)
                
                let isThePrinter = true
                if (isThePrinter) {
                    es_retain_message(message)
                    DispatchQueue.global().async { [self] in
//                        let dest = cups_dest_t()//name: "", instance: "", is_default: 0, num_options: 0, options: NULL)
//                        let http = http_t()
                              
                        let status = cupsCancelJob("Brother_HL_1210W_series", jobID!);
                        // let status = cupsCancelDestJob(NULL, dest.instance, jobID); difficult
                        sleep(1)
                        os_log("EVENT:%{public}s BACKEND CANCELLED JOB:%d status:%d JobId:%{public}s args-count:%d", ESEventTypes[message.pointee.event_type.rawValue]!, jobID!, status, argsArray[1], argsArray.count)
                        es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
                        es_release_message(message)
                    }
                } else {
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
                }
            } else if isCupsFilterProcess(process: message.pointee.event.exec.target) {
                let argsArray = collectExecArgsArray(message: message)
                let jobID = Int32(argsArray[1])
//                os_log("EVENT:%{public}s FILTER CANCELLED JOB:%d  args-count:%d", ESEventTypes[message.pointee.event_type.rawValue]!, jobID!, argsArray.count)
                
                let isThePrinter = true
                if (isThePrinter) {
                    es_retain_message(message)
                    DispatchQueue.global().async { [self] in
//                        let dest = cups_dest_t()//name: "", instance: "", is_default: 0, num_options: 0, options: NULL)
//                        let http = http_t()
                              
                        let status = cupsCancelJob("Brother_HL_1210W_series", jobID!);
                        // let status = cupsCancelDestJob(NULL, dest.instance, jobID); difficult
                        sleep(1)
                        os_log("EVENT:%{public}s FILTER CANCELLED JOB:%d status:%d JobId:%{public}s args-count:%d", ESEventTypes[message.pointee.event_type.rawValue]!, jobID!, status, argsArray[1], argsArray.count)
                        es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
                        es_release_message(message)
                    }
                } else {
                    es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
                }
                
//                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_DENY, false)
            } else {
                es_respond_auth_result((labEsClient?.esClientPtr)!, message, ES_AUTH_RESULT_ALLOW, false)
            }

            if isCupsBackendOrFilterProcess(process: message.pointee.event.exec.target) {
                syncQueue.sync {
                    let args = collectExecArgs(message: message)
                    let cupsProcPid = audit_token_to_pid(message.pointee.event.exec.target.pointee.audit_token)
                    cupsProcesses[cupsProcPid] = args
                    os_log("EVENT '%{public}s' proc:'%{public}s' args:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.event.exec.target.pointee.executable.pointee.path.data)), args)
                }
            } 
            break;

        case ES_EVENT_TYPE_AUTH_OPEN:
            
            // LAST SECURITY STEP, it should not arrive here, the blocking of backends and filters should do the printing blocking.

            let cupsFilePath = FilePath(String(cString: UnsafePointer(message.pointee.event.open.file.pointee.path.data)))

            os_log("EVENT '%{public}s' proc:'%{public}s' file:'%{public}s'", ESEventTypes[message.pointee.event_type.rawValue]!, String(cString: UnsafePointer(message.pointee.process.pointee.executable.pointee.path.data)), cupsFilePath.string)

            if isCupsBackendOrFilterProcess(process: message.pointee.process) && isCupsDataFile(filePath: cupsFilePath) {
                os_log("PRINT EVENT FROM CUPS. file:'%{public}s' ", cupsFilePath.string)
                syncQueue.sync {
                    let cupsPid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
                    let args = cupsProcesses[cupsPid]
                    os_log("PRINT EVENT with file:'%{public}s' proc_args:'%{public}s'", cupsFilePath.string, args!)
                }
                es_respond_flags_result((labEsClient?.esClientPtr)!, message, 0, false) // DENY
            } else {
                es_respond_flags_result((labEsClient?.esClientPtr)!, message, UINT32_MAX, false)
            }
            break
        default:
            break
        }
        
    }
    
    // MARK: Private
    
    private func isCupsDataFile(filePath: FilePath) -> Bool {
        return filePath.string.starts(with: "/private/var/spool/cups/d") // we can't comapre it with FilePAth because /d is not full component!
    }


}
