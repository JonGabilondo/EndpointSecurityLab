//
//  LabAllAuthMetrics.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 26/03/2024.
//
import Foundation
import Cocoa
import EndpointSecurity
import OSLog
import Collections


struct EventData {
    var count: UInt64
    var min: UInt64
    var max: UInt64
}

typealias EventType = UInt32
var gEventsPerTypeRecord : OrderedDictionary<EventType, EventData> = [:]

public class LabAllAuthMetrics {
    
    static var esClientPtr: OpaquePointer? = nil
    static var pythonProcess: Process? = nil
    static let defaultLog = Logger()
    static var eventsCount = 0
    
    public static func start() {
        
        if !startEndpointSecurityClient() {
            return;
        }
    }
    
    static func stop() {
        if pythonProcess != nil && pythonProcess!.isRunning {
            pythonProcess!.terminationHandler = { (Process) -> Void in
                print("python process terminated")
            }
            pythonProcess!.terminate()
        }
        
        if (esClientPtr != nil) {
            es_delete_client(esClientPtr)
            esClientPtr = nil
        }
    }
    
    static func export() {
        
        do {
            var csvData = "Event, Count, Deadline-min, Deadline-max\n"
            
            for event in gEventsPerTypeRecord {
                csvData.append(String(format: "%@, %@, %@, %@\n", ESEventTypes[event.key]!, String(format: "%d", event.value.count), String(format: "%ld", event.value.min), String(format: "%ld", event.value.max)))
            }
            
            let fileManager = FileManager.default
            let userDirectory = try! fileManager.url (for: .userDirectory, in: .localDomainMask, appropriateFor: nil, create: false)
            let folderURL = userDirectory.appendingPathComponent("Shared/EndpointSecurityLab")
            if !fileManager.fileExists(atPath: folderURL.path) {
                do {
                    try fileManager.createDirectory(at: folderURL, withIntermediateDirectories: true, attributes: nil)
                } catch {
                    print("Couldn't create document directory", error)
                }
            }
            let fileURL = folderURL.appendingPathComponent("AuthMetrics.csv")
            if fileManager.fileExists(atPath: fileURL.path) {
                try fileManager.removeItem(atPath: fileURL.path)
            }
            print("csv file to create: '\(fileURL)'")
            try csvData.write(to: fileURL, atomically: true, encoding: .utf8)
            
            do {
                let openCSVProcess = Process()
                openCSVProcess.executableURL = URL(fileURLWithPath: "/bin/zsh")
                openCSVProcess.arguments = ["-c", "/usr/bin/open " + fileURL.path]

                try openCSVProcess.run()
                openCSVProcess.waitUntilExit()
                print("finished. termination status:\(openCSVProcess.terminationStatus) reason:\(openCSVProcess.terminationReason)")
            } catch {
                print("error opening csv file", error)
            }

        } catch {
            print("error creating csv file", error)
        }
    }
    
    
    // MARK: Private
    

    private static func handleClientMessage(client: OpaquePointer, message : UnsafePointer<es_message_t>) {
        
        eventsCount+=1

        var clockTimebase : mach_timebase_info_data_t = mach_timebase_info();
        mach_timebase_info(&clockTimebase);

        let deadline = message.pointee.deadline;
        let deadline_nanos = (deadline * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)

        let time_now_tics = mach_absolute_time();
        let time_now_nanos = (time_now_tics * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)

//        let deadline_delta_tics = deadline - time_now_tics;
//        let deadline_delta_nano = (deadline_delta_tics * UInt64(clockTimebase.numer)) / (UInt64(clockTimebase.denom));
        let deadline_delta_nano = deadline_nanos - time_now_nanos
        let deadline_delta_secs = deadline_delta_nano/UInt64(1e9);

        
        if (message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN) // OPEN event has to respond differently
        {
            es_respond_flags_result(esClientPtr!, message, UINT32_MAX, false)
        }
        else
        {
            es_respond_auth_result(esClientPtr!, message, ES_AUTH_RESULT_ALLOW, false)
        }
        
        var count : UInt64 = 1
        var minDeadline : UInt64 = deadline_delta_secs
        var maxDeadline : UInt64 = deadline_delta_secs

        let eventData = gEventsPerTypeRecord[message.pointee.event_type.rawValue]
        if eventData != nil {
            count = eventData!.count + 1
            if (deadline_delta_secs > eventData!.max) {
                maxDeadline = deadline_delta_secs
            } else if (deadline_delta_secs < eventData!.min) {
                minDeadline = deadline_delta_secs
            }
        }
        
        gEventsPerTypeRecord[message.pointee.event_type.rawValue] =  EventData(count:count, min:minDeadline, max:maxDeadline)
        
        if  eventsCount % 2000 == 0 {
            //print("deadline: ", deadline_delta_secs);
            //os_log("event_type:\(message.pointee.event_type.rawValue) duration:\(deadline_delta_secs)")
            DispatchQueue.global().async {
                //print("event type: \(message.pointee.event_type)")
                //os_log("event type:%d name:%{public}@", message.pointee.event_type.rawValue, ESEventTypes[message.pointee.event_type.rawValue]!)
            }
        }

    }
    
  
    private static func startEndpointSecurityClient() -> Bool {
        
        let newClientResult = es_new_client(&esClientPtr, { [self] (client: OpaquePointer , message: UnsafePointer<es_message_t> ) -> Void in
            handleClientMessage(client: client, message: message);
        })
        
        
        // Handle any errors encountered while creating the client.
        var errorString : String = ""
        
        switch (newClientResult) {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            print( "Success creating ES client.")
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            errorString = "Could not create ES client, is missing entitlement."
            print(errorString);
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            errorString = "Could not create ES client, process is not running as root."
            print(errorString);
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            errorString = "Could not create ES client, it needs TCC approval."
            print(errorString);
            break;
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            errorString = "Could not create ES client, invalid argument."
            print(errorString);
            break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            errorString = "Could not create ES client, exceeded maximum number of simultaneously-connected ES clients."
            print(errorString);
            break;
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            errorString = "Could not create ES client, failed to connect to the Endpoint Security subsystem."
            print(errorString);
            break;
        default:
            errorString = "Could not create ES client, failed to connect to the Endpoint Security subsystem."
            print(errorString);
            break;
        }
        
        
        if esClientPtr == nil {
            DispatchQueue.main.async {
                let alert = NSAlert()
                alert.messageText = errorString
                alert.informativeText = "err: \(newClientResult.rawValue)"
                alert.alertStyle = NSAlert.Style.warning
                alert.addButton(withTitle: "OK")
                alert.runModal()
            }
            return false
        }
        
        let clearResult = es_clear_cache(esClientPtr!);
        if (clearResult != ES_CLEAR_CACHE_RESULT_SUCCESS) {
            print("es_clear_cache failed. Err:%s", clearResult);
        }
        
        let events : [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC
            , ES_EVENT_TYPE_AUTH_OPEN
            , ES_EVENT_TYPE_AUTH_KEXTLOAD
            , ES_EVENT_TYPE_AUTH_MMAP
            , ES_EVENT_TYPE_AUTH_MPROTECT
            , ES_EVENT_TYPE_AUTH_MOUNT
            , ES_EVENT_TYPE_AUTH_RENAME
            , ES_EVENT_TYPE_AUTH_SIGNAL
            , ES_EVENT_TYPE_AUTH_UNLINK
            , ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE
            , ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE
            , ES_EVENT_TYPE_AUTH_READLINK
            , ES_EVENT_TYPE_AUTH_TRUNCATE
            , ES_EVENT_TYPE_AUTH_LINK
            , ES_EVENT_TYPE_AUTH_CREATE
            , ES_EVENT_TYPE_AUTH_SETATTRLIST
            , ES_EVENT_TYPE_AUTH_SETEXTATTR
            , ES_EVENT_TYPE_AUTH_SETFLAGS
            , ES_EVENT_TYPE_AUTH_SETMODE
            , ES_EVENT_TYPE_AUTH_SETOWNER
////            // The following events are available beginning in macOS 10.15.1
            , ES_EVENT_TYPE_AUTH_CHDIR
            , ES_EVENT_TYPE_AUTH_GETATTRLIST
            , ES_EVENT_TYPE_AUTH_CHROOT
            , ES_EVENT_TYPE_AUTH_UTIMES
            , ES_EVENT_TYPE_AUTH_CLONE
            , ES_EVENT_TYPE_AUTH_GETEXTATTR
            , ES_EVENT_TYPE_AUTH_LISTEXTATTR
            , ES_EVENT_TYPE_AUTH_READDIR
            , ES_EVENT_TYPE_AUTH_DELETEEXTATTR
            , ES_EVENT_TYPE_AUTH_FSGETPATH
            , ES_EVENT_TYPE_AUTH_SETTIME
            , ES_EVENT_TYPE_AUTH_UIPC_BIND
            , ES_EVENT_TYPE_AUTH_UIPC_CONNECT
            , ES_EVENT_TYPE_AUTH_EXCHANGEDATA
            , ES_EVENT_TYPE_AUTH_SETACL
            , ES_EVENT_TYPE_AUTH_PROC_CHECK
            , ES_EVENT_TYPE_AUTH_GET_TASK
            // The following events are available beginning in macOS 11.0
            , ES_EVENT_TYPE_AUTH_SEARCHFS
            , ES_EVENT_TYPE_AUTH_FCNTL
            , ES_EVENT_TYPE_AUTH_IOKIT_OPEN
            , ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME
            , ES_EVENT_TYPE_AUTH_REMOUNT
            // The following events are available beginning in macOS 11.3
            , ES_EVENT_TYPE_AUTH_GET_TASK_READ
            // The following events are available beginning in macOS 12.0
            , ES_EVENT_TYPE_AUTH_COPYFILE
        ]
        
        let ret = es_subscribe(esClientPtr!, events, UInt32(events.count))
        
        if (ret != ES_RETURN_SUCCESS) {
            print("es_subscribe failed")
        }
        
        return true
    }
}
