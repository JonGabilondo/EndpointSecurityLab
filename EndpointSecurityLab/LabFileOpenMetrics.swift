//
//  LabFileOpenMetrics.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 26/03/2024.
//
import Foundation
import Cocoa
import EndpointSecurity
import OSLog
import Collections


public class LabFileOpenMetrics {

    public struct FileOpenEventPerProcData {
        var eventCount: UInt64
        var procPath: String
        var procName: String
    }

    public static var gFileOpenEventsTroughputRecord : [UInt64] = []
    public static var gFileOpenEventsPerProcDict : OrderedDictionary<String, FileOpenEventPerProcData> = [:]

    static var esClientPtr: OpaquePointer? = nil
    static let defaultLog = Logger()
    static var totalEventsCount = 0
    static var periodEventsCount : UInt64 = 0
    static var periodStartTics : UInt64 = 0
    static var ticsPerSecond : UInt64 = 0
    static var clockTimebase : mach_timebase_info_data_t = mach_timebase_info_data_t()

    public static func start() {
        
        clockTimebase = mach_timebase_info();
        mach_timebase_info(&clockTimebase);
        ticsPerSecond = UInt64( Double(1e9) / (Double(clockTimebase.numer) / Double(clockTimebase.denom)))
        //print("ticsPerSecond: \(ticsPerSecond)");
        
        if !startEndpointSecurityClient() {
            return;
        }
    }
    
    static func stop() {
        if (esClientPtr != nil) {
            es_delete_client(esClientPtr)
            esClientPtr = nil
        }
    }
    
    static func export() {
        
        do {
            var csvData = "Process, Events\n"
            
            for (procPath, procData) in gFileOpenEventsPerProcDict {
                csvData.append(String(format: "%@, %@\n", procPath, String(format: "%d", procData.eventCount)))
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
            let fileURL = folderURL.appendingPathComponent("FileOpenMetrics.csv")
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

            
//            var csvData = "Event, Count, Events/s Peak, Events/s Avg\n"
//            
//            csvData.append(String(format: "%@, %@, %@, %@\n", String("ES_EVENT_TYPE_NOTIFY_OPEN"), String(format: "%d", totalEventsCount), String(format: "%d", 0), String(format: "%d", 0)))
//            
//            let fileManager = FileManager.default
//            let userDirectory = try! fileManager.url (for: .userDirectory, in: .localDomainMask, appropriateFor: nil, create: false)
//            let folderURL = userDirectory.appendingPathComponent("Shared/EndpointSecurityLab")
//            if !fileManager.fileExists(atPath: folderURL.path) {
//                do {
//                    try fileManager.createDirectory(at: folderURL, withIntermediateDirectories: true, attributes: nil)
//                } catch {
//                    print("Couldn't create document directory", error)
//                }
//            }
//            let fileURL = folderURL.appendingPathComponent("FileOpenMetrics.csv")
//            if fileManager.fileExists(atPath: fileURL.path) {
//                try fileManager.removeItem(atPath: fileURL.path)
//            }
//            print("csv file to create: '\(fileURL)'")
//            try csvData.write(to: fileURL, atomically: true, encoding: .utf8)
//            
//            do {
//                let openCSVProcess = Process()
//                openCSVProcess.executableURL = URL(fileURLWithPath: "/bin/zsh")
//                openCSVProcess.arguments = ["-c", "/usr/bin/open " + fileURL.path]
//
//                try openCSVProcess.run()
//                openCSVProcess.waitUntilExit()
//                print("finished. termination status:\(openCSVProcess.terminationStatus) reason:\(openCSVProcess.terminationReason)")
//            } catch {
//                print("error opening csv file", error)
//            }

        } catch {
            print("error creating csv file", error)
        }
        
    }
    
    
    // MARK: - Private
    

    private static func handleClientMessage(client: OpaquePointer, message : UnsafePointer<es_message_t>) {
        
        let procPathString = String(cString: UnsafePointer(message.pointee.process.pointee.executable.pointee.path.data))
        
        var entry = gFileOpenEventsPerProcDict[procPathString]
        if (entry == nil) {
            let procName = URL(fileURLWithPath: procPathString).lastPathComponent
            gFileOpenEventsPerProcDict[procPathString] = FileOpenEventPerProcData(eventCount: 1, procPath: procPathString, procName: procName)
        } else {
            entry?.eventCount += 1
            gFileOpenEventsPerProcDict[procPathString] = entry
       }
         
        if (periodStartTics == 0) {
            periodStartTics = mach_absolute_time()
//            periodStartNanos = (periodStartTics * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)
            return;
        }
        
        totalEventsCount+=1
        
//        assert(message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_OPEN)
        //os_log("File Open event count:\(totalEventsCount)")

        periodEventsCount += 1
        
//        let nowNanos : UInt64 = (mach_absolute_time() * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)
        let nowTics : UInt64 = mach_absolute_time()

        if ((nowTics - periodStartTics) >= ticsPerSecond) {
//        if ((nowNanos - periodStartNanos) >= UInt64(1e9)) {
            //os_log("1 sec ?")
            //os_log("events in record:%d period_events:%d total:%d", gFileOpenEventsTroughputRecord.count, periodEventsCount, totalEventsCount)
            gFileOpenEventsTroughputRecord.append(periodEventsCount)
            periodEventsCount = 0
            periodStartTics = mach_absolute_time()
//            periodStartNanos = (periodStartTics * UInt64(clockTimebase.numer)) / UInt64(clockTimebase.denom)
       }
        
        
//        if  (totalEventsCount % 100 == 0) {
//            //print("deadline: ", deadline_delta_secs);
//            //os_log("event_type:\(message.pointee.event_type.rawValue) duration:\(deadline_delta_secs)")
//            //DispatchQueue.global().async {
//                //print("event type: \(message.pointee.event_type)")
//            os_log("events in record: %d", gFileOpenEventsTroughputRecord.count)
//            //}
//        }
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
            ES_EVENT_TYPE_NOTIFY_OPEN
        ]
        
        let ret = es_subscribe(esClientPtr!, events, UInt32(events.count))
        
        if (ret != ES_RETURN_SUCCESS) {
            print("es_subscribe failed")
        }
        
        return true
    }
}
