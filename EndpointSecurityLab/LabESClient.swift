//
//  LabESClient.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 02/05/2024.
//

import Foundation
import Cocoa
import EndpointSecurity

class LabESClient {
    
    var listener : LabESClientListenerProtocol? = nil
    var name : String = ""
    var esClientPtr: OpaquePointer? = nil

    init(listener: LabESClientListenerProtocol? = nil, name: String) {
        self.listener = listener
        self.name = name
    }
    
    func start() -> Bool {
        if listener == nil {
            return false
        }
        if esClientPtr != nil {
            return true
        }
        return startEndpointSecurityClient()
    }
    
    func stop() -> Bool {
        if listener == nil {
            return false
        }
        if esClientPtr == nil {
            return true
        }

        es_delete_client(esClientPtr)
        esClientPtr = nil
        return true
    }

    private func startEndpointSecurityClient() -> Bool {
        
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
    
        let events = listener?.subcribeEvents
        let ret = es_subscribe(esClientPtr!, events!, UInt32(events!.count))
        
        if (ret != ES_RETURN_SUCCESS) {
            print("es_subscribe failed")
        }
        
        return true
    }
    
    private func handleClientMessage(client: OpaquePointer, message : UnsafePointer<es_message_t>) -> Void {
                
        switch message.pointee.action_type {
        case ES_ACTION_TYPE_AUTH:
            listener?.handleAuth(message: message)
            break
        case ES_ACTION_TYPE_NOTIFY:
            listener?.handleNotify(message: message)
            break
        default:
            print("unknown !")
        }
        return
    }
}
