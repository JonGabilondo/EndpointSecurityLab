//
//  LabESClientListenerProtocol.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 02/05/2024.
//

import Foundation
import EndpointSecurity

protocol LabESClientListenerProtocol {
    
    var subcribeEvents : [es_event_type_t] { get set }
    
    func handleNotify(message : UnsafePointer<es_message_t>) -> Void
    func handleAuth(message : UnsafePointer<es_message_t>) -> Void
}
