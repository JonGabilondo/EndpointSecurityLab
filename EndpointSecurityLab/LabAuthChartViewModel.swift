//
//  LabAuthCharts.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 07/04/2024.
//

import SwiftUI
import Charts
//import Collections

struct AuthEventMetricsData : Identifiable {
    var eventType : String
    var count : UInt64
    var deadline : UInt64
    var deadlineCategory : String
    var deadlineColor : Color
    var id: String { eventType }
}

class AuthEventsDataViewModel : ObservableObject {
    
    @Published var data : [AuthEventMetricsData] = []
}

