//
//  LabFileOpenMetricsChartView.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 04/04/2024.
//

import SwiftUI
import Charts


struct FileOpenThroughputSample : Identifiable {
    var eventCount : UInt64
    var sampleIndex : UInt64
    var id: String
}

struct FileOpenEventsPerProcess : Identifiable {
    var procPath : String
    var eventCount : UInt64
    var id: String
}

enum ChartType: String, CaseIterable {
    case throughput, processes

    static var description = "type"
}

class FileOpenViewModel : ObservableObject {
    
    @Published var chosenChartType: ChartType = .throughput
    @Published var throughputData : [FileOpenThroughputSample] = []
    @Published var perProcessData : [FileOpenEventsPerProcess] = []
}

