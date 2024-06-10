//
//  EndpointSecurityLabApp.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 26/03/2024.
//

import SwiftUI



@main
struct EndpointSecurityLabApp: App {
    
    //let name : String = "com.zscaler.zdp.EndpointSecurityLab" + ".sudo"
    //var myItems : [AuthorizationItem] = []
    
    init() {
    }
    
    var body: some Scene {
        Window("Endpoint Security Lab", id: "main") {
            LabMainView()
                .frame(
                    minWidth: 350, maxWidth: 350,
                    minHeight: 360, maxHeight: 360)
        }
        .windowResizability(.contentSize)
        
        WindowGroup(id: "auth-live-data") {
            AuthMetricsChart()
                .navigationTitle("Auth Metrics Live Data")
        }

        WindowGroup(id: "file-open-live-data") {
            LabFileOpenMetricsChartView()
                .navigationTitle("File-Open Metrics Live Data")
        }

    }
}
