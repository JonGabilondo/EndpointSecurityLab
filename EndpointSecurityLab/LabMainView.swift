//
//  ContentView.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 26/03/2024.
//

import SwiftUI

func startAuthMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabAllAuthJob.start()
    }
}

func stopAuthMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabAllAuthJob.stop()
    }
}

func exportAuthMetricsData() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabAllAuthJob.export()
    }
}

func startFileOpenMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabFileOpenJob.start()
    }
}

func stopFileOpenMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabFileOpenJob.stop()
    }
}

func exportFileOpenData() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabFileOpenJob.export()
    }
}

func startEventAnalisys() -> Bool {
    return LabEventAnalisysJob.sharedInstance.start()
}

func stopEventAnalisys() -> Bool {
    return LabEventAnalisysJob.sharedInstance.stop()
}

func startAntitamperingJob() -> Bool {
    return LabAntitamperingJob.sharedInstance.start()
}

func stopAntitampering() -> Bool {
    return LabAntitamperingJob.sharedInstance.stop()
}

struct LabMainView: View {
    @State var isAuthMetricsRunning: Bool = false
    @State var authMetricsProgressOpacity: Double = 0.0
    @State var authMetricsButtonLabel: String = "Start"

    @State var isFileOpenMetricsRunning: Bool = false
    @State var fileOpenMetricsProgressOpacity: Double = 0.0
    @State var fileOpenMetricsButtonLabel: String = "Start"

    @State var isEventAnalisysRunning: Bool = false
    @State var eventAnalisysProgressOpacity: Double = 0.0
    @State var eventAnalisysButtonLabel: String = "Start"

    @State var isAntitamperingRunning: Bool = false
    @State var antitamperingProgressOpacity: Double = 0.0
    @State var antitamperingButtonLabel: String = "Start"

    @Environment(\.openWindow) private var openWindow

    var body: some View {

        VStack {
            GroupBox(label: Label("AUTH Metrics", systemImage: "hammer").fontWeight(.bold)
            ) {
                HStack {
                    Button(authMetricsButtonLabel) {
                        if isAuthMetricsRunning {
                            stopAuthMetrics()
                            authMetricsButtonLabel = "Start"
                            isAuthMetricsRunning.toggle()
                        } else {
                            startAuthMetrics()
                            authMetricsButtonLabel = "Stop"
                            isAuthMetricsRunning.toggle()
                        }
                        authMetricsProgressOpacity = isAuthMetricsRunning ?1.0 :0.0
                    }
                    
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .scaleEffect(0.5)
                        .disabled(!isAuthMetricsRunning)
                        .opacity(authMetricsProgressOpacity)
                    Button("Export CSV", systemImage: "tablecells") {
                        exportAuthMetricsData()
                    }
                    Button("Live Data", systemImage: "chart.xyaxis.line") {
                        openWindow(id: "auth-live-data")
                    }
                }
            }
//            .padding(.bottom)
            .frame(maxWidth: .infinity, alignment: .leading)

            GroupBox(label: Label("Open-File Metrics", systemImage: "hammer").fontWeight(.bold)) {
                HStack {
                    Button(fileOpenMetricsButtonLabel) {
                        if isFileOpenMetricsRunning {
                            stopFileOpenMetrics()
                            fileOpenMetricsButtonLabel = "Start"
                        } else {
                            startFileOpenMetrics()
                            fileOpenMetricsButtonLabel = "Stop"
                        }
                        isFileOpenMetricsRunning.toggle()
                        fileOpenMetricsProgressOpacity = isFileOpenMetricsRunning ?1.0 :0.0
                    }
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .scaleEffect(0.5)
                        .disabled(!isFileOpenMetricsRunning)
                        .opacity(fileOpenMetricsProgressOpacity)
                    Button("Export CSV", systemImage: "tablecells") {
                        exportFileOpenData()
                    }
                    Button("Live Data", systemImage: "chart.xyaxis.line") {
                        openWindow(id: "file-open-live-data")
                    }
                }
            }
//            .padding(.bottom)
            .frame(maxWidth: .infinity, alignment: .leading)

            GroupBox(label: Label("Event Analisys", systemImage: "hammer").fontWeight(.bold)) {
                HStack {
                    Button(eventAnalisysButtonLabel) {
                        if isEventAnalisysRunning {
                            if stopEventAnalisys() {
                                eventAnalisysButtonLabel = "Start"
                                isEventAnalisysRunning.toggle()
                            }
                        } else {
                            if startEventAnalisys() {
                                eventAnalisysButtonLabel = "Stop"
                                isEventAnalisysRunning.toggle()
                            }
                        }
                        eventAnalisysProgressOpacity = isEventAnalisysRunning ?1.0 :0.0
                    }
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .scaleEffect(0.5)
                        .disabled(!isEventAnalisysRunning)
                        .opacity(eventAnalisysProgressOpacity)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            GroupBox(label: Label("ZDP Antitampering", systemImage: "hammer").fontWeight(.bold)) {
                HStack {
                    Button(antitamperingButtonLabel) {
                        if isAntitamperingRunning {
                            if stopAntitampering() {
                                antitamperingButtonLabel = "Start"
                                isAntitamperingRunning.toggle()
                            }
                        } else {
                            if startAntitamperingJob() {
                                antitamperingButtonLabel = "Stop"
                                isAntitamperingRunning.toggle()
                            }
                        }
                        antitamperingProgressOpacity = isAntitamperingRunning ?1.0 :0.0
                    }
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .scaleEffect(0.5)
                        .disabled(!isAntitamperingRunning)
                        .opacity(antitamperingProgressOpacity)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            
        }
        .padding()
        .focusable(false)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    
}


#Preview {
    LabMainView()
}
