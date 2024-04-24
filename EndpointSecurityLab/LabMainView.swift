//
//  ContentView.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 26/03/2024.
//

import SwiftUI

func startAuthMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabAllAuthMetrics.start()
    }
}

func stopAuthMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabAllAuthMetrics.stop()
    }
}

func exportAuthMetricsData() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabAllAuthMetrics.export()
    }
}

func startFileOpenMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabFileOpenMetrics.start()
    }
}

func stopFileOpenMetrics() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabFileOpenMetrics.stop()
    }
}

func exportFileOpenData() {
    DispatchQueue.global(qos: .userInitiated).async {
        LabFileOpenMetrics.export()
    }
}



struct LabMainView: View {
    @State var isAuthMetricsRunning: Bool = false
    @State var authMetricsProgressOpacity: Double = 0.0
    @State var authMetricsButtonLabel: String = "Start"

    @State var isFileOpenMetricsRunning: Bool = false
    @State var fileOpenMetricsProgressOpacity: Double = 0.0
    @State var fileOpenMetricsButtonLabel: String = "Start"

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
                        } else {
                            startAuthMetrics()
                            authMetricsButtonLabel = "Stop"
                        }
                        isAuthMetricsRunning.toggle()
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
            .padding(.bottom)

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

        }
        .padding()
        .focusable(false)
    }
    
}


#Preview {
    LabMainView()
}
