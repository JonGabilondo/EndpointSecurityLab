//
//  LabFileOpenMetricsChartView.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 04/04/2024.
//

import SwiftUI
import Charts

private enum Constant {
    static let timerLapse : TimeInterval = 2
}

struct FileOpenMetricsData : Identifiable {
    var eventCount : UInt64
    var sampleIndex : UInt64
    var id: String
}

struct FileOpenPerProcessData : Identifiable {
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
    @Published var data : [FileOpenMetricsData] = []
}

class FileOpenPerProcessViewModel : ObservableObject {
    
    @Published var data : [FileOpenPerProcessData] = []
}

struct LabFileOpenMetricsChartView: View {
    
    private func populateViewDataModel(viewDataModel : FileOpenViewModel) {
        viewDataModel.data.removeAll()
        var sampleIndex : UInt64 = 0
        for (eventCount) in LabFileOpenMetrics.gFileOpenEventsTroughputRecord {
            let event : FileOpenMetricsData = FileOpenMetricsData(eventCount: eventCount, sampleIndex: sampleIndex, id: "")
            viewDataModel.data.append(event)
            sampleIndex += 1
        }
    }
    
    private func populateProcEventsViewDataModel(viewDataModel : FileOpenPerProcessViewModel) {
        viewDataModel.data.removeAll()
        for (procPath, eventData) in LabFileOpenMetrics.gFileOpenEventsPerProcDict {
            viewDataModel.data.append(FileOpenPerProcessData(procPath: procPath, eventCount: eventData.eventCount, id:""))
        }
    }


    @StateObject var viewModel = FileOpenViewModel()
    @StateObject var processEventsViewModel = FileOpenPerProcessViewModel()
    
    var body: some View {
        
        @ObservedObject var openFileDataModel = viewModel
        @ObservedObject var openFilePerProcessViewModel = processEventsViewModel

        let timer = Timer.publish(every: Constant.timerLapse, on: .current, in: .common).autoconnect()
        
        VStack {
            
            ZStack {
                switch viewModel.chosenChartType {
                case .throughput:
                    getThoughputChart()
                case .processes:
                    getProcessChart()
                }
            }
            
            Picker("", selection: $viewModel.chosenChartType) {
                    Text("Throughput").tag(ChartType.throughput)
                    Text("Per Process").tag(ChartType.processes)
            }
            .pickerStyle(.segmented)
            .padding(.bottom)
            .focusable(false)
        }
        .onReceive(timer) { val in
            populateViewDataModel(viewDataModel: openFileDataModel)
            populateProcEventsViewDataModel(viewDataModel: openFilePerProcessViewModel)
        }
        .onAppear() {
            populateViewDataModel(viewDataModel: openFileDataModel)
            populateProcEventsViewDataModel(viewDataModel: openFilePerProcessViewModel)
        }
        
        
    }
    
    private func getThoughputChart() -> some View {
        TrhoughputChart
    }
    
    private func getProcessChart() -> some View {
        PerProcessChart
    }
    
    private var TrhoughputChart : some View {
        
        @ObservedObject var openFileDataModel = viewModel

        return VStack {
            Text("File-Open Events")
                .bold()
                .padding(.top)

            Chart(openFileDataModel.data) {
                LineMark(
                    x: .value("Index", $0.sampleIndex),
                    y: .value("Count", $0.eventCount)
                )
                .interpolationMethod(.catmullRom)
            }
            .padding(.horizontal)
            .chartXAxisLabel(position: .bottom, alignment: .center) {
                            Text("Time (secs)")
                        }
            .chartYAxisLabel() {
                            Text("Events/sec")
                        }
            .chartYAxis {
                        AxisMarks(position: .leading)
                    }
        }
        
    }
    
    private var PerProcessChart : some View {

        @ObservedObject var openFilePerProcessViewModel = processEventsViewModel

        return VStack {
            Text("File-Open Per Process")
                .bold()
            
            Chart(openFilePerProcessViewModel.data) {
                BarMark(
                    x: .value("event count", $0.eventCount),
                    y: .value("proc path", $0.procPath)
                )
                .cornerRadius(0.5)
            }
            .padding(.all)
            .chartXAxisLabel(position: .bottom, alignment: .center) {
                            Text("Event Count")
                        }
        }
    }
    
   
}

#Preview {
    LabFileOpenMetricsChartView()
}