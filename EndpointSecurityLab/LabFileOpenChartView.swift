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

struct LabFileOpenMetricsChartView: View {
    
    private func populateViewDataModel(viewDataModel : FileOpenViewModel) {
        var sampleIndex : UInt64 = UInt64(viewDataModel.throughputData.count)
        for i in viewDataModel.throughputData.count..<LabFileOpenMetrics.gFileOpenEventsTroughputRecord.count {
            let sampleCount = LabFileOpenMetrics.gFileOpenEventsTroughputRecord[i]
            let event : FileOpenThroughputSample = FileOpenThroughputSample(eventCount: sampleCount, sampleIndex: sampleIndex, id: "")
            viewDataModel.throughputData.append(event)
            sampleIndex += 1
        }
    }
    
    private func populateProcEventsViewDataModel(viewDataModel : FileOpenViewModel) {
        viewDataModel.perProcessData.removeAll()
        for (procPath, eventData) in LabFileOpenMetrics.gFileOpenEventsPerProcDict {
            viewDataModel.perProcessData.append(FileOpenEventsPerProcess(procPath: procPath, eventCount: eventData.eventCount, id:""))
        }
    }


    @StateObject private var viewModel = FileOpenViewModel()
    
    var body: some View {
        
        @ObservedObject var openFileDataModel = viewModel

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
            populateProcEventsViewDataModel(viewDataModel: openFileDataModel)
        }
        .onAppear() {
            populateViewDataModel(viewDataModel: openFileDataModel)
            populateProcEventsViewDataModel(viewDataModel: openFileDataModel)
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

            Chart(openFileDataModel.throughputData) {
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

        @ObservedObject var openFileDataModel = viewModel

        return VStack {
            Text("File-Open Per Process")
                .bold()
            
            Chart(openFileDataModel.perProcessData) {
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
