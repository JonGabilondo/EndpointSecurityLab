//
//  LabAuthCharts.swift
//  EndpointSecurityLab
//
//  Created by Jon Gabilondo on 07/04/2024.
//

import SwiftUI
import Charts
import Collections

private enum Constant {
    static let timerLapse : TimeInterval = 5
    static let topPadding = 10.0
    static let leadingPadding = 40.0
    static let bottomPadding = 15.0
    static let trailingPadding = 15.0
    static let stackSpacing = 10.0
    static let textColorOpacity = 0.7
}

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


struct AuthMetricsChart: View {

    private func populateViewDataModel(viewDataModel : AuthEventsDataViewModel) {
        viewDataModel.data.removeAll()
        for (eventId, eventData) in gEventsRecord {
            viewDataModel.data.append(AuthEventMetricsData(eventType: ESEventTypes[eventId]!, count: eventData.count, deadline: eventData.min, deadlineCategory:"min", deadlineColor: .pink))
            if (eventData.min != eventData.max) {
                viewDataModel.data.append(AuthEventMetricsData(eventType: ESEventTypes[eventId]!, count: eventData.count, deadline: eventData.max+55, deadlineCategory:"max", deadlineColor: .purple))
            }
        }
    }

    @StateObject var viewModel = AuthEventsDataViewModel()

    var body: some View {

        @ObservedObject var authEventsDataModel = viewModel

        let timer = Timer.publish(every: Constant.timerLapse, on: .current, in: .common).autoconnect()

        HStack {
            VStack {
                Text("Auth Event Count")
                    .bold()
                
                Chart {
                    ForEach(authEventsDataModel.data) {
                        let count = $0.count
                        let name = $0.eventType
                        BarMark(
                            x: .value("count", count),
                            y: .value("name", name)
                        )
                        .annotation(position: .overlay, alignment: .trailing, spacing: -50) {
                            Text("\(count)")
                                .font(.system(size: 12))
                        }
                        .annotation(position: .overlay, alignment: .leading, spacing: -110) {
                            Text("\(name)")
                                .font(.system(size: 10))
                        }
                    }
                }
                .chartXAxis(.hidden)
                .chartYAxis(.hidden)
                .onTapGesture(count: 2, perform: { location in
                                    //self.location = location
                                 })

            }
            .padding(EdgeInsets(top:Constant.topPadding,leading:Constant.leadingPadding,bottom:Constant.bottomPadding,trailing:Constant.trailingPadding))
            
            VStack {
                Text("Auth Event Deadlines")
                    .bold()
                
                Chart {
                    ForEach(authEventsDataModel.data) {
                        let deadline = $0.deadline
                        let name = $0.eventType
                        BarMark(
                            x: .value("deadline", deadline),
                            y: .value("name", name)
                        )
                        .annotation(position: .overlay, alignment: .trailing, spacing: 0) {
                            Text("\(deadline)")
                                .font(.system(size: 12))
                        }
                        .foregroundStyle($0.deadlineColor)
                    }
                }
                .cornerRadius(5)
                .frame(width: 200, alignment: .leading)
                .chartXAxis(.hidden)
                .chartYAxis(.hidden)
                .padding(EdgeInsets(top:Constant.topPadding,leading:Constant.leadingPadding,bottom:Constant.bottomPadding,trailing:Constant.trailingPadding))
                
            }

        }  // HStack
        .onReceive(timer) { val in
            populateViewDataModel(viewDataModel: authEventsDataModel)
        }
        .onAppear() {
            populateViewDataModel(viewDataModel: authEventsDataModel)
        }

    }
}

#Preview {
    AuthMetricsChart()
}
