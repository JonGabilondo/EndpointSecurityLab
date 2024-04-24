import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sys
import threading
import re
import os.path
from matplotlib.gridspec import GridSpec
from matplotlib.widgets import Button
from subprocess import call

#
# Globals
#
gProcessesDataLock = threading.Lock()

gInboundTrhoughputs = []
gInboundTrhoughputsChanged = True

gOutboundTrhoughputs = []
gOutboundTrhoughputsChanged = True

gInboundESEventsNames = []
gInboundESEventsCounts = []
gInboundESEventsChanged = True

gProcessesDict = {}
gProcessesDictLabels = []
gProcessesDictValues = []
gProcessesDictChanged = True

gProcEventsQueue = 0
gDefaultEventsQueue = 0
gProcEventsQueuePeak = 0
gDefaultEventsQueuePeak = 0
gEventsQueueChanged = True

#
# Figure
#
fig = plt.figure( figsize=(14, 8))
fig.canvas.manager.set_window_title('ZDPDESD Events')
gs = GridSpec(4, 2, figure=fig)
axInboundThroughput = plt.subplot(gs.new_subplotspec((0, 0), colspan=1))
axOutboundThroughput = plt.subplot(gs.new_subplotspec((0, 1), colspan=1))
axInboundESEvents= plt.subplot(gs.new_subplotspec((1, 0), colspan=1))
axQueuedEvents = plt.subplot(gs.new_subplotspec((1, 1), colspan=1))
axInboundESProcEvents= plt.subplot(gs.new_subplotspec((2, 0), colspan=2, rowspan=2))

plt.subplots_adjust(wspace=0.2,  hspace=0.8)
plt.rc('font', size=8)
plt.rc('axes', titlesize=8, labelsize=8, titleweight="bold")     # fontsize of the axes title
plt.rc('axes', labelsize=8)    # fontsize of the x and y labels
plt.rc('xtick', labelsize=8)    # fontsize of the tick labels
plt.rc('ytick', labelsize=8)    # fontsize of the tick labels
plt.rc('legend', fontsize=8)    # legend fontsize
plt.rc('figure', titlesize=10)  # fontsize of the figure title

#
# Export
#

def buildProcessesData(dataDict):
    global gProcessesDataLock
    with gProcessesDataLock:
        csvData = "Object, Count\r"
        for key, value in dataDict.items():
            csvData += f"{key}, {value}\r"
    return csvData
    

def exportProcessesData():
    folderPath = os.path.join(os.path.expanduser('~'),'Documents/zdpmetrics/zdpesd')
    try:
        os.makedirs(folderPath, mode=0o777, exist_ok=True)
    except OSError as error:
        print("Directory '%s' can not be created" % folderPath)

    filePath = os.path.join(folderPath,'zdpesd_proc_data.csv')
    file = open(filePath, "w")
    file.write(buildProcessesData(gProcessesDict))
    file.close()
    call(["open", filePath]) 


#
# Buttons
#

class ButtonCallbacks:
    def resetAll(self, event):
        global gInboundTrhoughputs
        global gInboundTrhoughputsChanged
        global gOutboundTrhoughputs
        global gOutboundTrhoughputsChanged
        global gInboundESEventsNames
        global gInboundESEventsCounts
        global gInboundESEventsChanged
        global gProcessesDict
        global gProcessesDictLabels
        global gProcessesDictValues
        global gProcessesDictChanged
        global gProcEventsQueue
        global gDefaultEventsQueue
        global gProcEventsQueuePeak
        global gDefaultEventsQueuePeak
        global gEventsQueueChanged
           
        
        global gProcessesDataLock
        with gProcessesDataLock:
            gInboundTrhoughputs = []
            gInboundTrhoughputsChanged = True
            gOutboundTrhoughputs = []
            gOutboundTrhoughputsChanged = True
            gInboundESEventsNames = []
            gInboundESEventsCounts = []
            gInboundESEventsChanged = True
            gProcessesDict = {}
            gProcessesDictLabels = []
            gProcessesDictValues = []
            gProcessesDictChanged = True
            gProcEventsQueue = 0
            gDefaultEventsQueue = 0
            gProcEventsQueuePeak = 0
            gDefaultEventsQueuePeak = 0
            gEventsQueueChanged = True

    def exportData(self, event):
        exportProcessesData()


callback = ButtonCallbacks()

axExportButton = fig.add_axes([0.102, 0.01, 0.1, 0.025])
btExport = Button(axExportButton, 'Export')
btExport.on_clicked(callback.exportData)

axResetButton = fig.add_axes([0.81, 0.01, 0.1, 0.025])
btReset = Button(axResetButton, 'Reset')
btReset.on_clicked(callback.resetAll)


def make_responsibles_pie_picker(fig, wedges):

    def onclick(event):
        global gProcessesDictChanged
        global gProcessesDictValues

        if event.mouseevent.dblclick :
            wedge = event.artist
            label = wedge.get_label()
            #print(label) #WHY IS IT CALLED MULTIPLE TIMES ! 
            gProcessesDict[label] = 1
            gProcessesDictChanged = True

    # Make wedges selectable
    #print(len(wedges))
    for wedge in wedges:
        wedge.set_picker(True)

    fig.canvas.mpl_connect('pick_event', onclick)
    
#
# animate
#
def animate(i):
    global gInboundTrhoughputsChanged
    global gOutboundTrhoughputsChanged
    global gInboundESEventsChanged
    global gProcessesDictChanged
    global gEventsQueueChanged

    if gInboundTrhoughputsChanged:
        axInboundThroughput.clear()
        axInboundThroughput.set_ylabel('Messages/sec')
        axInboundThroughput.set_title('ZDPESD Inbound Events Throughput')
        axInboundThroughput.plot(gInboundTrhoughputs)
        gInboundTrhoughputsChanged = False

    if gOutboundTrhoughputsChanged:
        axOutboundThroughput.clear()
        axOutboundThroughput.set_ylabel('Messages/sec')
        axOutboundThroughput.set_title('ZDPESD Outbound Events Throughput')
        axOutboundThroughput.plot(gOutboundTrhoughputs)
        gOutboundTrhoughputsChanged = False

    if gInboundESEventsChanged:
        axInboundESEvents.clear()
        axInboundESEvents.set_xlabel('Event Count')
        axInboundESEvents.set_title('ZDPESD Inbound Events')
        gInboundESEventsChanged = False
        bars = axInboundESEvents.barh(gInboundESEventsNames, gInboundESEventsCounts)
        axInboundESEvents.bar_label(bars)
    
    if gProcessesDictChanged:
        axInboundESProcEvents.clear()
        axInboundESProcEvents.set(title='Processes Generating Events')
        #calculateUpgradePieValues()
        #total = sum(upgrade_counts)
        global gProcessesDataLock
        with gProcessesDataLock:
            wedges, plt_labels = axInboundESProcEvents.pie(gProcessesDictValues, labels=gProcessesDictLabels, textprops={'fontsize': 8})
            make_responsibles_pie_picker(fig, wedges)
        gProcessesDictChanged = False
    
    if gEventsQueueChanged:
        axQueuedEvents.clear()
        axQueuedEvents.set_ylabel('Queued Events')
        axQueuedEvents.set_title('ZDPESD Inbound Event Processing Queues (Proc & Default)')
        bar = axQueuedEvents.bar(['Proc.Peak', 'Proc.Queued', 'Def.Peak', 'Def.Queued'], [gDefaultEventsQueuePeak, gDefaultEventsQueue, gProcEventsQueuePeak, gProcEventsQueue])
        axQueuedEvents.bar_label(bar, fmt='{:,.0f}')

        #axQueuedEvents.legend()
        gEventsQueueChanged = False


 
#
# Logs Parsing
#

# Example. "ES client throughput.ESEventThroughput Events:	44	Ntfy/s:	44	Auth/s:	0	EventsPeak/s:	61172	XPCSend/s:	0	Total:	2263850"
inboundThroughputLogLine = "ES client throughput.ESEventThroughput"
inboundThroughputLogLinePatt = r"Events:\t\d+|EventsPeak/s:\t\d+"

outboundThroughputLogLine = "Posted events throughput."


esEventsLogLine = "ES inbound event counter. Events"
esEventsLogLinePatt = r"Events:\t\d+|Counts:\t\d+"

esProcEventsLogLine = "Proc. Count. ES inbound event counter."
esProcEventsLogLinePatt = r"Proc:\d+|Count:\d+"

esProcEventsQueueLine = "ES queued pending events. Qname"
esProcEventsQueueLinePatt = r"Total:\d+|Peak:\d+"


def processInboundThroughputLine(line):
    global gInboundTrhoughputs
    global gInboundTrhoughputsChanged

    values = re.findall(inboundThroughputLogLinePatt, line)
    if len(values) == 2 :
        gInboundTrhoughputs.append( int(values[0].split(":")[1]) )
        gInboundTrhoughputsChanged = True

def processOutboundThroughputLine(line):
    global gOutboundTrhoughputs
    global gOutboundTrhoughputsChanged

    values = re.findall(r"Events:(\d+)", line)
    #print(values)
    if len(values) == 1 :
        gOutboundTrhoughputs.append( int(values[0]) )
        gOutboundTrhoughputsChanged = True

def processESEventsLogLine(line):
    global gInboundESEventsNames
    global gInboundESEventsCounts
    global gInboundESEventsChanged

    events = re.findall(r"Events:'([^']+)'", line)
    counts = re.findall(r"Counts:'([^']+)'", line)
    if (len(events) == len(counts) ) :
        eventNamesTokens = events[0].split(",")
        eventCountsTokens = counts[0].split(",")
        eventNamesTokens.pop()
        eventCountsTokens.pop()
        if (len(eventNamesTokens) == len(eventCountsTokens) ) :
            gInboundESEventsNames = eventNamesTokens
            gInboundESEventsCounts = [int(i) for i in eventCountsTokens]
            gInboundESEventsChanged = True


def processESProcEventsLogLine(line):
    global gProcessesDictChanged
    global gProcessesDict
    global gProcessesDictLabels
    global gProcessesDictValues

    event = re.findall(r"Proc:'([^']+)'", line)
    count = re.findall(r"Count:'([^']+)'", line)

    procName = event[0]
    procCount = count[0]

    global gProcessesDataLock
    with gProcessesDataLock:
        if procName in gProcessesDict:
            count = gProcessesDict[procName]
            gProcessesDict[procName] += 1
        else:
            gProcessesDict[procName] = 1
        gProcessesDictLabels = gProcessesDict.keys()
        gProcessesDictValues = gProcessesDict.values()
        gProcessesDictChanged = True

def processEventsQueueLine(line):
    global gEventsQueueChanged
    global gProcEventsQueue
    global gProcEventsQueuePeak
    global gDefaultEventsQueue
    global gDefaultEventsQueuePeak

    values = re.findall(esProcEventsQueueLinePatt, line)
    if len(values) == 2 :
        global gProcessesDataLock
        with gProcessesDataLock:
            if "ZDP ESD Processes Queue" in line:
                gProcEventsQueue = int(values[0].split(":")[1])
                gProcEventsQueuePeak = int(values[1].split(":")[1])
            elif "ZDP ESD Default Queue" in line:
                gDefaultEventsQueue = int(values[0].split(":")[1])
                gDefaultEventsQueuePeak = int(values[1].split(":")[1])

            gEventsQueueChanged = True


def readInput():
    for line in sys.stdin:
        if inboundThroughputLogLine in line:
            processInboundThroughputLine(line)
        if outboundThroughputLogLine in line:
            processOutboundThroughputLine(line)
        elif esProcEventsLogLine in line:
            processESProcEventsLogLine(line)
        elif esEventsLogLine in line:
            processESEventsLogLine(line)
        elif esProcEventsQueueLine in line:
            processEventsQueueLine(line)
        


readThread = threading.Thread(target=readInput)
readThread.daemon = True
readThread.start()

ani = animation.FuncAnimation(fig, animate, interval=1000)
plt.show()



