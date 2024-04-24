import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sys
import threading
import re
from matplotlib.widgets import Button
from matplotlib.gridspec import GridSpec

gInboundMessagesChanged = True
gLocalEventsChanged = True

event_groups = ['Files', 'Processes', 'Prints', 'Cloud']
event_count = [0,0,0,0]

local_event_groups = ['Prints', 'Cloud', 'Removable', 'Network']
local_event_count = [0,0,0,0]

gClassificationPendingValues = []
gClassificationPendingValuesChanged = True

gClassificationDurationValues= []
gClassificationDurationValuesChanged = True

#
# figure
#
fig = plt.figure( figsize=(14, 8))
fig.canvas.manager.set_window_title('ZDPD Inbound Events')
gs = GridSpec(1, 2, figure=fig)
axInboundMessages = plt.subplot(gs.new_subplotspec((0, 0), colspan=1))
axLocalEvents = plt.subplot(gs.new_subplotspec((0, 1), colspan=1))
# axClassificationPending = plt.subplot(gs.new_subplotspec((1, 0), colspan=1))
# axClassificationDuration = plt.subplot(gs.new_subplotspec((1, 1), colspan=1))

plt.subplots_adjust(wspace=0.2,  hspace=0.2)
plt.rc('font', size=8)
plt.rc('axes', titlesize=8, labelsize=8, titleweight="bold")     # fontsize of the axes title
plt.rc('xtick', labelsize=8)    # fontsize of the tick labels
plt.rc('ytick', labelsize=8)    # fontsize of the tick labels
plt.rc('legend', fontsize=8)    # legend fontsize
plt.rc('figure', titlesize=10)  # fontsize of the figure title

#
# Button (we can't reset values)
#

#class ButtonCallbacks:
#    def resetAll(self, event):
#        global event_count
#        global gInboundMessagesChanged
#
#        event_count = [0,0,0,0];
#        gInboundMessagesChanged = True

#axReset = fig.add_axes([0.81, 0.01, 0.1, 0.025])
#bt = Button(axReset, 'Reset')
#callback = ButtonCallbacks()
#bt.on_clicked(callback.resetAll)

#
# animation
#

def animate(i):
    global gInboundMessagesChanged
    global gLocalEventsChanged
    global gClassificationPendingValuesChanged
    global gClassificationDurationValuesChanged

    if gInboundMessagesChanged:
        axInboundMessages.clear()
        axInboundMessages.set_ylabel('Messages')
        axInboundMessages.set_title('Zdpd Inbound Messages')
        bar_container = axInboundMessages.bar(event_groups,event_count)
        axInboundMessages.bar_label(bar_container, fmt='{:,.0f}')
        gInboundMessagesChanged = False

    if gLocalEventsChanged:
        axLocalEvents.clear()
        axLocalEvents.set_ylabel('Local Events')
        axLocalEvents.set_title('Zdpd Local Events')
        bar_container = axLocalEvents.bar(local_event_groups,local_event_count)
        axLocalEvents.bar_label(bar_container, fmt='{:,.0f}')
        gLocalEventsChanged = False
    
    # if  gClassificationPendingValuesChanged:
        # axClassificationPending.clear()
        # axClassificationPending.set_ylabel('Pending Files')
        # axClassificationPending.set_xlabel('Timeline')
        # axClassificationPending.set_title('Pending Clasifications')
        # axClassificationPending.plot(gClassificationPendingValues)
        # gClassificationPendingValuesChanged = False

    # if  gClassificationDurationValuesChanged:
    #     axClassificationDuration.clear()
    #     axClassificationDuration.set_ylabel('Duration per File (ms)')
    #     axClassificationDuration.set_xlabel('Timeline')
    #     axClassificationDuration.set_title('Clasifications Duration')
    #     axClassificationDuration.plot(gClassificationDurationValues)
    #     gClassificationDurationValuesChanged = False



# Example. "Zdpd local events counter Total:11 Prints:2 Cloud:3 Removable:23 Network:33"
inLocalEventsLogLine = "Zdpd local events counter Total"
inLocalEventsLogLinePatt = r"Total:\d+|Prints:\d+|Cloud:\d+|Removable:\d+|Network:\d+"

# Example. "Zdpd Inbound events counter Total:11 Files:2 Processes:22 Prints:2 Cloud:3"
inMessagesLogLine = "Zdpd Inbound events counter Total"
inMessagesLogLinePatt = r"Total:\d+|Files:\d+|Processes:\d+|Prints:\d+|Cloud:\d+"

# Example. "Zdpd file classification duration. Total duration(ms):0 peak(ms):41"
classficationDurationLine = "Zdpd file classification duration."
classficationDurationLinePatt = "Zdpd file classification duration. Total duration\(ms\):\d+"

# Example. "Files pending classification: 22"
classficationPendingLine = "Files pending classification:"
classficationPendingLinePatt = "Files pending classification: \d+"


def processInboundMessages(line) :
    global gInboundMessagesChanged
    values = re.findall(inMessagesLogLinePatt, line)
    if len(values) == 5 :
        event_count[0] = int(values[1].split(":")[1])
        event_count[1] = int(values[2].split(":")[1])
        event_count[2] = int(values[3].split(":")[1])
        event_count[3] = int(values[4].split(":")[1])
        gInboundMessagesChanged = True


def processLocalEvents(line) :
    global gLocalEventsChanged

    values = re.findall(inLocalEventsLogLinePatt, line)
    if len(values) == 5 :
        local_event_count[0] = int(values[1].split(":")[1])
        local_event_count[1] = int(values[2].split(":")[1])
        local_event_count[2] = int(values[3].split(":")[1])
        local_event_count[3] = int(values[4].split(":")[1])
        gLocalEventsChanged = True

def processClassificationDuration(line) :
    global gClassificationDurationValues
    global gClassificationDurationValuesChanged

    values = re.findall(classficationDurationLinePatt, line)
    if len(values) == 1 :
        gClassificationDurationValues.append( int(values[0].split(":")[1]) )
        gClassificationDurationValuesChanged = True

def processClassificationPending(line) :
    global gClassificationPendingValues
    global gClassificationPendingValuesChanged

    values = re.findall(classficationPendingLinePatt, line)
    
    if len(values) == 1 :
        #print(values[0].split(": ")[1])
        gClassificationPendingValues.append( int(values[0].split(": ")[1]) )
        #print(gClassificationPendingValues)
        gClassificationPendingValuesChanged = True


def readInput():
    for line in sys.stdin:
        if inMessagesLogLine in line:
            processInboundMessages(line)
        elif inLocalEventsLogLine in line:
            processLocalEvents(line)
        elif classficationDurationLine in line:
            processClassificationDuration(line)
        elif classficationPendingLine in line:
            processClassificationPending(line)
        

readThread = threading.Thread(target=readInput)
readThread.daemon = True
readThread.start()

ani = animation.FuncAnimation(fig, animate, interval=1000)
plt.show()



