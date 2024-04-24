import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sys
import threading
import re
import cos.path
import threading
from matplotlib.widgets import Button
from matplotlib.widgets import RadioButtons
from matplotlib.gridspec import GridSpec
from subprocess import call

#
# globals
#

gClassificationDataLock = threading.Lock()

gClassificationPendingValues = []
gClassificationPendingValuesChanged = True

gClassificationDurationValues= []
gClassificationDurationValuesChanged = True

gClassificationProcessesDict = {}
gClassificationProcessesDictLabels = []
gClassificationProcessesDictValues = []
gClassificationFilesDict = {}
gClassificationFilesDictLabels = []
gClassificationFilesDictValues = []
gClassificationProcessesDictChanged = True

gClassificationViewMode = 0 # 0 Files 1 Procs

#
# Export
#

def buildClassificationData(dataDict):
    global gClassificationDataLock
    with gClassificationDataLock:
        csvData = "Object, Count\r"
        for key, value in dataDict.items():
            csvData += f"{key}, {value}\r"
    return csvData
    

def exportClassificationData():
    folderPath = os.path.join(os.path.expanduser('~'),'Documents/zdpmetrics/classification')
    try:
        os.makedirs(folderPath, mode=0o777, exist_ok=True)
    except OSError as error:
        print("Directory '%s' can not be created" % folderPath)

    filePath = os.path.join(folderPath,'c_f_data.csv')
    file = open(filePath, "w")
    file.write(buildClassificationData(gClassificationFilesDict))
    file.close()
    call(["open", filePath]) 

    filePath = os.path.join(folderPath,'c_p_data.csv')
    file = open(filePath, "w")
    file.write(buildClassificationData(gClassificationProcessesDict))
    file.close()
    call(["open", filePath]) 


#
# figure
#
fig = plt.figure( figsize=(16, 9))
fig.canvas.manager.set_window_title('ZDPD Classification Load')
gs = GridSpec(3, 2, figure=fig)
axClassificationPending = plt.subplot(gs.new_subplotspec((0, 0), colspan=1))
axClassificationDuration = plt.subplot(gs.new_subplotspec((0, 1), colspan=1))
axClassificationProcesses = plt.subplot(gs.new_subplotspec((1, 0), colspan=2, rowspan=2))

plt.subplots_adjust(wspace=0.2,  hspace=0.2)
plt.rc('font', size=8)
plt.rc('axes', titlesize=8, labelsize=8, titleweight="bold")     # fontsize of the axes title
plt.rc('xtick', labelsize=8)    # fontsize of the tick labels
plt.rc('ytick', labelsize=8)    # fontsize of the tick labels
plt.rc('legend', fontsize=8)    # legend fontsize
plt.rc('figure', titlesize=10)  # fontsize of the figure title

#
# Buttons 
#

class ButtonCallbacks:
    def resetAll(self, event):
        global gClassificationPendingValues
        global gClassificationDurationValues
        global gClassificationPendingValuesChanged
        global gClassificationDurationValuesChanged
        global gClassificationProcessesDictChanged
        global gClassificationProcessesDict
        global gClassificationProcessesDictLabels
        global gClassificationProcessesDictValues
        global gClassificationFilesDict
        global gClassificationFilesDictLabels
        global gClassificationFilesDictValues

        global gClassificationDataLock
        
        with gClassificationDataLock:
            gClassificationPendingValues = []
            gClassificationDurationValues= []
            gClassificationProcessesDict = {}
            gClassificationProcessesDictLabels = []
            gClassificationProcessesDictValues = []
            gClassificationFilesDict = {}
            gClassificationFilesDictLabels = []
            gClassificationFilesDictValues = []
            gClassificationPendingValuesChanged = True
            gClassificationDurationValuesChanged = True
            gClassificationProcessesDictChanged = True

    def exportData(self, event):
        exportClassificationData()


axResetButton = fig.add_axes([0.81, 0.01, 0.1, 0.025])
btReset = Button(axResetButton, 'Reset')
callback = ButtonCallbacks()
btReset.on_clicked(callback.resetAll)

axExportButton = fig.add_axes([0.102, 0.01, 0.1, 0.025])
btExport = Button(axExportButton, 'Export')
btExport.on_clicked(callback.exportData)

#
# Radio
#

def radioClick(label):
    global gClassificationViewMode
    global gClassificationProcessesDictChanged

    if "Files" in label: 
        gClassificationViewMode = 0
    else:
        gClassificationViewMode = 1
    gClassificationProcessesDictChanged = True

rax = fig.add_axes([0.001, 0.01, 0.1, 0.05])
radio = RadioButtons(rax, ('Files', 'Processes'),  label_props={'fontsize': [8,8]})
radio.on_clicked(radioClick)


#
# animation
#

def animate(i):
    # global gInboundMessagesChanged
    # global gLocalEventsChanged
    global gClassificationPendingValuesChanged
    global gClassificationDurationValuesChanged
    global gClassificationProcessesDictChanged
    
    if  gClassificationPendingValuesChanged:
        axClassificationPending.clear()
        axClassificationPending.set_ylabel('Pending Files')
        axClassificationPending.set_xlabel('Timeline')
        axClassificationPending.set_title('Pending Clasifications')
        axClassificationPending.plot(gClassificationPendingValues)
        gClassificationPendingValuesChanged = False

    if  gClassificationDurationValuesChanged:
        axClassificationDuration.clear()
        axClassificationDuration.set_ylabel('Duration per File (ms)')
        axClassificationDuration.set_xlabel('Timeline')
        axClassificationDuration.set_title('Clasifications Duration')
        axClassificationDuration.plot(gClassificationDurationValues)
        gClassificationDurationValuesChanged = False

    if gClassificationProcessesDictChanged:
        axClassificationProcesses.clear()
        axClassificationProcesses.set(title='Files/Processes Generating Classifications')

        global gClassificationDataLock
        with gClassificationDataLock:
            if gClassificationViewMode == 0 :
                wedges, plt_labels = axClassificationProcesses.pie(gClassificationFilesDictValues, labels=gClassificationFilesDictLabels, textprops={'fontsize': 8})
            else:
                wedges, plt_labels = axClassificationProcesses.pie(gClassificationProcessesDictValues, labels=gClassificationProcessesDictLabels, textprops={'fontsize': 8})
            gClassificationProcessesDictChanged = False

#
# Logs Parsing
#

# Example. "Zdpd file classification duration. Total duration(ms):0 peak(ms):41"
classficationDurationLine = "Zdpd file classification duration."
classficationDurationLinePatt = "Zdpd file classification duration. Total duration\(ms\):\d+"

# Example. "Files pending classification: 22"
classficationPendingLine = "Files pending classification:"
classficationPendingLinePatt = "Files pending classification: \d+"

# Example "EventHandler, local file changed. Candidate for discovery. file:'path' proc:'path' "
classificationCandidateProcessLine = "EventHandler, local file changed. Candidate for discovery."


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

def processClassificationCandidate(line):
    global gClassificationProcessesDictChanged
    global gClassificationProcessesDict
    global gClassificationProcessesDictLabels
    global gClassificationProcessesDictValues
    global gClassificationFilesDict
    global gClassificationFilesDictLabels
    global gClassificationFilesDictValues

    procPathFindResult = re.findall(r"proc:'([^']+)'", line)
    filePathFindResult = re.findall(r"file:'([^']+)'", line)

    procPath = procPathFindResult[0]
    filePath = filePathFindResult[0]

    global gClassificationDataLock
    with gClassificationDataLock:
        if procPath in gClassificationProcessesDict:
            gClassificationProcessesDict[procPath] += 1
        else:
            gClassificationProcessesDict[procPath] = 1
        gClassificationProcessesDictLabels = gClassificationProcessesDict.keys()
        gClassificationProcessesDictValues = gClassificationProcessesDict.values()

        if filePath in gClassificationFilesDict:
            gClassificationFilesDict[filePath] += 1
        else:
            gClassificationFilesDict[filePath] = 1
        gClassificationFilesDictLabels = gClassificationFilesDict.keys()
        gClassificationFilesDictValues = gClassificationFilesDict.values()
    
    gClassificationProcessesDictChanged = True

def readInput():
    for line in sys.stdin:
        if classficationDurationLine in line:
            processClassificationDuration(line)
        elif classficationPendingLine in line:
            processClassificationPending(line)
        elif classificationCandidateProcessLine in line:
            processClassificationCandidate(line)
        

readThread = threading.Thread(target=readInput)
readThread.daemon = True
readThread.start()

ani = animation.FuncAnimation(fig, animate, interval=2000)
plt.show()



