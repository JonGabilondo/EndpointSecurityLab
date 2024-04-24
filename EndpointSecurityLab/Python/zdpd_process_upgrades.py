import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sys
import threading
import re
import array as arr
from matplotlib.gridspec import GridSpec
from matplotlib.widgets import Button

#import parse
#import numpy as np

#
# data structures
#
event_groups = ['P.Start', 'P.End', 'Resp.', 'Add.Map.Err']
event_counts = [0,0,0,0]

proc_map_count_groups = ['Map', "Archived"]
proc_map_count = [0,0]
proc_map_changed = False

upgrades_dict = {}
upgrade_labels = []
upgrade_counts = []
upgrades_dict_changed = False

upgrades_f_dict = {}
upgrade_f_labels = []
upgrade_f_counts = []
upgrades_f_dict_changed = True

durations = arr.array('i');

#
## figures
#

fig = plt.figure( figsize=(14, 8))
gs = GridSpec(5, 2, figure=fig)
axProcesses = plt.subplot(gs.new_subplotspec((0, 0), colspan=1))
axProcessesMap = plt.subplot(gs.new_subplotspec((0, 1), colspan=1))
#axDuration = plt.subplot(gs.new_subplotspec((0, 2), colspan=1))
axPieChart = plt.subplot(gs.new_subplotspec((1, 0), colspan=2, rowspan=4))

fig.suptitle('ZDPD Processes')

plt.subplots_adjust(wspace=0.2,  hspace=0.2)
plt.rc('font', size=8)
plt.rc('axes', titlesize=8)     # fontsize of the axes title
plt.rc('axes', labelsize=8)    # fontsize of the x and y labels
plt.rc('xtick', labelsize=8)    # fontsize of the tick labels
plt.rc('ytick', labelsize=8)    # fontsize of the tick labels
plt.rc('legend', fontsize=8)    # legend fontsize
plt.rc('figure', titlesize=10)  # fontsize of the figure title

#plt.subplots_adjust(left=0.1,
#                    bottom=0.1,
#                    right=0.9,
#                    top=0.9,
#                    wspace=0.5,
#                    hspace=0.8)
#
## Picker
#

def make_responsibles_pie_picker(fig, wedges):

    def onclick(event):
        if event.mouseevent.dblclick :
            wedge = event.artist
            label = wedge.get_label()
            #print(label) #WHY IS IT CALLED MULTIPLE TIMES ! 
            upgrades_dict[label] = 1
            global upgrades_dict_changed
            upgrades_dict_changed = True

    # Make wedges selectable
    #print(len(wedges))
    for wedge in wedges:
        wedge.set_picker(True)

    fig.canvas.mpl_connect('pick_event', onclick)

def calculateUpgradePieValues():
    global upgrades_dict_changed
    if upgrades_dict_changed :
        upgrade_labels.clear()
        upgrade_counts.clear()
        for k, v in upgrades_dict.items():
            upgrade_labels.append(k) 
            upgrade_counts.append(int(v)) 

def calculateUpgradeFailuresPieValues():
    global upgrades_f_dict_changed
    if upgrades_f_dict_changed :
        upgrade_f_labels.clear()
        upgrade_f_counts.clear()
        for k, v in upgrades_f_dict.items():
            upgrade_f_labels.append(k) 
            upgrade_f_counts.append(int(v)) 

def animate(i):
    axProcesses.clear()
    #axDuration.clear()


    ## animate Process events bars
    axProcesses.set_ylabel('Events')
    axProcesses.set_title('Inbound Process Events')
    bar_container = axProcesses.bar(event_groups,event_counts)
    axProcesses.bar_label(bar_container, fmt='{:,.0f}')

    ## animate Proc Map
    global proc_map_changed
    if proc_map_changed:
        axProcessesMap.clear()
        axProcessesMap.set_ylabel('Processes')
        axProcessesMap.set_title('Process Map')
        axProcessesMap_bar = axProcessesMap.bar(proc_map_count_groups, proc_map_count)
        axProcessesMap.bar_label(axProcessesMap_bar, fmt='{:,.0f}')
        proc_map_changed = False

    ## Duration plot
    #axDuration.set(xlabel='', ylabel='Duration (ms)', title='Upgrade Duration')
    #axDuration.plot(durations)


    ## animate Responsible pie
    global upgrades_dict_changed
    if upgrades_dict_changed :
        axPieChart.clear()
        axPieChart.set(title='Responsibles Map')
        calculateUpgradePieValues()
        total = sum(upgrade_counts)
        wedges, plt_labels, auto_texts = axPieChart.pie(upgrade_counts, labels=upgrade_labels, textprops={'fontsize': 8}, autopct=lambda p: '{:.0f}'.format(p * total / 100))
        make_responsibles_pie_picker(fig, wedges)
        upgrades_dict_changed = False

    ## Failure upgrades pie
    #global upgrades_f_dict_changed
    #if upgrades_f_dict_changed :
    #    axFailuresPieChart.clear()
    #    axFailuresPieChart.set(title='Failures')
    #    calculateUpgradeFailuresPieValues()
    #    axFailuresPieChart.pie(upgrade_f_counts, labels=upgrade_f_labels, textprops={'fontsize': 8})
    #    upgrades_f_dict_changed = True
       

eventsPatt = r"Proc.Start:\d+|Proc.End:\d+|Responsible:\d+|Proc.to.Map.err:\d+"
eventsLogLine = "Zdpd Inbound process upgrade counter."

processesMapLogLine = "Processes in map:"
processesMapLogLinePatt = r"map:\d+|archived:\d+"

def processEventsLine(line):
    values = re.findall(eventsPatt, line)
    print(line)
    if len(values) == len(event_groups) :
        event_counts[0] = int(values[0].split(":")[1])
        event_counts[1] = int(values[1].split(":")[1])
        event_counts[2] = int(values[2].split(":")[1])
        event_counts[3] = int(values[3].split(":")[1])
    else:
        print("Unexpected !")


def processProcessesMapLogLine(line):
    global proc_map_changed
    values = re.findall(processesMapLogLinePatt, line)
    if len(values) == 2 :
        proc_map_count[0] = int(values[0].split(":")[1])
        proc_map_count[1] = int(values[1].split(":")[1])
        proc_map_changed = True


def readInput():
    for line in sys.stdin:
        if eventsLogLine in line:
            processEventsLine(line)
        elif processesMapLogLine in line:
            processProcessesMapLogLine(line)
     
 
readThread = threading.Thread(target=readInput)
readThread.daemon = True
readThread.start()

ani = animation.FuncAnimation(fig, animate, interval=1000, cache_frame_data=False)
plt.show()



