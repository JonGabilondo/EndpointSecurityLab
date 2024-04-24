import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sys
import threading
import re
import parse

event_groups = ['Start Proc.', 'Upgrades', 'Failures']
event_counts = [0,0,0]
fig, ax = plt.subplots(figsize=(3, 5))
#ax.set_ylabel('')
#ax.set_title('(Zdpd) Process Upgrades')
ax.bar(event_groups,event_counts)

def animate(i):
    ax.clear()
    ax.set_ylabel('Events')
    ax.set_title('[Zdpd] Process Upgrades')
    bar_container = ax.bar(event_groups,event_counts)
    ax.bar_label(bar_container, fmt='{:,.0f}')
    #for index, value in enumerate(event_counts):
    #    plt.text(index, value, str(value))

# Example. "Zdpd Inbound process upgrade counter ..."
pattern = r"Processes:\d+|Success:\d+|Failures:\d+"

def readInput():
    for line in sys.stdin:
        #print(line)
        values = re.findall(pattern, line)
        #print(values)
        if len(values) == 3 :
            event_counts[0] = int(values[0].split(":")[1])
            event_counts[1] = int(values[1].split(":")[1])
            event_counts[2] = int(values[2].split(":")[1])
 

readThread = threading.Thread(target=readInput)
readThread.daemon = True
readThread.start()

ani = animation.FuncAnimation(fig, animate, interval=1000)
plt.show()



