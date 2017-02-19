import logging
import urllib2
from scapy.all import *
import datetime

# Constants
timespan_threshhold = 3
dash_mac_address = '50:f5:da:3e:02:36'
dash_url_action = 'http://www.google.de/'

# Globals
lastpress = datetime.datetime.now()
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
 
def button_pressed_dash():
  global lastpress
  thistime = datetime.datetime.now()
  timespan = thistime - lastpress
  if timespan.total_seconds() > timespan_threshhold:
    current_time = datetime.datetime.strftime(thistime, '%Y-%m-%d %H:%M:%S')
    print 'Dash button ' + dash_mac_address + ' pressed at ' + current_time
    urllib2.urlopen(dash_url_action)
  
  lastpress = thistime

def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
      if 'requested_addr' in option:
        # found the MAC address, which means its the second and final UDP request
        mac_to_action[pkt.src]()
        break

mac_to_action = {dash_mac_address : button_pressed_dash}
mac_id_list = list(mac_to_action.keys())
 
print "Waiting for a dash button to be pressed..."
sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)

if __name__ == "__main__":
  main()
