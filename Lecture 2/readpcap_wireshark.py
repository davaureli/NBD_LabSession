# -*- coding: utf-8 -*-
"""
@author: davide
"""

# =============================================================================
# # Reading a pcap File
# =============================================================================


#import nest_asyncio
#import tornado

import pyshark
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import copy
import sys
import shutil
import os


file_name = glob.glob("./*.pcap")[0]
print("Working with: ", file_name)
pcap = pyshark.FileCapture(file_name)


def extract_Info_pckt(file_name ): #lista_packet_ICMP
    
    pcap = pyshark.FileCapture(file_name)

    title = ["Label DSCP", "header len", "ds_field","ds_field_ecn", "length", 
          "Protocol" ,"flag_df", "flag_mf", "flag_rb", "fragment_offset", "ttl", 
          "IP_SRC", "IP_DST","src_port", "dst_port","time"] 
    
    total_info = []
    print("Now I'm working on: " + file_name)
    print()
       
    
    i = 0
    dscp = []
    total_info.append(title)
    
    for packet in pcap:
        
        ### MAC Address verification ###
        #sorgente = pcap[0].eth.src
            
        #Creating an empty list where we collect info about the packet
        #Useful this format to create then a DataFrame
        
        values = []
        
        #print(packet.layers)
        #We extract onòy the packets from IP Level and only Version IPv4
        #if 'IP' in packet and packet.eth.src == sorgente:
        if 'IP' in packet :
            
            
            #Label
            values.append(packet.ip.dsfield_dscp)
            dscp.append(packet.ip.dsfield_dscp)
            #Features
            
            #Header Length
            values.append(int(packet.ip.hdr_len))
            #Differentiated Service
            values.append(int(packet.ip.dsfield,16))
            #Explicit Congestion Notification
            values.append(packet.ip.dsfield_ecn)
            #Length of the Packet including the header
            values.append(int(packet.ip.len))
            #Number of Protocol (e.g. 6 = TCP, 17 = UDP, 1 = ICMP)
            values.append(int(packet.ip.proto))
            #Flag Do not Fragment 
            values.append(packet.ip.flags_df)
            #Flag More Fragment
            values.append(packet.ip.flags_mf)
            #Flag Reserved - Must be 0
            values.append(packet.ip.flags_rb)
            #Fragment Offset
            values.append(packet.ip.frag_offset)
            #Time To Live
            values.append(int(packet.ip.ttl))
            
            
            #### Extraction of the Ip Source and Ip Destination###
            
            source = packet.ip.src
            values.append(source)
            
            destination = packet.ip.dst
            values.append(destination)
  
            #### Extraction of the Port ####
            if "UDP" in packet:
                values.append(packet.udp.srcport)
                values.append(packet.udp.dstport)

            elif "TCP" in packet :
                values.append(packet.tcp.srcport)
                values.append(packet.tcp.dstport)            
                
            else:
                #Protocol as IP and ICMP e Ws.Short Port in src and dst will be set to -1
                values.append(-1)
                values.append(-1)
                
            #if "ICMP" in packet:
            #    lista_packet_ICMP.append((packet.ip.dsfield_dscp, packet.icmp.type, packet.icmp.code))
            
            
            #Time will be used for the simulation
            time = float(packet.sniff_timestamp)
            values.append(time)
             
            #Update the number of pckts
            i += 1
            
            #Store all the caracteristics of a packet into the Totale list
            total_info.append(values)
            
    print("Now we have finished the analysis so we closed the file: " + file_name)     
    pcap.close()
   
    print(len(total_info))
    #Creation of the data frame
    dataFrame = pd.DataFrame(total_info[1:],columns = total_info[0])
    
    return dataFrame
    
    # #We are saving the dataframe of Features Packets
    # with open('FeaturesDataFrame/' + title + '.pkl', 'wb') as f:
    #     pickle.dump(tot_dat, f)
    
    # print("Here we have analyzed this number of pckts: " + str(i))
    
    #Label Analysis
    # occ_label = dict(Counter(dscp))
    #print("DSCP occurrences",occ_label)

  
dataFrame = extract_Info_pckt(file_name)
print("Finish the reading part")

dataFrame.to_pickle("PacketDataframe.pkl")

dataFrame = pd.read_pickle("PacketDataframe.pkl")

print(dataFrame.head())

#Stop running from command Line
#sys.exit("Error message")

# =============================================================================
# #Bult-in function for the pandas dataframe 
# =============================================================================

print()
print(dataFrame['length'].describe())
print()

print()
print(dataFrame['ttl'].describe())
print()


# =============================================================================
# Global Settings for Plot
# =============================================================================

plt.rcParams['axes.facecolor'] = 'aliceblue'
plt.rcParams['axes.edgecolor'] = 'grey'
plt.rcParams['axes.grid'] = True
plt.rcParams['grid.alpha'] = 1
plt.rcParams['grid.color'] = "#cccccc"
plt.rcParams['axes.axisbelow'] = True

label_size = 13
plt.rcParams['xtick.labelsize'] = label_size 
plt.rcParams['ytick.labelsize'] = label_size 

#_______________________________________________________________________________#

folder_image = "Image"

#Remove directory already created
#shutil.rmtree(folder_image) 

try:
    os.mkdir(folder_image)
#If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % folder_image)
else:
    print("Successfully created the directory %s" % folder_image)
folder_image = "./Image/"
# =============================================================================
# #Histogram for packet length
# =============================================================================

plt.figure(figsize = (20, 10))
plt.hist(dataFrame["length"],bins= 20,label ="Byte")
#plt.xscale('log')
#plt.legend()
plt.xlabel("Byte",fontsize = 15)
plt.ylabel("Frequency",fontsize = 15)
#plt.xticks(fontsize=13)
plt.savefig(folder_image+"hist.png")
plt.show()



data_couple = dataFrame.groupby(["IP_SRC", "IP_DST"])[['length']].agg('sum')

data_couple = dataFrame.groupby(["IP_SRC", "IP_DST","Protocol"])[['length']].agg('sum')

print(data_couple.sort_values(by=['length'], ascending=False).head(20))



onlyMyIP = dataFrame[dataFrame["IP_SRC"] == "192.168.43.28"]
data_couple = onlyMyIP.groupby(["IP_DST"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(20)

def bitRate(data, step_sec = 1):
    start = data.iloc[0]["time"]
    finish = data.iloc[-1]["time"]
    print("Start: ",start)
    print("Finish: ",finish)
    
    
    data["time"] -= data.iloc[0]["time"]
    start = data.iloc[0]["time"]
    finish = data.iloc[-1]["time"]
    
    print("Start: ",start)
    print("Finish: ",finish)
    
    step = finish/ step_sec
    finish = start + step_sec
    value = []
    print(step)
    for i in range(int(step)):
    
        #From Byte to bit
        val = np.sum(data[(data["time"]>=start) & (data["time"]<finish)]["length"]*8)
        if not np.isnan(val):
            value.append(val/step_sec)
        start = finish 
        finish = start + step_sec
        
    return value

# =============================================================================
# # TOP 6 DESTINATION REACHED by specific IP BitRate    
# =============================================================================

#Get your Ip : https://whatismyipaddress.com/

personal_IP = "192.168.43.28"

onlyMyIP = dataFrame[dataFrame["IP_SRC"] == personal_IP]
grouped = onlyMyIP.groupby(["IP_DST"]).agg('sum').sort_values(by=['length'], ascending=False).head(6)
data_couple = onlyMyIP.groupby(["IP_DST"])


rowlength = int(grouped.shape[0]/2)   # fix up if odd number of groups
fig, axs = plt.subplots(figsize=(20,12), 
                        nrows=2, ncols=rowlength,     
                        gridspec_kw=dict(hspace=0.4)) 
fig.tight_layout()
targets = zip(grouped.index, axs.flatten())
for i, (key, ax) in enumerate(targets):
    print(key)
    #ax.plot(data_couple.get_group(key)["length"])
    ax.plot(bitRate(data_couple.get_group(key)),marker = "o")
    ax.set_title(key)
    ax.set_xlabel("T (sec)")
    ax.set_ylabel("bit/sec")
    #ax.set_yscale('log')
ax.legend()
fig.suptitle('TOP 6 IP Dst for 192.168.43.28', fontsize=16)
plt.savefig(folder_image + "TOP 6 IP Dst for MyIP")
plt.show()

# =============================================================================
# # TOP 5 DESTINATION for received data  
# =============================================================================

data_couple = dataFrame.groupby(["IP_DST"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(6)

plt.figure(figsize = (18, 12), dpi = 75)
#Remove my Ip too traffic generated
plt.barh(data_couple.index[1:], data_couple['length'][1:]/1e3, color = sns.color_palette('plasma', 10))
plt.title('Top 10 destinations for received data', fontsize = 30, loc = 'center', pad = 15)
plt.ylabel('IP address', fontsize = 18, labelpad = 5)
plt.xlabel('Total volume of received data ($Kbit$)', fontsize = 20, labelpad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.savefig(folder_image +"TOP Destination")
plt.show()

# =============================================================================
# # TO 10 DESTINATION for sending data  
# =============================================================================

data_couple = dataFrame.groupby(["IP_SRC"])[['length']].agg('sum').sort_values(by=['length'], ascending=False).head(6)

plt.figure(figsize = (18, 12), dpi = 75)
#plt.barh(data_couple.index[1:], data_couple['length'][1:]/1e3, color = sns.color_palette('plasma', 10))
plt.barh(data_couple.index, data_couple['length']/1e3, color = sns.color_palette('plasma', 10))

plt.title('Top 10 destinations for sending data', fontsize = 30, loc = 'center', pad = 15)
plt.ylabel('IP address', fontsize = 18, labelpad = 5)
plt.xlabel('Total volume of sending data ($Kbit$)', fontsize = 20, labelpad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.savefig(folder_image +"TOP Sender")
plt.show()

###############################################################################

# =============================================================================
# Bit Rate IP: 74.125.99.134 ??? Total Bit Rate ?
# =============================================================================


plt.figure(figsize = (20, 10))

plt.plot(list(map(lambda x: x/1e6, bitRate(dataFrame,1))), color = 'peru',marker="o",label = "avg 1sec")
plt.plot([ i*5 for i in range(1,len(list(map(lambda x: x/1e6, 
                                             bitRate(dataFrame,5))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,5))), color = 'gold',marker="*",label = "avg 5sec")
plt.plot([ i*10 for i in range(1,len(list(map(lambda x: x/1e6, bitRate(dataFrame,10))))+1)],list(map(lambda x: x/1e6, bitRate(dataFrame,10))), 
         color = 'chartreuse',marker="v",label = "avg 10sec")

#plt.plot(list(map(lambda x: x/1e6, bitRate(dataFrame,10))), color = 'olivedrab',marker="o-")
plt.xlabel('Time(s)', fontsize = 20, labelpad = 10)
plt.ylabel('Mbps', fontsize = 20, labelpad = 10)
plt.title('Total bitrate', fontsize = 30, pad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.legend(fontsize=20,loc="best")
plt.savefig(folder_image +"BitRate different Averages")
plt.show()


##############################################################################
                    #Geo Referenciation#
##############################################################################

from ip2geotools.databases.noncommercial import DbIpCity
import folium

def geo_infos(ip_src_list, ip_dst_list):

  src_geo_info = []
  dst_geo_info = []
  i = 0

  for j in range(len(ip_src_list)):
    try:
      src_response = DbIpCity.get(ip_src_list[j], api_key='free')
      dst_response = DbIpCity.get(ip_dst_list[j], api_key='free')
    except:
      continue
    if src_response.latitude == None or dst_response.latitude == None: 
      continue
    i +=1
    src_geo_info.append([src_response.latitude, src_response.longitude, src_response.region])
    dst_geo_info.append([dst_response.latitude, dst_response.longitude, dst_response.region])
    if i == 10: break

  return src_geo_info, dst_geo_info

data_couple = copy.deepcopy(dataFrame)
#Change your local IP with the one used to navigate on the Web
data_couple["IP_SRC"]= data_couple["IP_SRC"].replace({'192.168.43.28':'46.37.14.27'})
data_couple["IP_DST"] = data_couple["IP_DST"].replace({'192.168.43.28':'46.37.14.27'})
df_srcdst = list(zip(data_couple.IP_SRC, data_couple.IP_DST))

mostcommon_srcdst = Counter(df_srcdst).most_common(5)

list_src = []
list_dst = []

for i in range(len(mostcommon_srcdst)):
    list_src.append(mostcommon_srcdst[i][0][0]) #src pos 0
    list_dst.append(mostcommon_srcdst[i][0][1]) #dst pos 1

#src_geo, dst_geo = geo_infos(list(top_10_flows['ip_src']), list(top_10_flows['ip_dst']))

#Sigle Couple
src_geo, dst_geo = geo_infos(['185.86.84.30'],['46.37.14.27'])
#5 Couples
src_geo, dst_geo = geo_infos(list_src, list_dst)

src_geo = pd.DataFrame(src_geo, columns=['latitude', 'longitude', 'region'])
dst_geo = pd.DataFrame(dst_geo, columns=['latitude', 'longitude', 'region'])




flow_map = folium.Map([0, 0], zoom_start=2, tiles='Stamen Terrain')

for i in range(len(src_geo)):
  folium.Marker([src_geo.loc[i][0], src_geo.loc[i][1]], popup='<i>Mt. Hood Meadows</i>', 
                icon=folium.Icon(color='green')).add_to(flow_map)
  folium.Marker([dst_geo.loc[i][0], dst_geo.loc[i][1]], popup='<i>Mt. Hood Meadows</i>',  
                icon=folium.Icon(color='red')).add_to(flow_map)
  folium.PolyLine([(src_geo.loc[i][0], src_geo.loc[i][1]), (dst_geo.loc[i][0], dst_geo.loc[i][1])], 
                  color="blue", weight=1.5, opacity=1).add_to(flow_map)

flow_map.save(folder_image +"Map_top_5_flows.html")
#display(flow_map)


##############################################################################
                    #Flows analysis#
##############################################################################


grouped_flows = dataFrame.groupby(['IP_SRC', 'IP_DST', 'Protocol', 'src_port', 'dst_port']).agg(tot_len = pd.NamedAgg(column = 'length', aggfunc = 'sum')).reset_index()

grouped_flows["Protocol"] = grouped_flows["Protocol"].replace({1:"ICMP",6:"TCP",17:"UDP"})

#Protocol Frequencies

plt.figure(figsize = (16, 10), dpi = 75)
plt.barh(grouped_flows.Protocol.value_counts().index, grouped_flows.Protocol.value_counts().values, color = sns.color_palette('viridis', 5))
plt.title('Protocols frequencies flows based', fontsize = 30, loc = 'center', pad = 15)
plt.xlabel('Frequency', fontsize = 20, labelpad = 15)
plt.ylabel('Protocol', fontsize = 20, labelpad = 15)
plt.xticks(fontsize = 14)
plt.yticks(fontsize = 14)
plt.savefig(folder_image +"Protocol Analysis")
plt.show()





# =============================================================================
#                                 #Transport Layer Analysis : Port Number
# =============================================================================

def port_scan (x, dic):
    ''' scan through the ports and update the counter at each import file. 
    save only the info for the well-known ports '''
    
    for port in x:
        if pd.isnull(port) == False:
            #Well-Known Ports
            if int(port) < 1024:
                if port not in dic.keys():
                    dic[port] = 1
                else:
                    dic[port] += 1
    return(dic)

source_ports = {}
source_ports = port_scan(dataFrame["src_port"], source_ports)
dest_ports = {}
dest_ports = port_scan(dataFrame["dst_port"], dest_ports)


pd.DataFrame.from_dict(source_ports, orient = 'index').to_json('./source_ports.json')
pd.DataFrame.from_dict(dest_ports, orient = 'index').to_json('./dest_ports.json')


sports = pd.read_json('./source_ports.json')
dports = pd.read_json('./dest_ports.json')

sports = sports.reset_index()
dports = dports.reset_index()
sports = sports.rename(columns = {'index':'port', 0:'count'})
dports = dports.rename(columns = {'index':'port', 0:'count'})


sports = sports.sort_values(by = 'count', ascending = False)
dports = dports.sort_values(by = 'count', ascending = False)


plt.figure(figsize = (19, 10), dpi = 75)
plt.bar(x = list(map(str, list(sports.loc[sports['count'] > 50,'port']))), color = 'darkred', height = list(sports.loc[sports['count'] > 50,'count']), label = 'Src port', alpha = 0.7)
plt.bar(x = list(map(str, list(dports.loc[dports['count'] > 50,'port']))), color = 'darkcyan', height = list(dports.loc[dports['count'] > 50,'count']), label = 'Dst port', alpha = 0.7)
plt.legend(fontsize=20)
plt.yscale('log')
plt.title('Ports with more than 50 occurrences', fontsize = 30, pad = 15)
plt.xlabel('Port number', fontsize = 20, labelpad = 15)
plt.ylabel('Count', fontsize = 20, labelpad = 15)
plt.savefig(folder_image +"Port Scanner")
plt.show()



#############################################################################

# =============================================================================
#                               VIOLIN Plot for pckt length
# =============================================================================

import copy
from collections import Counter
import seaborn as sns


def InterArrivalTime(data):
    val = np.array(data["time"])
    
    return np.diff(val)

data_protocol = copy.deepcopy(dataFrame[dataFrame["Protocol"].isin([6,17])])
data_protocol["Protocol"] = data_protocol["Protocol"].replace({1:"ICMP",6:"TCP",17:"UDP"})

print(Counter(data_protocol["Protocol"]))


data_protocol = data_protocol[data_protocol["length"]<= 6000]

plt.figure(figsize = (20, 10))
ax = sns.violinplot(x="Protocol", y="length", data=data_protocol, cut=0)
ax.set_xlabel("")
ax.set_ylabel("Byte Length")





#Inter arrival time

tcp_data = data_protocol[data_protocol["Protocol"]=="TCP"]
udp_data = data_protocol[data_protocol["Protocol"]=="UDP"]

inteArr_TCP= []
for elem in tcp_data.groupby(['IP_SRC', 'IP_DST', 'Protocol', 'src_port', 'dst_port']):
    #groupby tuple (key,dataframe)
    inteArr_TCP += InterArrivalTime(elem[1]).tolist()

inteArr_UDP = []
for elem in udp_data.groupby(['IP_SRC', 'IP_DST', 'Protocol', 'src_port', 'dst_port']):
    inteArr_UDP += InterArrivalTime(elem[1]).tolist()


val_ = inteArr_TCP + inteArr_UDP

label_TCP = [ "TCP" for i in range(len(inteArr_TCP))]
label_UDP =[ "UDP" for i in range(len(inteArr_UDP))]

lab_ = label_TCP + label_UDP

d = {'Protocol': lab_, 'IntArrTime': val_}
df = pd.DataFrame(data=d)


plt.figure(figsize = (20, 10))
#df = df[df["IntArrTime"] < 0.05]
ax = sns.violinplot(x="Protocol", y="IntArrTime", data=df, cut=0)
ax.set_xlabel("")
ax.set_ylabel("Inter Arrival Time (sec)",fontsize=15)
plt.show()


#Time under 1 sec

plt.figure(figsize = (20, 10))
df_ = df[df["IntArrTime"] < 0.01]
ax = sns.violinplot(x="Protocol", y="IntArrTime", data=df_, cut=0)
ax.set_xlabel("")
ax.set_ylabel("Inter Arrival Time (sec)",fontsize=15)

plt.figure(figsize = (20, 10))
plt.rcParams['ytick.labelsize'] = 14
df_ = df[df["IntArrTime"] < 0.01]
ax = sns.boxplot(x="Protocol", y="IntArrTime", data=df_)
ax.set_xlabel("")
ax.set_ylabel("Inter Arrival Time (sec)",fontsize=16)
plt.savefig(folder_image +"BoxPlot InterArrivalTime")
plt.show()



print("Mean InterArrivalTime TCP Session: %.2f"% np.mean(np.array(inteArr_TCP)[np.array(inteArr_TCP)<1]))

print("Mean InterArrivalTime UDP Session: %.2f"% np.mean(np.array(inteArr_UDP)[np.array(inteArr_UDP)<1]))