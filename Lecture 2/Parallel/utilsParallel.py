# -*- coding: utf-8 -*-
"""
@author: david
"""

import pyshark

import pandas as pd


def extract_Info_pckt(file_name ): #lista_packet_ICMP
    
    pcap = pyshark.FileCapture(file_name)

    title = ["Label DSCP", "headerLen", "ds_field","ds_field_ecn", "length", 
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
                #Protocol as IP and ICMP e Ws.Short avranno come porta -1
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
   
    print("# Packets \t",len(total_info)-1) #-1 fro the title list
    #Creation of the data frame
    dataFrame = pd.DataFrame(total_info[1:],columns = total_info[0])
    
    
    
    dataFrame.to_pickle(file_name + "_PacketDataframe.pkl")
    
    #return dataFrame