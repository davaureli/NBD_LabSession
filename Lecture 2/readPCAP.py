# -*- coding: utf-8 -*-
"""
@author: davide
"""

# =============================================================================
# #Libraries
# =============================================================================
import glob
from os import system as cmd
import os
import shutil
import sys

# =============================================================================
# #Reading .pcap File
# =============================================================================

#all files with specific extension
list_pcap_file = glob.glob("./*.pcap")

print("Number of .pcap files: ", len(list_pcap_file))

file = list_pcap_file[0]

#Capinfos is a program that reads one or more capture files and returns 
#some or all available statistics (infos) of each <infile> in one of two types 
#of output formats: long or table.

#*Options*
print("*OPTIONS :*")

print()
print()
#-c --> Number of Packets in the capture
cmd("capinfos -c "+file)
print()
print()
#-i --> The average data rate, in bits/sec
cmd("capinfos -i "+file)
print()
print()
#-z --> The average PACKET SIZE
cmd("capinfos -z "+file)
print()
print()
#-A --> Generate all infos
cmd("capinfos -A "+file)
print()
print()
sys.exit("Error message")
#______________________________________________________________________________

# =============================================================================
# Info -Table Format
# =============================================================================

#To generate a TAB delimited table form report
cmd("capinfos -T -m "+file+" >info.txt")
print()
print()

#To generate a CSV delimited table style report of all infos 
#and write it to a text file called info.csv use:
cmd("capinfos -TmQ "+file+" >info.csv")
print()
print()

#**Reference: https://www.wireshark.org/docs/man-pages/capinfos.html

#______________________________________________________________________________

# =============================================================================
# Splitting .pcap file
# =============================================================================

#create directory
name_folder = "Splitting"

#Remove directory already created
shutil.rmtree(name_folder) 

try:
    os.mkdir(name_folder)
#If you have already created it Error
except OSError:
    print("Creation of the directory %s failed" % name_folder)
else:
    print("Successfully created the directory %s" % name_folder)
    

#Editcap is a program that reads some or all of the captured packets from the infile, 
#optionally converts them in various ways and writes the resulting packets to the 
#capture outfile.

#*Options*
print("*OPTIONS :*")

print()
print()

#-c Splits the packet output to different files based on uniform packet counts with 
#a maximum of <packets per file> each
cmd("editcap -c 1000 " + file + " " + name_folder + "/.pcap")

print("Check on the amount of pkt in the last .pcap generated: ")

file_check = sorted(glob.glob(name_folder+"./*.pcap"))[-1]
cmd("capinfos -c "+file_check)


#Remove First Splitting

shutil.rmtree(name_folder) 
os.mkdir(name_folder)

#-i Splits the packet output to different files based on uniform time intervals 
#using a maximum interval of <seconds per file> each

cmd("editcap -i 7 " + file + " " + name_folder + "/.pcap")

print("Check on the time duration of the last .pcap generated: ")

file_check = sorted(glob.glob(name_folder+"./*.pcap"))[-1]
#-u --> Capture duration in sec
cmd("capinfos -u "+file_check)


#We can split also using floating values as 0.5 (it is important the version of wireshark)

shutil.rmtree(name_folder) 
os.mkdir(name_folder)

#-i Splits the packet output to different files based on uniform time intervals 
#using a maximum interval of <seconds per file> each
print()
cmd("editcap -i 0.1 " + file + " " + name_folder + "/.pcap")
print("Total Number of pcap created with a slice of 0.1 sec : ",len(sorted(glob.glob(name_folder+"./*.pcap"))))

#**Reference: https://www.wireshark.org/docs/man-pages/editcap.html