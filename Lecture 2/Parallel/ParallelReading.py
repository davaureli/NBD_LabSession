# -*- coding: utf-8 -*-
"""
@author: david
"""

#Parallel Reading

#*https://docs.python.org/3/library/multiprocessing.html*

from utilsParallel import *
import os
from multiprocessing import Process, Manager
import glob
from os import system as cmd
import time
import shutil

if __name__ == "__main__":
    
    list_files = glob.glob("./*.pcap")
    
    print("# Files \t", len(list_files))
    pcap_analyzed = list_files[0]
    
    sub_dir = "SplitRead/"
    
    #Remove directory already created
    shutil.rmtree(sub_dir) 
    
    try:
        os.mkdir("./" + sub_dir)
    #If you have already created it Error
    except OSError:
        print("Creation of the directory %s failed" % sub_dir)
    else:
        print("Successfully created the directory %s" % sub_dir)
    
    cmd('editcap -c 1 ' + pcap_analyzed +" ./"+ sub_dir +"__mini.pcap")
    #cmd("complete PATH for wireshark...")
    
    print("Current Working Directory: "+ os.getcwd())
    
    #Change directory
    os.chdir("./"+sub_dir)
    
    print("New Working Directory: "+ os.getcwd())
    
    splitting_file = sorted(glob.glob("*.pcap"))
    
    print("# Splitted Files \t", len(list_files))
    
    manager = Manager()
    
    start_time = time.time()
    
    lista_process = []
    
    for i in range(len(splitting_file)):
        print("ok_")
        file = splitting_file[i]
        
        p1 = Process(target = extract_Info_pckt, args = (file,))
        
        lista_process.append(p1)
        
        p1.start()
        
    for process in lista_process:
        process.join()
        
    ### Finish ####
    
    print("Finish to read al pcap file")
    print("--- %s seconds ---" % (time.time() - start_time))
        
    

