# -*- coding: utf-8 -*-

"""
Lecture 3: Machine Learning 

@author: Davide
"""
# =============================================================================
# Library
# =============================================================================

import sys
import glob
import pandas as pd
from collections import Counter
import math
import numpy as np
from tqdm import tqdm
import pickle
import operator 

#Scikit-Learn
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.pipeline import make_pipeline
from sklearn.metrics import confusion_matrix

from sklearn.model_selection import GridSearchCV
from sklearn.metrics import classification_report


from imblearn.over_sampling import SMOTE

import matplotlib.pyplot as plt

from sklearn.cluster import KMeans
from kneed import KneeLocator


#Requirements:
# conda install -c conda-forge imbalanced-learn --> for SMOTE
# pip install kneed --> for KneeLocator
# pip install tqdm --> for tqdm


#Read all pickle file saved (On the GitHub repository is available just 2 pkl files zipped,
#in this part we are concatenating multiple dataframe)
splitting_file = list(sorted(glob.glob('SmallFile*')))
print("Available files: ",splitting_file)

#Concatenation in a unique Dataframe
df = pd.concat([ pd.read_pickle(name) for name in splitting_file])

#Shape(# packets,variables)
print(df.shape)

###############################################################################

# =============================================================================
# Label : DSCP --> DifferentiatedService Code Point
# =============================================================================
# In this small example we consider the label the differentiation between 
# service class applied in IP Traffic

#_____________________________________
#General classifiation (macroclasses):
#Be --> Best Effort
#AF --> Assured Forwarding
#EF --> Expidited Forwarding
#NIC --> Network and Internetwork Control
#
#( Usually all the traffic with DSCP between 0 and 8 is considered Scavenger)
#_______________________________________________________________________

#Reference: RFC 4594

#Article : 
#Aureli, D., Cianfrani, A., Diamanti, A., Vilchez, J. M. S., & Secci, S. 
#(2020, April). Going beyond diffserv in ip traffic classification. 
#In NOMS 2020-2020 IEEE/IFIP Network Operations and Management Symposium (pp. 1-6).IEEE.

###############################################################################

df["Label DSCP"] = pd.to_numeric(df["Label DSCP"])

dscp_tab = {0: "BE",
            8: "Priority",
            10: "Priority",
            12: "Priority",
            14: "Priority",
            16: "Immediate",
            18: "Immediate",
            20: "Immediate",
            22: "Immediate",
            24: "Flash voice",
            26: "Flash voice",
            28: "Flash voice",
            30: "Flash voice",
            32: "Flash Override",
            34: "Flash Override",
            36: "Flash Override",
            38: "Flash Override",
            40: "Critical voice RTP",
            46: "Critical voice RTP",
            48: "Internetwork control",
            56: "Network Control"
            } 

df = df.replace({'Label DSCP': dscp_tab})
df = df.replace({'Label DSCP': {"Priority":"AF","Immediate":"AF","Flash voice":"AF",
                                "Flash Override":"AF","Critical voice RTP":"EF",
                                 "Internetwork control":"CS6","Network Control":"CS6",
                                 4:"NotKnown",2:"NotKnown",6:"NotKnown",7:"NotKnown",
                                 1:"NotKnown",41:"EF",42:"EF",43:"EF",44:"EF",45:"EF"}})

print("DSCP Occurrences: \n")
print(Counter(df["Label DSCP"]))


#Following the paper proposed by Rossi(2010):
#Retrieve all info flows based

data_unique = df.drop_duplicates(["IP_DST","dst_port"])

#all possible (IP_0,port_0)
flows_list = data_unique[["IP_DST","dst_port"]].values.tolist()


dict_rows = {}

for i in tqdm(range(len(flows_list))):
    #extract all packets received by each specific couple IP dst, port destination
    subdata = df[(df["IP_DST"] == flows_list[i][0]) & (df["dst_port"] == flows_list[i][1])]
    
    #20 is just the length of our vector when we change the values in a logaritmic scale
    #max 2**19 --> 524288 | This consideration depends on your dataset
    length = np.zeros(20)
    pkt = np.zeros(20)
    
    #At least 2 pkts received by this specific (IP_0,port_0)
    if subdata.shape[0] >= 2:
        
        #Check about the label, we want to be sure to analyze a couple with just 1 DSCP
        #The vector that represents this element will have just one label
        
        if Counter(subdata["Label DSCP"] == 1):
        
            dtu = subdata.drop_duplicates(["IP_SRC","src_port"])
            
            list_couple_src = dtu[["IP_SRC","src_port"]].values.tolist()
            
            for elem in list_couple_src:
                #Observe each element in the Neighborhood (N)
                finaldata = subdata[(subdata["IP_SRC"]==elem[0]) & (subdata["src_port"]==elem[1])]
                
                #Number of packets
                #Ex: pck = 245, log_{2}(245) = 7.94 --> ceil()--> 8 
                #The range considered is (2**7,2**8] = (128,256]
                length[math.ceil(math.log(finaldata.shape[0])/math.log(2))] += 1
                
                #Packet length analysis --> Byte
                #extract each packet length
                for index,row in finaldata.iterrows():
                    pkt[math.ceil(math.log(row["length"])/math.log(2))] += 1
                    
            #Normalization vector both for packets and bytes    
            dict_rows[(flows_list[i][0],flows_list[i][1])] = [list(Counter(subdata["Label DSCP"]).keys())[0],length/sum(length),pkt/sum(pkt)]
                
        else:
            #print("problem")
            break
 

#Save the data in a pickle file
with open('dictAnalysis.pkl', 'wb') as handle:
    pickle.dump(dict_rows, handle, protocol=pickle.HIGHEST_PROTOCOL)

#Reading data
dict_rows = pd.read_pickle("dictAnalysis.pkl")

#Check the low number of occurrences of the priority flows
dscp_check_less_occ = [ dict_rows[k][0] for k in dict_rows.keys()]
print(dscp_check_less_occ)

### Add other flows with priority ####
for i in range(2,4):
    dict_ = pd.read_pickle("./dictAnalysis"+str(i)+".pkl")

    keys_ = list(set(dict_.keys())-set(dict_rows.keys()))
    for k in keys_:
        dict_rows[k] = dict_[k]


#Fast check about DSCP Occurrences
check = []
for k,val in dict_rows.items():
    check.append(val[0])

print("DSCP Check:\t", Counter(check).items())   



#Create a dataframe extending the data about packet length and number

data_pandas = []        
for k,val in dict_rows.items():
    obs = []
    obs.append(val[0])
    obs.extend(val[1].tolist())
    obs.extend(val[2].tolist())
    data_pandas.append(obs)

#Columns 
col = ["Label"]
col.extend(["X"+str(i)for i in range(40)])
df_ = pd.DataFrame.from_records(data_pandas,columns=col )
#Select just items with a string label and not numeric
df_ = df_[df_["Label"].isin(['AF','BE', 'CS6','EF','NotKnown'])]
#Useful to encode the label, it will be exploited at the end of the classification
le = preprocessing.LabelEncoder()
df_["Label"]  = le.fit_transform(df_["Label"])



#Extract X,Y
X = df_.iloc[:,1:]
Y = df_.iloc[:,0]
#Divide in train and test
x_train, x_test, y_train, y_test = train_test_split(X, Y,test_size = 0.25, random_state = 0)

print()
print("Train: ", Counter(y_train))
print("Test: ", Counter(y_test))
print()

#Create the classifier based on the SVM
#observe without the balance part
clf = make_pipeline(SVC(gamma='auto'))
clf.fit(x_train, y_train)
y_pred = clf.predict(x_test)
print(clf.score(x_test, y_test))

#Analysis on the prediction --> UNBALANCED Prediction
#*Paradox of Accuracy*
print("Our Prediction: ", Counter(y_pred))
print("Our Prediction based on the DSCP label: ", Counter(le.inverse_transform(y_pred)))
print("This is really UNBALANCED, even if we have obtained a good accuracy. It is better to observe the Confusion Matrix")


#________________________________________

clf = make_pipeline(SVC(gamma='auto',class_weight='balanced'))
clf.fit(x_train, y_train)
y_pred = clf.predict(x_test)

print(clf.score(x_test, y_test))
print("Our Prediction based on the DSCP label: ", Counter(le.inverse_transform(y_pred)))
print("Lower accuracy result, but we start to detect some elements of the other classes")

# =============================================================================
#  Oversampling 
# =============================================================================

x_train, x_test, y_train, y_test = train_test_split(X, Y,test_size = 0.25, random_state = 0)

print()
print("train: ", Counter(y_train))
print("test: ", Counter(y_test))
print()

#The class about Best Effort is 1, we want to balance the number of occurrences
#Synthetic samples generated by the interpolation of 2 elements in the population,
#taking a values randomly between 0 and 1 and then create the sample.

oversample = SMOTE(sampling_strategy={0:int(sum(y_train==1)),
                                      3:int(sum(y_train==1)),
                                      2:int(sum(y_train==1)),
                                      4:int(sum(y_train==1))})  
    
    
X_over, Y_over = oversample.fit_resample(x_train, y_train)

clf = make_pipeline(SVC(gamma=1e-1,class_weight='balanced',C = 1000))
clf.fit(X_over, Y_over)
y_pred = clf.predict(x_test)
print(clf.score(x_test, y_test))

print("Our Prediction based on the DSCP label: ", Counter(le.inverse_transform(y_pred)))
print("Let's observe the confusion matrix ...")

# =============================================================================
# # CONFUSION MATRIX
# =============================================================================

def plot_confusion_matrix(df_confusion, title='Confusion matrix', cmap=plt.cm.gray_r):
    
    '''Confusion Matrix Evaluation'''
    
    plt.figure(figsize=(9,9))
    plt.matshow(df_confusion, cmap=cmap,fignum=1) # imshow
    
    for (i, j), z in np.ndenumerate(df_confusion):
        plt.text(j, i, '{:0.2f}'.format(z), ha='center', va='center',
                 bbox=dict(boxstyle='round', facecolor='white'))
    
    #plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(df_confusion.columns))
    plt.xticks(tick_marks, df_confusion.columns, rotation=45,fontsize = 13)
    plt.gca().xaxis.tick_bottom()
    plt.yticks(tick_marks, df_confusion.index,fontsize = 13)
    plt.tight_layout()
    #plt.ylabel(df_confusion.index.name)
    #plt.xlabel(df_confusion.columns.name)
    plt.ylabel("True",fontsize = 18)
    plt.xlabel("Predicted",fontsize = 18)
    plt.grid(False)
    #plt.savefig("")
    plt.show()

labels = [ "BE", "NotKnown","AF", "EF","CS6"]
confmatrix = confusion_matrix(le.inverse_transform(y_test), le.inverse_transform(y_pred),
                 labels=labels)

df_confusion = pd.DataFrame(confmatrix, index=labels, columns=labels)
#Normalizing the matrix
df_conf_norm = df_confusion.div(df_confusion.sum(axis=1),axis=0)

plot_confusion_matrix(df_conf_norm)


# =============================================================================
# #IMPROVEMENTS for your PROJECT
# =============================================================================
#1) Dimensionality Reduction ? PCA or LDA
#2) Adding other variables --> Such as InterArrival time between packets in a flow
#3) Grid Search : (I'll give you snippet code for this part above ...)



# Set the parameters by cross-validation
tuned_parameters = [{'kernel': ['rbf'], 'gamma': [1e-2,5e-3],
                     'C': [800,1000]},
                    {'kernel': ['sigmoid']}]

clf = GridSearchCV(
    SVC(class_weight='balanced'), tuned_parameters,cv=3) #Cross-Validation 3 

#clf.fit(x_train, y_train)
clf.fit(X_over, Y_over)

print("Best parameters set found on development set:")
print()
print(clf.best_params_)
print()

print("Detailed classification report:")
print()
print("The model is trained on the full development set.")
print("The scores are computed on the full evaluation set.")
print()

y_true, y_pred = y_test, clf.predict(x_test)

print("Label transforation: ",set(y_test), le.inverse_transform(list(set(y_test))))
#print(classification_report(y_true, y_pred))
print()
#Complete Report based on the classification
print(classification_report(le.inverse_transform(y_true), le.inverse_transform(y_pred)))


## Precision = TP/(TP + FP)
## Recall = TP/(TP + FN) --> Sensitivity to predict a specific class


#Final Confusion Matrix after Grid Search
labels = [ "BE", "NotKnown","AF", "EF","CS6"]
confmatrix = confusion_matrix(le.inverse_transform(y_test), le.inverse_transform(y_pred),
                 labels=labels)

df_confusion = pd.DataFrame(confmatrix, index=labels, columns=labels)
#Normalizing the matrix
df_conf_norm = df_confusion.div(df_confusion.sum(axis=1),axis=0)

plot_confusion_matrix(df_conf_norm)

###############################################################################
###############################################################################
###############################################################################
###############################################################################

#sys.exit("Stop here the supervised Machine Learning part")

# =============================================================================
# Unsupervised Classification --> Clustering (K-MEANS)
# =============================================================================

#Here we exploit the data already available from the previous analysis
#trying to observe the results obtained in a complete unsupervised way.

#Here we do not go deeper as in the previous example, but in the Project it will be required
#for those of you that decide to work with this methodology.

#Reading data
dict_rows = pd.read_pickle("dictAnalysis.pkl")


### Add other flows with priority ####
for i in range(2,4):
    dict_ = pd.read_pickle("./dictAnalysis"+str(i)+".pkl")

    keys_ = list(set(dict_.keys())-set(dict_rows.keys()))
    for k in keys_:
        dict_rows[k] = dict_[k]


#Fast check about DSCP Occurrences
check = []
for k,val in dict_rows.items():
    check.append(val[0])

print("DSCP Check:\t", Counter(check).items())   



#Create a dataframe extendind the data about packet length and number

data_pandas = []        
for k,val in dict_rows.items():
    obs = []
    obs.append(val[0])
    obs.extend(val[1].tolist())
    obs.extend(val[2].tolist())
    data_pandas.append(obs)

#Columns 
col = ["Label"]
col.extend(["X"+str(i)for i in range(40)])
df_ = pd.DataFrame.from_records(data_pandas,columns=col )
#Select just items with a string label and not numeric
df_ = df_[df_["Label"].isin(['AF','BE', 'CS6','EF','NotKnown'])]
#Useful to encode the label, it will be exploited at the end of the classification
le = preprocessing.LabelEncoder()
df_["Label"]  = le.fit_transform(df_["Label"])

#Extract X,Y
X = df_.iloc[:,1:]
Y = df_.iloc[:,0]

#Step:
#1)Extract train and test from our starting dataset
#2)Apply oversampling to rebalance in the training the number of occurrences
#3)Find the optimal K (number of clusters) according to the training
#4) Apply this clustering to the test

x_train, x_test, y_train, y_test = train_test_split(X, Y,test_size = 0.20, random_state = 0)
oversample = SMOTE(sampling_strategy={0:sum(y_train==1),
                                      2:sum(y_train==1),
                                      4:sum(y_train==1),
                                      3:sum(y_train==1)})
X_over, Y_over = oversample.fit_resample(x_train, y_train)

print()
print("Starting y_train distribution: ", Counter(y_train))
print("Distribution of the labels after oversampling: ", Counter(le.inverse_transform(y_train)))

print()

print("Distribution of the labels after oversampling: ", Counter(Y_over))
print("Distribution of the labels after oversampling: ", Counter(le.inverse_transform(Y_over)))
print()

kmeans_kwargs = {
    "init": "random",
    "n_init": 10,
    "max_iter": 300,
    "random_state": 95,
}

# =============================================================================
# # A list holds the SSE (sum of squared errors) values for each k
# =============================================================================
sse = []
for k in range(1, 15):
    kmeans = KMeans(n_clusters=k,**kmeans_kwargs)
    kmeans.fit(X_over)
    sse.append(kmeans.inertia_)
    
# =============================================================================
# # Elbow Method    
# =============================================================================

plt.plot(range(1, 15), sse)
plt.xticks(range(1, 15))
plt.xlabel("Number of Clusters")
plt.ylabel("SSE")
plt.show()

#Extract the minimum in the convex curve 

kl = KneeLocator(
    range(1, 15), sse, curve="convex", direction="decreasing"
)

print("Optimal number of clusters: ",kl.elbow)
opt = kl.elbow

#Apply again K.Means with this specific number of clusters

kmeans = KMeans(
    init="random",
    n_clusters=opt,
    n_init=10,
    max_iter=300,
    random_state=95
)
kmeans.fit(X_over)


#Observe the results
#In each cluster finding the occurrences of the DSCP Labels

dict_label_dscp = {}

for i in list(set(kmeans.labels_)):
    #print(sum(kmeans.labels_== i))
    ind = []
    for s, j in enumerate(kmeans.labels_):
        if j == i:
            ind.append(s) 

    print("Label: ",i)
    stats = Counter(le.inverse_transform(Y_over[ind]))
    print(stats)
    print(max(stats.items(), key=operator.itemgetter(1))[0])
    dict_label_dscp[i] = max(stats.items(), key=operator.itemgetter(1))[0]
    print()
    print()
    
# =============================================================================
# #Test   
# =============================================================================
pred = kmeans.predict(x_test)    

prediction = [ dict_label_dscp[elem] for elem in pred ]    

# =============================================================================
# Confusion matrix evaluation   
# =============================================================================

confmatrix = confusion_matrix(le.inverse_transform(y_test), 
                              prediction,
                 labels=labels)

df_confusion = pd.DataFrame(confmatrix, index=labels, columns=labels)
df_conf_norm = df_confusion.div(df_confusion.sum(axis=1),axis=0)

plot_confusion_matrix(df_conf_norm)


# =============================================================================
# #Idea for this project:

# 1)Dimensionality reduction
# 2)Add more features (int_arr_time)
# 2)Silhouette index, observing cohesion and dispersion within each cluster
# =============================================================================
