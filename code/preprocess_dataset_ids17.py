import pandas as pd
import numpy as np
import os

# Loading csv files of IDS2017 dataset
df1 = pd.read_csv("./Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df2 = pd.read_csv("./Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
df3 = pd.read_csv("./Friday-WorkingHours-Morning.pcap_ISCX.csv")
df4 = pd.read_csv("./Monday-WorkingHours.pcap_ISCX.csv")
df5 = pd.read_csv("./Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
df6 = pd.read_csv("./Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
df7 = pd.read_csv("./Tuesday-WorkingHours.pcap_ISCX.csv")
df8 = pd.read_csv("./Wednesday-workingHours.pcap_ISCX.csv")


# Concatenation of dataframes
df = pd.concat([df1, df2])
del df1, df2
df = pd.concat([df, df3])
del df3
df = pd.concat([df, df4])
del df4
df = pd.concat([df, df5])
del df5
df = pd.concat([df, df6])
del df6
df = pd.concat([df, df7])
del df7
df = pd.concat([df, df8])
del df8


for i in df.columns:
    df = df[df[i] != "Infinity"]
    df = df[df[i] != np.nan]
    df = df[df[i] != ",,"]
df[["Flow Bytes/s", " Flow Packets/s"]] = df[["Flow Bytes/s", " Flow Packets/s"]].apply(
    pd.to_numeric
)


# Removing these columns as their value counts are zero
df.drop([" Bwd PSH Flags"], axis=1, inplace=True)
df.drop([" Bwd URG Flags"], axis=1, inplace=True)
df.drop(["Fwd Avg Bytes/Bulk"], axis=1, inplace=True)
df.drop([" Fwd Avg Packets/Bulk"], axis=1, inplace=True)
df.drop([" Fwd Avg Bulk Rate"], axis=1, inplace=True)
df.drop([" Bwd Avg Bytes/Bulk"], axis=1, inplace=True)
df.drop([" Bwd Avg Packets/Bulk"], axis=1, inplace=True)
df.drop(["Bwd Avg Bulk Rate"], axis=1, inplace=True)

# Replacing nans, infs with zero's
df.replace([np.inf, -np.inf, -np.nan, np.nan], 0, inplace=True)

X = df.drop(" Label", 1)
New_y = np.array(df[" Label"])

labels = np.reshape(New_y, (New_y.shape[0], 1))
dataset = X.to_numpy()

print(labels)

print("Shape of dataset(X) is", dataset.shape)
print("Shape of labels(Y) is", labels.shape)


df = pd.DataFrame(dataset)
y =  labels
print(y)
# Normalsing Dataset
X = (df - df.min()) / (df.max() - df.min() + 1e-5)

#print("Shape of dataset(X) is", X.shape)
#print("Shape of labels(Y) is", y.shape)

#np.save("X_whole",X)
#np.save("y_whole",y)

names = ['BENIGN', 'DoS Hulk', 'PortScan', 'DDoS', 'FTP-Patator', 'DoS slowloris', 'DoS Slowhttptest', 'SSH-Patator', 'Bot', 'Web Attack � Brute Force', 'DoS GoldenEye', 'Web Attack � XSS', 'Infiltration', 'Web Attack � Sql Injection', 'Heartbleed']
path = "CICIDS2017_Class-wise-normalized_datasets"
os.mkdir(path)
for name in names:
  X_temp = []
  for i in range(0,y.shape[0]):
    if y[i,0] == name:
      X_temp.append((X.iloc[i,:].values))
  X_temp = np.array(X_temp)
  #print(X_temp.shape)
  np.save(F"CICIDS2017_Class-wise-normalized_datasets/{name}", X_temp)


'''
names = ['BENIGN.npy','DoSGoldenEye.npy','DoSslowloris.npy',  'Infiltration.npy','WebAttackBruteForce.npy',
'Bot.npy','DoSHulk.npy', 'FTP-Patator.npy','PortScan.npy', 'WebAttackSqlInjection.npy',
'DDoS.npy', 'DoSSlowhttptest.npy', 'Heartbleed.npy', 'SSH-Patator.npy', 'WebAttackXSS.npy'
]
df = pd.DataFrame()
for idx,name in enumerate(names):
  print("loading file:",name)
  file = np.load(name)
  temp2 = pd.Series([idx for x in range(file.shape[0])])
  #file[:,-1] = idx
  temp = pd.DataFrame(file)
  temp[' Label'] =temp2# pd.concat([temp, temp2], axis=1)
  print(temp.head())
  df = pd.concat([df,temp], axis=0)

print(df.shape)  
  
#df[' Label'] = (df[' Label'].apply(lambda x: np.random.randint(15, 20) if x == 0 else x)) 
print("number of unique labels are",df[' Label'].nunique())
print("unique labels in total_ds",df[' Label'].unique())
df2=df 
unique_label=df2[' Label'].unique()
print("labels are:",unique_label)
print("Before removing duplicates",Counter(df2[' Label']))
print("Total no of rows before removing duplicates",df2.shape[0])
df2.drop_duplicates(inplace=True)
print("After removing duplicates",Counter(df2[' Label']))
print("Total no of rows after removing duplicates",df2.shape[0])
y = df2.pop(df.columns[-1]).to_frame()
#for column in df.columns:
 # df[column] = (df[column] - df[column].min()) / (df[column].max() - df[column].min() + 1e-5)

multilabel_idx=~df2.duplicated(keep='first')
   # print("Number of multilabel rows",Counter(multilabel_idx))
   
df2=df2[multilabel_idx]
y=y[multilabel_idx]
print("Total number of rows after removing multilabel rows",df2.shape[0])
print("After removing multi_label duplicates",Counter(y[' Label']))
df2=pd.concat([df2,y],axis=1)    
for label in unique_label:
  sub_dataset=df2[df2[' Label']==label]
  np.save("./CIL/"+str(label)+".npy",sub_dataset)'''
