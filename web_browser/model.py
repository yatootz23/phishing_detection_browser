import numpy as np
import pandas as pd
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
import seaborn as sns
from matplotlib import pyplot as plt
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Activation, Dense, Flatten, Conv1D, MaxPool1D, Dropout, Input
from tensorflow.keras.losses import sparse_categorical_crossentropy
from tensorflow.keras.optimizers import Adam
from sklearn.model_selection import KFold
import tensorflow as tf
import random as python_random
from tensorflow.keras import layers
from tensorflow.keras.layers import Dense, Flatten, Conv1D, MaxPool1D, Activation, Dropout
from keras import regularizers
import features
from tensorflow import keras

def start_model():
    dataset = pd.read_csv("C:/Users/nellen/Desktop/Python/Django/web_browser/D3_allfeats.csv")
    dataset_2 = dataset.drop('domain', axis=1)
    dataset_shuffle = shuffle(dataset_2, random_state=42)
    y = dataset_2['label']
    X = dataset_2.drop('label', axis=1)
    X = np.array(X)
    y = np.array(y)
    X = X.reshape((X.shape[0], X.shape[1], 1))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    input_dim = X_train.shape
    batch_size = 128
    no_epochs = 40
    optimizer = Adam(learning_rate=0.001)
    verbosity = 2
    l1 = regularizers.l1(0.0001)
    # Define the model architecture
    #--Layer Name
    proposed = Sequential(name="Proposed_Model")
    #--Input Layer
    proposed.add(Conv1D(40, 3, activation='relu', input_shape=input_dim[1:],
                        kernel_regularizer=l1))
    #--Convo Layer 1
    proposed.add(Conv1D(14, 3, activation='relu', padding='same', name="CONV_1"))
    proposed.add(MaxPool1D(2, name="POOLING_1"))
    #--Convo Layer 2
    proposed.add(Conv1D(20, 3, activation='relu', padding='same', name="CONV_2", kernel_regularizer=l1))
    #--Convo Layer 3
    proposed.add(Conv1D(26, 3, activation='relu', padding='same', name="CONV_3"))
    #--Convo Layer 4
    proposed.add(Conv1D(32, 3, activation='relu', padding='same', name="CONV_4"))
    proposed.add(MaxPool1D(2, name="POOLING_2"))
    proposed.add(Dropout(0.5, name="DROPOUT_1"))
    ##-----Fully Connected Layer
    proposed.add(Flatten(name="FC"))
    ##--First Fully Connected Layer 5
    proposed.add(Dense(64, activation='relu', name='DENSE_1', kernel_regularizer=l1))
    proposed.add(Dropout(0.5, name="DROPOUT_2"))
    ##--Fully Connected Output Layer
    proposed.add(Dense(2, activation='softmax', name="OUTPUT"))
    # Compile the model
    proposed.compile(loss='sparse_categorical_crossentropy',
                    optimizer=optimizer, metrics=['accuracy'])
    proposed.fit(X_train, y_train, validation_split=0.1, 
                            batch_size=128, epochs=1000, verbose=2)
    proposed.save('C:/Users/nellen/Desktop/Python/Django/web_browser')

def load_model(url):
    proposed = keras.models.load_model('C:/Users/nellen/Desktop/Python/Django/web_browser')
    sample_data = features.featureExtraction(url)
    sample_data = np.array(sample_data)
    sample_data = sample_data.reshape((1, sample_data.shape[0], 1))
    probability = proposed.predict(sample_data) * 100
    predicted = np.argmax(probability, axis=-1)
    #probability[0, 1]
    return predicted


#sample_data = features.featureExtraction('https://www.google.com')
#print(sample_data)
#sample_data = np.array(sample_data)
#sample_data = sample_data.reshape((1, sample_data.shape[0], 1))
#print(start_model('http://9fjwyr.nodxteh.cn/coca/tb.php?v=ph1622811244172ms'))
#start_model()
#print(load_model('https://www.asus.com/Motherboards-Components/Motherboards/All-series/TUF-B450M-PLUS-GAMING/'))