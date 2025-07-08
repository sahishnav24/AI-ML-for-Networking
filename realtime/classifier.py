import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import joblib
import pandas as pd
import numpy as np
import pickle

try:
    model = joblib.load("ml/model_rf.pkl")
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model : {e} ")
    model = None

try:
    with open("ml/features_columns.pkl","rb") as f:
        feature_columns = pickle.load(f)
    print("feature columns loaded from file")
except:
    feature_columns = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size',
        'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Max', 'Idle Min'
        ]
    print(" Using default feature columns")

print(f"Expected features:{len(feature_columns)}")

def preprocess_features(feature_dict):
    processed_features = feature_dict.copy()

    for feat in feature_columns:
        if feat not in processed_features:
            processed_features[feat]=0
            
    for feat in processed_features:
        value = processed_features[feat]
        if np.isinf(value) or np.isnan(value):
            processed_features[feat] = 0
        try:
            processed_features[feat] = float(value)
        except:
            processed_features[feat] = 0

    return processed_features
def classify_features(feature_dict):
    if model is None:
        return{"label": "Error","probabilities": [], "error":"Model not loaded"}
    
    try:
        processed_features = preprocess_features(feature_dict)

        df = pd.DataFrame([processed_features])[feature_columns]

        df = df.replace([np.inf, -np.inf], 0)
        df = df.fillna(0)

        prediction = model.predict(df)[0]
        probabilities = model.predict_proba(df)[0]

        class_names= model.classes_

        prob_dict = {class_names[i] : float(probabilities[i]) for i in range(len(class_names))}

        threat_level = "Low"
        if prediction != "Normal Traffic":
            max_prob = max(probabilities)
            if max_prob > 0.8:
                 threat_level = "High"
            elif max_prob >0.5:
                threat_level = "Medium"

        return{
            "label" : prediction,
            "probabilities" : probabilities.tolist(),
            "prob_dict": prob_dict,
            "threat_level": threat_level,
            "confidence": float(max(probabilities))
        }
    
    except Exception as e:
        print(f"Error in classification : {e}")
        return {
            "label" : "Error",
            "probabilities": [],
            "error":str(e),
            "threat_level": "unknown",
            "confidence": 0.0
        }




    
    

