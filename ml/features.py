from collections import defaultdict
import time
import numpy as np
import joblib
import pickle 
import os
import pandas as pd 

class Flow:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.flow_iat_times = []
        self.prev_pkt_time = None
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.dst_port = None
        self.src_port = None 
        self.protocol = None
        self.flow_bytes = 0
        self.fwd_iat = []
        self.bwd_iat=[]
        self.fwd_headers = []
        self.bwd_headers = []
        self.fin_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.init_win_bytes_forward = 0
        self.init_win_bytes_backward = 0
        self.active_times = []
        self.idle_times = []
        self.last_activity_time = None
        self.activity_threshold = 1.0
        self.subflow_fwd_bytes = 0 
        self.subflow_bwd_bytes = 0 
        self.bulk_state_forward = 0
        self.bulk_state_backward = 0
        self.first_fwd_packet = True
        self.first_bwd_packet = True

    def update(self, pkt, direction='fwd' ):
        ts = pkt.time
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts
        pkt_len = len(pkt)
        self.packet_lengths.append(pkt_len)
        self.flow_bytes += pkt_len
        if hasattr(pkt, 'flags'):
            flags = pkt.flags
            if flags & 0x01:
                self.fin_flag_count +=1
            if flags & 0x08:
                self.psh_flag_count +=1
            if flags & 0x010:
                self.ack_flag_count +=1
        if hasattr(pkt, 'window'):
            if direction == 'fwd' and self.first_fwd_packet:
                self.init_win_bytes_forward = pkt.window
                self.first_fwd_packet = False
            elif direction == 'bwd' and self.first_bwd_packet:
                self.init_win_bytes_backward = pkt.window
                self.first_bwd_packet = False
        if direction == 'fwd':
            self.total_fwd_packets += 1
            self.fwd_packet_lengths.append(pkt_len)
            self.subflow_fwd_bytes += pkt_len
            header_len = 20
            if hasattr(pkt,'dataofs'):
                header_len += pkt.dataofs * 4
            else:
                header_len += 8
            self.fwd_headers.append(header_len)
        else:
            self.total_bwd_packets += 1
            self.bwd_packet_lengths.append(pkt_len)
            self.subflow_bwd_bytes += pkt_len
            header_len = 20
            if hasattr(pkt, 'dataofs'):
                header_len += pkt.dataofs * 4
            else:
                header_len += 8
            self.bwd_headers.append(header_len)
        if self.prev_pkt_time is not None:
            iat = (ts - self.prev_pkt_time) *1000000
            self.flow_iat_times.append(iat) 
            if iat > self.activity_threshold * 1000000:
                if self.last_activity_time is not None:
                    active_duration = self.prev_pkt_time - self.last_activity_time
                    if active_duration > 0:
                        self.active_times.append(active_duration * 1000000)
                    self.idle_times.append(iat)
                self.last_activity_time = ts
            if direction == 'fwd':
                self.fwd_iat.append(iat)
            else:
                self.bwd_iat.append(iat)

        self.prev_pkt_time = ts
        if hasattr(pkt, 'proto'):
            self.protocol = pkt.proto
        if hasattr(pkt, 'dport'):
            self.dst_port = pkt.dport
        if hasattr(pkt, 'sport'):
            self.src_port = pkt.sport

    def features(self):
        duration = (self.end_time - self.start_time) * 1000000 if self.end_time and self.start_time else 0
        total_packets = self.total_fwd_packets + self.total_bwd_packets
        total_fwd_bytes = sum(self.fwd_packet_lengths)
        total_bwd_bytes = sum(self.bwd_packet_lengths)
        duration_seconds = duration / 1000000 if duration > 0 else 1e-6
        flow_bytes_per_s = self.flow_bytes / duration_seconds if duration_seconds > 0 else 0
        flow_packets_per_s = total_packets / duration_seconds if duration_seconds > 0 else 0
        fwd_packets_per_s = self.total_fwd_packets / duration_seconds if duration_seconds > 0 else 0
        bwd_packets_per_s = self.total_bwd_packets / duration_seconds if duration_seconds > 0 else 0
        def safe_stats(data):
            if not data:
                return 0, 0, 0, 0, 0
            return np.mean(data), np.std(data), np.min(data), np.max(data), np.sum(data)
        fwd_mean, fwd_std, fwd_min, fwd_max, _ = safe_stats(self.fwd_packet_lengths)
        bwd_mean, bwd_std, bwd_min, bwd_max, _ = safe_stats(self.bwd_packet_lengths)
        pkt_mean, pkt_std, pkt_min, pkt_max, _ = safe_stats(self.packet_lengths)
        flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max, _ = safe_stats(self.flow_iat_times)
        fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max, fwd_iat_total = safe_stats(self.fwd_iat)
        bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max, bwd_iat_total = safe_stats(self.bwd_iat)
        fwd_header_len = np.sum(self.fwd_headers) if self.fwd_headers else 0
        bwd_header_len = np.sum(self.bwd_headers) if self.bwd_headers else 0
        active_mean, active_std, active_min, active_max, _ = safe_stats(self.active_times)
        idle_mean, idle_std, idle_min, idle_max, _ = safe_stats(self.idle_times)
        avg_packet_size = np.mean(self.packet_lengths) if self.packet_lengths else 0
        avg_fwd_segment_size = fwd_mean
        avg_bwd_segment_size = bwd_mean
        pkt_variance = np.var(self.packet_lengths) if self.packet_lengths else 0
        act_data_pkt_fwd = sum(1 for pkt_len in self.fwd_packet_lengths if pkt_len > 60)
        min_seg_size_forward = min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        return {
            'Destination Port': self.dst_port or 0,
            'Flow Duration': duration,
            'Total Fwd Packets':self.total_fwd_packets,
            'Total Length of Fwd Packets':total_fwd_bytes,
            'Fwd Packet Length Max':fwd_max,
            'Fwd Packet Length Min':fwd_min,
            'Fwd Packet Length Mean': fwd_mean,
            'Fwd Packet Length Std': fwd_std,
            'Bwd Packet Length Max':bwd_max,
            'Bwd Packet Length Min':bwd_min,
            'Bwd Packet Length Mean':bwd_mean,
            'Bwd Packet Length Std':bwd_std,
            'Flow Bytes/s' :flow_bytes_per_s,
            'Flow Packets/s':flow_packets_per_s,
            'Flow IAT Mean':flow_iat_mean,
            'Flow IAT Std' :flow_iat_std,
            'Flow IAT Max':flow_iat_max,
            'Flow IAT Min':flow_iat_min,
            'Fwd IAT Total':fwd_iat_total,
            'Fwd IAT Mean' :fwd_iat_mean,
            'Fwd IAT Std' :fwd_iat_std,
            'Fwd IAT Max' :fwd_iat_max,
            'Fwd IAT Min' :fwd_iat_min,
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean' :bwd_iat_mean,
            'Bwd IAT Std' :bwd_iat_std,
            'Bwd IAT Max' :bwd_iat_max,
            'Bwd IAT Min' :bwd_iat_min,
            'Fwd Header Length':fwd_header_len,
            'Bwd Header Length':bwd_header_len,
            'Fwd Packets/s' :fwd_packets_per_s,
            'Bwd Packets/s' :bwd_packets_per_s,
            'Min Packet Length':pkt_min,
            'Max Packet Length':pkt_max,
            'Packet Length Mean':pkt_mean,
            'Packet Length Std':pkt_std,
            'Packet Length Variance':pkt_variance,
            'FIN Flag Count':self.fin_flag_count,
            'PSH Flag Count':self.psh_flag_count,
            'ACK Flag Count':self.ack_flag_count,
            'Average Packet Size':avg_packet_size,
            'Subflow Fwd Bytes':self.subflow_fwd_bytes,
            'Init_Win_bytes_forward':self.init_win_bytes_forward,
            'Init_Win_bytes_backward':self.init_win_bytes_backward,
            'act_data_pkt_fwd':act_data_pkt_fwd,
            'min_seg_size_forward':min_seg_size_forward,
            'Active Mean':active_mean,
            'Active Max':active_max,
            'Active Min':active_min,
            'Idle Mean':idle_mean,
            'Idle Max':idle_max,
            'Idle Min':idle_min
        }

def create_feature_columns_file():

    print("Setting up feature coulms for threat detection system...")

    model_path = "model_rf.pkl"

    try:
        model = joblib.load(model_path)
        print(f"Loaded model from {model_path}")

        if hasattr(model, 'feature_names_in_'):
            feature_columns = model.feature_names_in_.tolist()
            print(f"Extracted {len(feature_columns)} feature names from model")
        else:
            print("Model doesn't have feature_names_in, using default features")
            feature_columns = get_default_cicids_features()

    except FileNotFoundError:
        print(" Model file not found, using default CICIDS 2017 features")
        feature_columns = get_default_cicids_features()
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Using default features")
        feature_columns = get_default_cicids_features()
    
    feature_columns_path = 'ml/features_columns.pkl'
    with open(feature_columns_path, 'wb') as f :
        pickle.dump(feature_columns, f)

    print(f"Saved feature columns to {feature_columns_path}")
    print(f"Total features: {len(feature_columns)}")

    print("\n first 10 features:")
    for i, feature in enumerate(feature_columns[:10]):
        print(f"  {i+1:2d}. {feature}")
    
    if len(feature_columns) > 10:
        print(f"... and {len(feature_columns) - 10} more")

    return feature_columns

def get_default_cicids_features():
    return [ 
        'Destination Port', 
        'Flow Duration', 
        'Total Fwd Packets', 
        'Total Length of Fwd Packets', 
        'Fwd Packet Length Max', 
        'Fwd Packet Length Min', 
        'Fwd Packet Length Mean', 
        'Fwd Packet Length Std', 
        'Bwd Packet Length Max', 
        'Bwd Packet Length Min', 
        'Bwd Packet Length Mean', 
        'Bwd Packet Length Std', 
        'Flow Bytes/s', 
        'Flow Packets/s', 
        'Flow IAT Mean', 
        'Flow IAT Std', 
        'Flow IAT Max', 
        'Flow IAT Min', 
        'Fwd IAT Total', 
        'Fwd IAT Mean', 
        'Fwd IAT Std', 
        'Fwd IAT Max', 
        'Fwd IAT Min', 
        'Bwd IAT Total', 
        'Bwd IAT Mean', 
        'Bwd IAT Std', 
        'Bwd IAT Max', 
        'Bwd IAT Min', 
        'Fwd Header Length', 
        'Bwd Header Length', 
        'Fwd Packets/s', 
        'Bwd Packets/s', 
        'Min Packet Length', 
        'Max Packet Length', 
        'Packet Length Mean', 
        'Packet Length Std', 
        'Packet Length Variance', 
        'FIN Flag Count', 
        'PSH Flag Count', 
        'ACK Flag Count', 
        'Average Packet Size', 
        'Subflow Fwd Bytes', 
        'Init_Win_bytes_forward', 
        'Init_Win_bytes_backward', 
        'act_data_pkt_fwd', 
        'min_seg_size_forward', 
        'Active Mean', 
        'Active Max', 
        'Active Min', 
        'Idle Mean', 
        'Idle Max', 
        'Idle Min'
    ]

def move_model_to_ml_directory():
    if os.path.exists("model_rf.pkl") and not os.path.exists("ml/model_rf.pkl"):
        import shutil
        shutil.copy("model_rf.pkl","ml/model_rf.pkl")
        print("Copied model to ml/model_rf.pkl")

def main():
    print("CICIDS 2017 Threat Detection System Setup")
    print("="*60)

    move_model_to_ml_directory()

    feature_columns = create_feature_columns_file()

    print("\n" + "="*60)
    print("="*60)

if __name__ == "__main__":
    main()