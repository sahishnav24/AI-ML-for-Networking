import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))

from flask import Flask,render_template,jsonify,request
from realtime.capture import flows,lock,flow_stats
from realtime.classifier import classify_features
import threading
import time
import json
from datetime import datetime
from scapy.all import get_if_list
from collections import deque
import signal
app=Flask(__name__)
classified_flows=deque(maxlen=100)
active_flows_data=deque(maxlen=50)
system_stats={
    'start_time': datetime.now(),
    'total_packets': 0,
    'total_flows': 0,
    'threats_detected': 0,
    'last_update': datetime.now()
}
monitoring_active=False
sniffer_thread=None

def background_classifier():
    global classified_flows,system_stats

    timeout=30

    while True:
        try:
            current_time=time.time()
            expired_flows=[]

            with lock:
                for flow_key,flow in list(flows.items()):
                    if flow.end_time and (current_time-flow.end_time > timeout):
                        expired_flows.append((flow_key,flow))
            for flow_key,flow in expired_flows:
                     
                try:
                    features=flow.features()

                    result=classify_features(features)

                    src_ip,dst_ip,src_port,dst_port,protocol=flow_key
                    protocol_name={6:'TCP',17:'UDP',1:'ICMP'}.get(protocol,str(protocol))

                    flow_data={
                        'timestamp':datetime.now().isoformat(),
                        'src_ip':src_ip,
                        'dst_ip':dst_ip,
                        'src_port':src_port,
                        'dst_port':dst_port,
                        'protocol':protocol_name,
                        'label':result['label'],
                        'confidence':result.get('confidence',0),
                        'threat_level':result.get('threat_level','Unknown'),
                        'duration':features.get('Flow Duration',0)/1000000,
                        'packets':features.get('Total Fwd Packets',0) + flow.total_bwd_packets,
                        'bytes':features.get('Total Length of Fwd Packets',0) +sum(flow.bwd_packet_lengths)
                    }
                        
                    classified_flows.append(flow_data)

                    system_stats['total_flows']+=1
                    system_stats['last_update']=datetime.now()

                    if result['label']!='Normal Traffic':
                        system_stats['threats_detected']+=1
                        print(f"THREAT DETECTED: {result['label']}from{src_ip}:{src_port}")

                except Exception as e:
                    print(f"Error classifying flow:{e}")

                with lock:
                    flows.pop(flow_key,None)

            system_stats['total_packets']=flow_stats.get('total_packets',0)

            time.sleep(3)

        except Exception as e:
            print(f"Error in background classifier:{e}")
            time.sleep(5)

def active_flows_monitor():
    global active_flows_data
    
    while True:
        try:
            with lock:
                current_stats={
                    'timestamp':datetime.now().isoformat(),
                    'active_flows':len(flows),
                    'total_packets':flow_stats.get('total_packets',0),
                    'total_flows':flow_stats.get('total_flows',0),
                    'threats_detected':system_stats['threats_detected']
                }

            active_flows_data.append(current_stats)
            time.sleep(2)

        except Exception as e:
            print(f"Error in flow monitor:{e}")
            time.sleep(5)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    uptime=datetime.now()-system_stats['start_time']
    
    return jsonify({
        'monitoring_active':monitoring_active,
        'uptime_seconds':int(uptime.total_seconds()),
        'uptime_display':str(uptime).split('.')[0],
        'total_packets':system_stats['total_packets'],
        'total_flows':system_stats['total_flows'],
        'threats_detected':system_stats['threats_detected'],
        'active_flows':len(flows),
        'last_update':system_stats['last_update'].isoformat()
    })

@app.route('/api/flows')
def get_flows():
    limit=request.args.get('limit',50,type=int)
    flows_list=list(classified_flows)[-limit:]
    
    return jsonify({
        'flows':flows_list,
        'total_count':len(classified_flows)
    })

@app.route('/api/stats')
def get_stats():
    stats_list=list(active_flows_data)[-20:]
    
    return jsonify({
        'timeline_data':stats_list,
        'summary':{
            'total_flows':system_stats['total_flows'],
            'total_packets':system_stats['total_packets'],
            'threats_detected':system_stats['threats_detected'],
            'threat_percentage':(system_stats['threats_detected']/max(system_stats['total_flows'],1))*100
        }
    })

@app.route('/api/threats')
def get_threats():
    flows_list=list(classified_flows)

    threat_counts={}
    severity_counts={'Low':0,'Medium':0,'High':0}
    
    for flow in flows_list:
        label=flow['label']
        if label !='Normal Traffic':
            threat_counts[label]=threat_counts.get(label,0)+1
            
        threat_level=flow.get('threat_level','Low')
        severity_counts[threat_level]=severity_counts.get(threat_level,0)+1

    return jsonify({
        'threat_types':threat_counts,
        'severity_distribution':severity_counts,
        'recent_threats':[f for f in flows_list if f['label']!='Normal Traffic'][-10:]
    })

@app.route('/api/interfaces')
def get_interfaces():
    try:
        interfaces=get_if_list()
        return jsonify({'interfaces':interfaces})
    except Exception as e:
        return jsonify({'error':str(e),'interfaces':[]})

@app.route('/api/start_monitoring',methods=['POST'])
def start_monitoring():
    global monitoring_active,sniffer_thread
    
    if monitoring_active:
        return jsonify ({'error':'Monitoring already active'})
    
    try:
        data=request.get_json() or {}
        interface=data.get('interface',None)
        
        from realtime.capture import start_sniffer
        
        def run_sniffer():
            try:
                start_sniffer(interface)
            except Exception as e:
                print(f"Sniffer error:{e}")
                global monitoring_active
                monitoring_active=False

        sniffer_thread=threading.Thread(target=run_sniffer,daemon=True)
        sniffer_thread.start()
            
        monitoring_active=True
            
        return jsonify({
            'success':True,
            'message':f'Monitoring started on interface:{interface or "all interfaces"}'
        })
    
    except Exception as e:
        return jsonify({'error':str(e)})

@app.route('/api/stop_monitoring',methods=['POST'])
def stop_monitoring():
    global monitoring_active
    
    monitoring_active=False
    
    return jsonify({
        'success':True,
        'message':'Monitoring stopped'
    })

@app.route('/api/simulate_traffic',methods=['POST'])
def simulate_traffic():
    try:
        import random
        
        attack_types=['Normal Traffic','DoS','DDoS','Port Scanning','Brute Force','Bots','Web Attacks']
        
        for _ in range(5):
            attack_type=random.choice(attack_types)
            
            flow_data={
                'timestamp':datetime.now().isoformat(),
                'src_ip':f"192.168.1{random.randint(1,254)}",
                'dst_ip':f"10.0.0.{random.randint(1,254)}",
                'src_port':random.randint(1024,65535),
                'dst_port':random.choice([80,443,22,21,25,53,8080]),
                'protocol':random.choice(['TCP','UDP']),
                'label':attack_type,
                'confidence':random.uniform(0.7,0.99),
                'threat_level':random.choice(['Low','Medium','High']),
                'duration':random.uniform(0.1,30.0),
                'packets':random.randint(1,1000),
                'bytes': random.randint(64,100000)
            }
            
            classified_flows.append(flow_data)
            
            system_stats['total_flows']+=1
            if attack_type!='Normal Traffic':
                system_stats['threats_detected']+=1
                
        return jsonify({'success':True,'message':'Simulated traffic generated'})
        
    except Exception as e:
        return jsonify({'error':str(e)})

def signal_handler(sig,frame):
    print("\n Shutting down...")
    os._exit(0)

if __name__ =="__main__":
    print("Starting AI/ML Network Threat Detection Web Dashboard")
    print("="*60)
    
    signal.signal(signal.SIGINT,signal_handler)

    classifier_thread=threading.Thread(target=background_classifier,daemon=True)
    classifier_thread.start()
    print("Background classifier started")
    
    monitor_thread=threading.Thread(target=active_flows_monitor,daemon=True)
    monitor_thread.start()
    print("Flow monitor started")
    try:
        app.run(host='0.0.0.0',port=5000,debug=True,threaded=True)
    except KeyboardInterrupt:
        print("\n Dashboard shutting down...")
    except Exception as e:
        print(f" Error running dashboard:{e}")