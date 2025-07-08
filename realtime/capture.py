import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'..')))
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from ml.features import Flow
from realtime.classifier import classify_features
import threading
import time
from collections import defaultdict
lock = threading.Lock()  
flows = {}   
flow_stats = defaultdict(int)     
timeout = 30
CAPTURE_INTERFACE = None

def get_flow_key(pkt):
    if IP not in pkt:
        return None
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    protocol = pkt[IP].proto

    src_port = 0
    dst_port = 0

    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport  

    if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
        return (src_ip, dst_ip, src_port, dst_port, protocol, 'forward')  
    else:
        return (dst_ip, src_ip, dst_port, src_port, protocol, 'reverse')  
    
def determine_direction(pkt, flow_key):
    if IP not in pkt:
        return'fwd'
    
    src_ip = pkt[IP].src

    if src_ip == flow_key[0]:
        return 'fwd'
    else:
        return 'bwd'
    
def extract_packet_info(pkt):
    info={}

    if TCP in pkt:
        tcp_layer=pkt[TCP]
        info['flags']=tcp_layer.flags
        info['window']=tcp_layer.window
        info['dataofs']=tcp_layer.dataofs if hasattr(tcp_layer,'dataofs') else 5
    elif UDP in pkt:
        info['flags']=0
        info['window']=0
        info['dataofs']=0

    if IP in pkt:
        info['proto']=pkt[IP].proto
        info['sport']=0
        info['dport']=0

        if TCP in pkt:
            info['sport']=pkt[TCP].sport
            info['dport']=pkt[TCP].dport
        elif UDP in pkt:
            info['sport']=pkt[UDP].sport
            info['dport']=pkt[UDP].dport

    return info

def process_packet(pkt):
    try:
        flow_data = get_flow_key(pkt)
        if not flow_data:
            return
        
        flow_key=flow_data[:5]

        direction=determine_direction(pkt,flow_key)

        pkt_info=extract_packet_info(pkt)

        for key,value in pkt_info.items():
            setattr(pkt,key,value)

        with lock:
            if flow_key not in flows:
                flows[flow_key]=Flow()
                flow_stats['total_flows'] += 1

            flows[flow_key].update(pkt,direction)
            flow_stats['total_packets'] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

def flow_cleaner():
    print("Flow cleaner thread started")
    
    while True:
        try:
            current_time=time.time()
            expired_flows=[]

            with lock:
                for flow_key, flow in list(flows.items()):
                    if flow.end_time and (current_time-flow.end_time>timeout):
                        expired_flows.append((flow_key,flow))

            for flow_key, flow in expired_flows:
                try:
                    features=flow.features()

                    result=classify_features(features)

                    src_ip, dst_ip, src_port, dst_port, protocol = flow_key
                    protocol_name={6:'TCP',17:'UDP',1:'ICMP'}.get(protocol,str(protocol))

                    print(f"\n Flow Classification:")
                    print(f"   {src_ip}:{src_port}->{dst_ip}:{dst_port}({protocol_name})")
                    print(f"   Prediction:{result['label']}")
                    print(f"   Confidence:{result.get('confidence',0):.3f}")
                    print(f"   Threat Level:{result.get('threat_level','Unknown')}")

                    if 'prob_dict' in result:
                        print(f" Top Probabilities:")
                        sorted_probs=sorted(result['prob_dict'].items(),
                                            key=lambda x:x[1],reverse=True)[:3]
                        for cls,prob in sorted_probs:
                            print(f" {cls}: {prob:.3f}")

                    if result['label']!='Normal Traffic':
                        print(f" THREAT DETECTED: {result['label']}")

                    flow_stats['classified_flows']+=1

                except Exception as e:
                    print(f" Error classifying flow {flow_key}: {e}")

                with lock:
                    flows.pop(flow_key,None)

            if flow_stats['total_packets']>0 and flow_stats['total_packets']% 1000==0:
                print(f"\n Statistics:")
                print(f"   Active Flows: {len(flows)}")
                print(f"   Total Flows:{flow_stats['total_flows']}")
                print(f"   Total packets:{flow_stats['total_packets']}")
                print(f"   Classified Flows:{flow_stats['classified_flows']}")

            time.sleep(5)
            
        except Exception as e:
            print(f"Error in flow cleaner: {e}")
            time.sleep(5)

def packet_filter(pkt):
    return IP in pkt

def start_sniffer(interface=None):
    global CAPTURE_INTERFACE
    CAPTURE_INTERFACE=interface

    print(" Starting AI/ML Network Threat Detection System")
    print("="*60)

    available_interfaces=get_if_list()
    print(f"Available network interfaces:{available_interfaces}")

    if interface:
        if interface in available_interfaces:
            print(f"Capturing on interface:{interface}")
        else:
            print(f" Interface '{interface}' not found. Using default interface.")
            interface=None
    else:
        print("Capturing on all interfaces")

    cleaner_thread=threading.Thread(target=flow_cleaner,daemon=True)
    cleaner_thread.start()

    print("Starting packet capture...(Press Ctrl+C to stop)")
    print("="*60)

    try:
        sniff(
            prn=process_packet,
            filter="ip",
            store=False,
            iface=interface,
            lfilter=packet_filter
        )                
    except KeyboardInterrupt:
        print("\n Stopping packet capture...")
        print(f"Final Statistics:")
        print(f"  Total Flows: {flow_stats['total_flows']}")
        print(f"  Total Packets: {flow_stats['total_packets']}")
        print(f"  Classified Flows: {flow_stats['classified_flows']}")


    except Exception as e:
        print(f"Error during packet capture: {e}")

def get_active_interface():
    import psutil

    try:
        net_stats=psutil.net_io_counters(pernic=True)

        best_interface=None
        max_bytes=0

        for interface, stats in net_stats.items():
            total_bytes=stats.bytes_sent+stats.bytes_recv
            if total_bytes>max_bytes:
                max_bytes=total_bytes
                best_interface=interface

        return best_interface
    except:
        common_names=['eth0','wlan0','Wi-Fi','Ethernet','en0']
        available=get_if_list()

        for name in common_names:
            if name in available:
                return name
            
        return None
    
if __name__ =="__main__":
    print("Network Threat Detection-Packet Capture Module")

    active_interface=get_active_interface()

    if active_interface:
        print(f" Auto-detected active interface: {active_interface}")
        start_sniffer(active_interface)
    else:
        print(" Could not auto-detect interface. Starting with default...")
        start_sniffer()