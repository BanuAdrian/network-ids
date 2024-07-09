import customtkinter as gui
import tkinter as tk
import pandas as pd
import socket
import threading
import os
import time
import pathlib
from tkinter import filedialog
from scapy.all import *
from CTkListbox import *
from CTkMessagebox import CTkMessagebox

number_of_packets = 0
capturing_packets = False
loading_pcap = False
first_flagged_packet = True
packets = []
loaded_packets = []
rules_data_frame = []
all_packets_listbox = []
flagged_packets_listbox = []
all_packets_frame = []
flagged_packets_frame = []
packet_info = []
app = []

def read_rules():
    rules_file_name = 'rules.txt'
    rules_file = open(rules_file_name, 'r')
    rules_lines = rules_file.readlines()
    rules_list = []
    for line in rules_lines:
        if line.startswith('alert'):
            rules_list.append(line)
    rules_file.close()
    return rules_list

def parse_rules(rules_list):
    global rules_data_frame
    data = []
    rules_data_frame = []
    for rule in rules_list:
        rule_words = rule.split(" ")
        
        try:
            message = " ".join([rule_words[i] for i in range(7, len(rule_words))])
        except:
            message = ""
            pass

        data.append(dict(protocol = rule_words[1].lower(), 
                         src_ip = rule_words[2].lower(),
                         src_port = rule_words[3].lower(),
                         direction = rule_words[4].lower(),
                         dest_ip = rule_words[5].lower(),
                         dest_port = rule_words[6].lower(),
                         message = message.rstrip()))

        rules_data_frame = pd.DataFrame(data)

parse_rules(read_rules())

def pcap_packet_handler(packet):
    global number_of_packets
    global capturing_packets
    global first_flagged_packet
    global packets
    if loading_pcap:
        number_of_packets += 1
        packets.append(packet)
        flagged_packet, rule_number = verify_packet(packet)
        if flagged_packet == True:
            if first_flagged_packet:
                CTkMessagebox(title = "Alert!", message = "Flagged packet found!", icon = "warning", option_1 = "OK")
                first_flagged_packet = False
            flagged_packets_listbox.insert('Packet ' + str(number_of_packets), [str(number_of_packets), packet, rules_data_frame.loc[rule_number].iat[6]])
        all_packets_listbox.insert('Packet ' + str(number_of_packets), [str(number_of_packets), packet])

def packet_handler(packet):
    global number_of_packets
    global capturing_packets
    global first_flagged_packet
    global packets
    if capturing_packets:
        number_of_packets += 1
        packets.append(packet)
        flagged_packet, rule_number = verify_packet(packet)
        if flagged_packet == True:
            if first_flagged_packet:
                CTkMessagebox(title = "Alert!", message = "Flagged packet found!", icon = "warning", option_1 = "OK")
                first_flagged_packet = False
            flagged_packets_listbox.insert('Packet ' + str(number_of_packets), [str(number_of_packets), packet, rules_data_frame.loc[rule_number].iat[6]])
        all_packets_listbox.insert('Packet ' + str(number_of_packets), [str(number_of_packets), packet])

def verify_packet(packet):
    if 'IP' in packet:
        try:
            pkt_protocol = protocol_number_to_name(packet['IP'].proto).lower()
            pkt_src_ip = packet['IP'].src
            pkt_src_port = packet['IP'].sport
            pkt_dest_ip = packet['IP'].dst
            pkt_dest_port = packet['IP'].dport
            
            for i in range(len(rules_data_frame)):
                if rules_data_frame.loc[i].iat[0] != 'any':
                    flagged_protocol = rules_data_frame.loc[i].iat[0]
                else:
                    flagged_protocol = pkt_protocol

                if rules_data_frame.loc[i].iat[1] != 'any':
                    flagged_src_ip = rules_data_frame.loc[i].iat[1]
                else:
                    flagged_src_ip = pkt_src_ip
                
                if rules_data_frame.loc[i].iat[2] != 'any':
                    flagged_src_port = rules_data_frame.loc[i].iat[2]
                else:
                    flagged_src_port = pkt_src_port

                if rules_data_frame.loc[i].iat[4] != 'any':
                    flagged_dest_ip = rules_data_frame.loc[i].iat[4]
                else:
                    flagged_dest_ip = pkt_dest_ip

                if rules_data_frame.loc[i].iat[5] != 'any':
                    flagged_dest_port = rules_data_frame.loc[i].iat[5]
                else:
                    flagged_dest_port = pkt_dest_port

                if (str(flagged_protocol).strip() == str(pkt_protocol).strip() and
                    str(flagged_src_ip).strip() == str(pkt_src_ip).strip() and
                    str(flagged_src_port).strip() == str(pkt_src_port).strip() and
                    str(flagged_dest_ip).strip() == str(pkt_dest_ip).strip() and
                    str(flagged_dest_port).strip() == str(pkt_dest_port).strip()):

                        # print("Flagged packet")
                        return True, i
        except:
            pass
        
    return False, -1
    
def protocol_number_to_name(protocol_number):
    for name, number in vars(socket).items():
        if name.startswith("IPPROTO") and protocol_number == number:
            return name[8:]

def on_closing_packet_info():
    packet_info.withdraw()
    # packet_info.quit()

def on_closing_main_app():
    app.withdraw()
    app.quit()

def show_packet_info(selected_value):
    global packet_info
    packet_number = selected_value[0]
    selected_packet = selected_value[1]
    packet_info = gui.CTk()
    packet_arrival_time = time.localtime(int(selected_packet.time))
    formatted_packet_arrival_time = str(packet_arrival_time.tm_hour) + ":" + str(packet_arrival_time.tm_min)+ ":" + str(packet_arrival_time.tm_sec)
    packet_info.title('Packet ' + str(packet_number) + " - " + formatted_packet_arrival_time)
    packet_info.grid_rowconfigure(0, weight = 1)
    packet_info.grid_columnconfigure(0, weight = 1)
    packet_info_textbox = gui.CTkTextbox(packet_info, width = 600, height = 800)
    packet_info_textbox.grid(row = 0, column = 0, sticky = "nsew")
    packet_info_textbox.insert("0.0", str(selected_packet.show(dump = True)) + ' \n HEXDUMP \n' + str(hexdump(selected_packet, dump = True)))
    packet_info_textbox.configure(state = "disabled")
    packet_info.geometry('800x600')
    packet_info.protocol("WM_DELETE_WINDOW", on_closing_packet_info)

def show_all_packets():
    all_packets_frame.grid(row=0, column=1, sticky="nsew")
    flagged_packets_frame.grid_forget()

def show_flagged_packets():
    flagged_packets_frame.grid(row=0, column=1, sticky="nsew")
    all_packets_frame.grid_forget()

def start_capturing_packets():
    global capturing_packets
    capturing_packets = True
    print('Started capturing')

def stop_capturing_packets():
    global capturing_packets
    capturing_packets = False
    print('Stopped capturing')

def save_pcap():
    now = datetime.now()
    current_time = now.strftime("%H-%M-%S")
    pcap_file = 'log-' + str(current_time) + '.pcap'
    wrpcap(pcap_file, packets)


def load_pcap():
    global loaded_packets
    global loading_pcap
    stop_capturing_packets()
    load_pcap_window = tk.Tk()
    load_pcap_window.withdraw()
    pcap_file_path = filedialog.askopenfilename()
    if pcap_file_path != ():
        pcap_file = os.path.basename(pcap_file_path)
        if pathlib.Path(pcap_file).suffix == '.pcap':
            loading_pcap = True
            loaded_packets = rdpcap(pcap_file)
            for packet in loaded_packets:
                try:
                    pcap_packet_handler(packet)
                except:
                    pass
            loading_pcap = False

def configure_rules():
    os.system('code -n --no-sandbox --user-data-dir /home/adrian rules.txt')

def reload_rules():
    parse_rules(read_rules())

gui.set_appearance_mode('light')
gui.set_default_color_theme('blue')

app = gui.CTk()
app.title('MDS Intrusion Detection System')
app.geometry('1280x720')

app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=1)

navigation_frame = gui.CTkFrame(app, corner_radius=0)
navigation_frame.grid(row=0, column=0, sticky="nsew")
navigation_frame.grid_rowconfigure(3, weight=1)

navigation_frame_label = gui.CTkLabel(navigation_frame, text="Intrusion Detection System", compound="left", font=gui.CTkFont(size=15, weight="bold"))

navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)


all_packets_button = gui.CTkButton(navigation_frame, corner_radius=0, height=40, border_spacing=10, text="All Packets", fg_color="transparent",  
                                   text_color=("gray10", "gray90"),  hover_color=("gray70", "gray30"), anchor="w", command=show_all_packets)
all_packets_button.grid(row=1, column=0, sticky="ew")

flagged_packets_button = gui.CTkButton(navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Flagged Packets", fg_color="transparent", 
                                       text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w", command=show_flagged_packets)
flagged_packets_button.grid(row=2, column=0, sticky="ew")


appearance_mode_menu = gui.CTkOptionMenu(navigation_frame, values=["Light", "Dark", "System"], command = lambda new_appearance: 
                                                                                                         gui.set_appearance_mode(new_appearance))
appearance_mode_menu.grid(row=3, column=0, padx = 20, pady = 20, sticky = "s")


all_packets_frame = gui.CTkFrame(app, corner_radius=0, fg_color="transparent")
all_packets_frame.grid_columnconfigure(0, weight=1)
all_packets_frame.grid_rowconfigure(0, weight=1)
all_packets_frame.grid_rowconfigure(1, weight=10)
all_packets_frame.grid_rowconfigure(2, weight=1)

all_packets_label = gui.CTkLabel(all_packets_frame, text = "ALL PACKETS", font = gui.CTkFont(size=20, weight="bold"))
all_packets_label.grid(row = 0, column = 0)

all_packets_listbox = CTkListbox(all_packets_frame, command = show_packet_info)
all_packets_listbox.grid(row=1, column=0, padx = 5, pady = 5, sticky="nsew")

all_packets_start_capturing_packets_button  = gui.CTkButton(all_packets_frame, text = "Start Capturing", width = 100, height = 50, command = start_capturing_packets)
all_packets_start_capturing_packets_button.grid(row = 2, column = 0, padx = 20, sticky="w")

all_packets_stop_capturing_packets_button  = gui.CTkButton(all_packets_frame, text = "Stop Capturing", width = 100, height = 50, command = stop_capturing_packets)
all_packets_stop_capturing_packets_button.grid(row = 2, column = 0, padx = 150, sticky="w")

all_packets_save_pcap_button = gui.CTkButton(all_packets_frame, text = "Save PCAP", width = 100, height = 50, command = save_pcap)
all_packets_save_pcap_button.grid(row = 2, column = 0, padx = 280, sticky="w")

all_packets_load_pcap_button = gui.CTkButton(all_packets_frame, text = "Load PCAP", width = 100, height = 50, command = load_pcap)
all_packets_load_pcap_button.grid(row = 2, column = 0, padx = 410, sticky="w")


flagged_packets_frame = gui.CTkFrame(app, corner_radius=0, fg_color="transparent")
flagged_packets_frame.grid_columnconfigure(0, weight=1)
flagged_packets_frame.grid_rowconfigure(0, weight=1)
flagged_packets_frame.grid_rowconfigure(1, weight=10)
flagged_packets_frame.grid_rowconfigure(2, weight=1)

flagged_packets_label = gui.CTkLabel(flagged_packets_frame, text = "FLAGGED PACKETS", font = gui.CTkFont(size=20, weight="bold"))
flagged_packets_label.grid(row = 0, column = 0)

flagged_packets_listbox = CTkListbox(flagged_packets_frame, command=show_packet_info)
flagged_packets_listbox.grid(row=1, column=0, padx = 5, pady = 5, sticky="nsew")

flagged_packets_configure_rules_button  = gui.CTkButton(flagged_packets_frame, text = "Configure Rules", width = 100, height = 50, command = configure_rules)
flagged_packets_configure_rules_button.grid(row = 2, column = 0, padx = 20, sticky="w")

flagged_packets_reload_rules_button  = gui.CTkButton(flagged_packets_frame, text = "Reload Rules", width = 100, height = 50, command = reload_rules)
flagged_packets_reload_rules_button.grid(row = 2, column = 0, padx = 200, sticky="w")


sniffing_thread = threading.Thread(target = sniff, kwargs={'prn': packet_handler}, daemon=True)
sniffing_thread.start()

app.protocol("WM_DELETE_WINDOW", on_closing_main_app)
app.mainloop()

