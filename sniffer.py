import sys
from scapy.all import * 
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QSpinBox, QTableWidget

# for monitor fucntionality? 
from scapy.config import conf
conf.use_pcap = True

from scapy.all import get_if_list, get_if_addr

print(f"Available interfaces: ")
for iface in get_if_list():
    print(f"- {iface}: {get_if_addr(iface)}")

class Settings():
    def __init__(self, protocol='TCP', packet_count=1, save_to_file=False):
        self.protocol = protocol
        self.packet_count = packet_count
        self.save_to_file = save_to_file

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        self._protocol = value

    @property
    def packet_count(self):
        return self._packet_count

    @packet_count.setter
    def packet_count(self, value):
        self._packet_count = value

    @property
    def saveToFile(self):
        return self._save_to_file

    @saveToFile.setter
    def saveToFile(self, value):
        self._save_to_file = value

class MyWidget(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        # window setup 
        self.setup_ui()
        self.setup_connections()

        # Create settings object
        self.settings = Settings()
        
        self.protocol = None
        self.packet_count = 1
        self.saveToFile = False
        self.captured_packets = []

    def setup_ui(self):
        # set main layout 
        self.layout = QVBoxLayout()
        self.button_layout = QHBoxLayout()

        # create widgets 
        self.label = QLabel("Choose Protocol (1) to Monitor")
            # buttons for protocol selection
        self.TCP_Btn = QPushButton("TCP")
        self.UDP_Btn = QPushButton("UDP")
        self.ARP_Btn = QPushButton("ARP")


        # add widgets to layout 
        self.layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignCenter)

        # add buttons to layout 
        for btn in [self.TCP_Btn, self.UDP_Btn, self.ARP_Btn]:
            btn.setFixedSize(80, 30)  # Set button size
            self.button_layout.addWidget(btn)  # Add buttons to horizontal layout
        self.layout.addLayout(self.button_layout)

        self.button_layout.setSpacing(15)
        self.layout.setContentsMargins(10,10,10,10)


        self.pcLabel = QLabel("Set number of packets to monitor")
        self.layout.addWidget(self.pcLabel, alignment=Qt.AlignmentFlag.AlignCenter)

        # input field for packet count 
        self.spin_box = QSpinBox()
        self.spin_box.setRange(1, 10000)  # Set min and max values
        self.spin_box.setValue(1)  # Default value
        self.spin_box.setFixedSize(50,50)
        self.layout.addWidget(self.spin_box, alignment=Qt.AlignmentFlag.AlignCenter)

        # Button to get packet count value
        self.packetCount_Btn = QPushButton("Set Packet Count")
        self.packetCount_Btn.setFixedSize(150,35) # btn size 
        self.layout.addWidget(self.packetCount_Btn,alignment=Qt.AlignmentFlag.AlignCenter)

        # save to file label 
        self.saveLabel = QLabel("Save to pcap file?")
        self.layout.addWidget(self.saveLabel, alignment=Qt.AlignmentFlag.AlignCenter)

        # Small horizontal layout to position the save button properly
        self.save_layout = QHBoxLayout()
        self.save_Btn = QPushButton("Yes, Save!")
        self.save_Btn.setFixedSize(120, 35)  # Set fixed size
        self.save_layout.addWidget(self.save_Btn, alignment=Qt.AlignmentFlag.AlignCenter)  # Add to horizontal layout
        self.layout.addLayout(self.save_layout)  # Add to the main layout

        # Execute button
        self.executeBtn = QPushButton("Run Sniffer")
        self.executeBtn.setFixedSize(150, 40)  # Set fixed width to prevent stretching
        self.layout.addWidget(self.executeBtn, alignment=Qt.AlignmentFlag.AlignCenter)  # Center alignment in PySide6

        self.resetBtn = QPushButton("Reset")
        self.resetBtn.setFixedSize(150, 40)
        self.layout.addWidget(self.resetBtn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setWindowTitle("Packet Sniffer by Greg")


        # packets table 
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Source IP", "Destination IP", "Protocol", "Length" ])
        self.layout.addWidget(self.packet_table)



        self.setLayout(self.layout)


    def setup_connections(self):
        # connect buttons 
        self.TCP_Btn.clicked.connect(lambda: self.set_protocol("TCP"))
        self.UDP_Btn.clicked.connect(lambda: self.set_protocol("UDP"))
        self.ARP_Btn.clicked.connect(lambda: self.set_protocol("ARP"))
        self.packetCount_Btn.clicked.connect(self.get_packetCount)
        self.save_Btn.clicked.connect(lambda: self.save_to_file(True))
        self.executeBtn.clicked.connect(self.runSniffer)
        self.resetBtn.clicked.connect(self.reset_inputs)



    def save_to_file(self, saveToFile):
        self.settings.saveToFile = saveToFile
        print(f"/ SaveToFile set to: {self.settings.saveToFile} /")


    def set_protocol(self, protocol):
        self.settings.protocol = protocol
        print(f"/ Protocol set to: {self.settings.protocol} /")


    def get_packetCount(self):
        self.settings.packet_count = self.spin_box.value()
        print(f"/ Packet Count set to: {self.settings.packet_count} /")


    def runSniffer(self):
        # run 
        protocol_filter = self.settings.protocol.lower()
        if protocol_filter in ["tcp", "udp", "arp"]:
            bpf_filter = protocol_filter
        else:
            print(f"** WARNING : Invalid protocol '{protocol_filter}', defaulting to 'tcp' **")
            bpf_filter = "tcp"

        packet_count = self.settings.packet_count
        
        self.captured_packets = []

        print("** REVVING UP SNIFFER **")
        packets = sniff(
            iface= conf.iface,
            stop_filter=self.stop_when_count_reached, 
            filter=bpf_filter,
            prn=lambda pkt: pkt.summary(), 
            timeout=20)

        # save to file if enabled 
        if self.saveToFile:
            wrpcap("captured_packets.pcap", packets)
            print("\n** Packets saved to captured_packets.pcap **")

        print("\n ===   ALL PACKETS COLLECTED   ===")
        print("\n +    press reset to run again   +")


    # determines when to stop the sniff() from running once enough of the specified protocol packets are received 
    def stop_when_count_reached(self, pkt):
        protocol_map = {"tcp": TCP, "udp": UDP, "arp": Raw}  # ARP often appears in Raw layer

        if self.settings.protocol.lower() in protocol_map:
            protocol_layer = protocol_map[self.settings.protocol.lower()]
            if pkt.haslayer(protocol_layer):
                self.captured_packets.append(pkt)

        return len(self.captured_packets) >= self.settings.packet_count

    def reset_inputs(self): 
        self.spin_box.setValue(1)  # Reset packet count
        self.protocol = None  # Reset protocol
        self.saveToFile = False  # Reset save to file option
        self.captured_packets = []  # Clear captured packets
        print("\n === Inputs have been reset === ")



if __name__ == "__main__":
    app = QtWidgets.QApplication([])

    widget = MyWidget()
    widget.resize(600, 600)
    widget.show()

    sys.exit(app.exec())