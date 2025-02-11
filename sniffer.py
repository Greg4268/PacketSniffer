from PySide6.QtWidgets import *
from PySide6.QtCore import Qt, QThread, Signal
from PySide6 import QtCore, QtWidgets, QtGui
from scapy.all import * 
import sys
import datetime

# for monitor fucntionality? 
from scapy.config import conf
conf.use_pcap = True


# user options obj
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

# multithreading the sniffing task
class SnifferThread(QThread):
    packet_captured = Signal(object)

    def __init__(self, iface="en0", filter_protocol="tcp", packet_count=10):
        super().__init__()
        self.iface = iface
        self.filter_protocol = filter_protocol.lower()  # 🟢 Ensure lowercase
        self.packet_count = packet_count

    def run(self):
        try:
            print(f"Starting sniffing on {self.iface} for {self.packet_count} {self.filter_protocol.upper()} packets")
            sniff(iface=self.iface, filter=self.filter_protocol, count=self.packet_count,
                  prn=lambda pkt: self.packet_captured.emit(pkt), store=False)
        except Exception as e:
            print(f"❌ Sniffer error: {e}")


class PacketTableWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Captured Packets")
        self.resize(800,400)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Table Widget 
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Source IP", "Destination IP", "Protocol", "Length"])
        self.layout.addWidget(self.packet_table)

        # Button to clear table
        self.clear_button = QPushButton("Clear Table")
        self.clear_button.clicked.connect(self.clear_table)
        self.layout.addWidget(self.clear_button)

    def add_packet(self, packet):
        if not packet.haslayer(IP):
            return 
        
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ARP"
        length = len(packet)

        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)

        self.packet_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(src_ip))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(dst_ip))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(protocol))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(str(length)))

    def clear_table(self):
        """Clears the table."""
        self.packet_table.setRowCount(0)


class MainWindow(QWidget):
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
        self.packet_table_window = None  
        self.sniffer_thread = None

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


    def save_to_file(self, save_to_file):
        self.save_to_file = save_to_file
        print(f"/ SaveToFile set to: {self.save_to_file} /")


    def set_protocol(self, protocol):
        self.selected_protocol = protocol
        print(f"/ Protocol set to: {self.selected_protocol} /")


    def get_packetCount(self):
        self.settings.packet_count = self.spin_box.value()
        print(f"/ Packet Count set to: {self.settings.packet_count} /")


    def runSniffer(self):
        packet_count = self.spin_box.value()

        if self.packet_table_window is None:
            self.packet_table_window = PacketTableWindow()  # Create table window
            self.packet_table_window.show()

        # Run Sniffer Thread
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            return  # Prevent multiple sniffers from running

        self.sniffer_thread = SnifferThread(iface="en0", filter_protocol=self.selected_protocol, packet_count=packet_count)
        self.sniffer_thread.packet_captured.connect(self.packet_table_window.add_packet)
        self.sniffer_thread.start()

    

    def reset_inputs(self): 
        self.spin_box.setValue(1)  # Reset packet count
        self.protocol = None  # Reset protocol
        self.saveToFile = False  # Reset save to file option
        self.captured_packets = []  # Clear captured packets
        print("\n === Inputs have been reset === ")



if __name__ == "__main__":
    app = QtWidgets.QApplication([])

    main_window = MainWindow()
    main_window.resize(600, 600)
    main_window.show()

    sys.exit(app.exec())