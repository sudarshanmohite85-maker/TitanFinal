import sys
import os
import ctypes
import struct
import platform
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QComboBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QProgressBar, QLabel, 
                             QMessageBox, QFileDialog, QAbstractItemView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# -----------------------------------------------------------------------------
# CONSTANTS & SIGNATURES (VERSION 5.0 - FIXED EXTRACTION)
# -----------------------------------------------------------------------------
# We explicitly define Footers for images to prevent corruption
FILE_MARKERS = {
    'jpg':  {'head': b'\xFF\xD8\xFF', 'foot': b'\xFF\xD9'},
    'png':  {'head': b'\x89\x50\x4E\x47', 'foot': b'\x49\x45\x4E\x44\xAE\x42\x60\x82'},
    'mp4':  {'head': b'\x66\x74\x79\x70', 'foot': None}, 
    'avi':  {'head': b'\x52\x49\x46\x46', 'foot': None},
}

CHUNK_SIZE = 1024 * 1024  # 1 MB read speed
SECTOR_SIZE = 512

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def get_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            dtype = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
            if dtype == 2 or dtype == 3: 
                drives.append((letter, f"\\\\.\\{letter}:"))
        bitmask >>= 1
    return drives

# -----------------------------------------------------------------------------
# RECOVERY ENGINE
# -----------------------------------------------------------------------------
class RecoveryWorker(QThread):
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    file_found = pyqtSignal(dict)
    finished_scan = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, drive_path, save_dir):
        super().__init__()
        self.drive_path = drive_path
        self.save_dir = save_dir
        self.is_running = True

    def run(self):
        try:
            self.status_update.emit(f"Opening drive {self.drive_path}...")
            try:
                disk = open(self.drive_path, 'rb')
            except:
                self.error_occurred.emit("Access Denied. Run as Admin.")
                return

            # 250GB Limit to bypass Windows size check errors
            disk_size = 250 * 1024 * 1024 * 1024 
            
            self.status_update.emit(f"Scanning (v5.0 Fixed Extraction)...")

            offset = 0
            found_count = 0
            
            while offset < disk_size and self.is_running:
                if offset % (20 * CHUNK_SIZE) == 0:
                    percent = int((offset / disk_size) * 100)
                    if percent > 100: percent = 99
                    self.progress_update.emit(percent)

                try:
                    data = disk.read(CHUNK_SIZE)
                    if not data: break
                except:
                    offset += CHUNK_SIZE
                    continue

                # Scan for signatures
                for ext, markers in FILE_MARKERS.items():
                    header = markers['head']
                    pos = data.find(header)
                    
                    if pos != -1:
                        global_pos = offset + pos
                        file_start = global_pos
                        
                        # Adjust for MP4 'ftyp' (starts 4 bytes earlier)
                        if ext == 'mp4': file_start = global_pos - 4
                        
                        self.status_update.emit(f"Found {ext.upper()} at {file_start}")
                        
                        # --- EXTRACTOR v5.0 FIXED ---
                        recovered_data, status_msg = self.extract_file(disk, file_start, ext, markers['foot'])
                        
                        if recovered_data:
                            filename = f"recovered_{file_start}.{ext}"
                            filepath = os.path.join(self.save_dir, filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(recovered_data)
                            
                            found_count += 1
                            size_mb = len(recovered_data) / (1024*1024)
                            self.file_found.emit({
                                'name': filename,
                                'size': f"{size_mb:.2f} MB",
                                'type': ext.upper(),
                                'status': status_msg
                            })
                            
                            # Skip the data we just recovered
                            if len(recovered_data) > CHUNK_SIZE:
                                skip = (len(recovered_data) // SECTOR_SIZE) * SECTOR_SIZE
                                offset += skip
                                disk.seek(offset)
                                break 

                offset += CHUNK_SIZE

            disk.close()
            self.progress_update.emit(100)
            self.status_update.emit(f"Done. {found_count} files found.")
            self.finished_scan.emit()

        except Exception as e:
            self.error_occurred.emit(str(e))

    def extract_file(self, disk, start_pos, ext, footer):
        """
        v5.0 FIXED Extraction Logic:
        - Properly handles sector alignment
        - Extracts clean file data without padding
        - JPG/PNG: Reads until the exact footer is found
        - MP4/AVI: Reads until next header or empty space
        """
        saved_pos = disk.tell()
        
        # Align to sector boundary
        aligned = (start_pos // SECTOR_SIZE) * SECTOR_SIZE
        diff = start_pos - aligned  # Offset within the aligned sector
        
        buffer = bytearray()
        status = "Recovered"
        
        try:
            disk.seek(aligned)
            
            # Size limits: Images 20MB, Videos 3GB
            max_limit = 20 * 1024 * 1024 if ext in ['jpg', 'png'] else 3000 * 1024 * 1024
            
            # Initial read
            chunk = disk.read(min(CHUNK_SIZE, max_limit))
            if not chunk:
                disk.seek(saved_pos)
                return (None, "")
            
            buffer.extend(chunk)
            read_so_far = len(chunk)

            # Start searching right after the header
            header_len = len(FILE_MARKERS[ext]['head'])
            scan_offset = diff + header_len
            found_end = False
            final_size = 0
            
            # Main extraction loop
            while read_so_far < max_limit:
                window = buffer
                
                # --- STRATEGY 1: LOOK FOR FOOTER (Images) ---
                if footer:
                    f_pos = window.find(footer, scan_offset)
                    if f_pos != -1:
                        # Found the footer! Include it in the file
                        final_size = f_pos + len(footer)
                        found_end = True
                        break

                # --- STRATEGY 2: LOOK FOR NEXT HEADER (Videos) ---
                if not footer:
                    # Stop if we encounter another file header
                    for other_ext, m in FILE_MARKERS.items():
                        h_pos = window.find(m['head'], scan_offset)
                        if h_pos != -1:
                            # Found next file, stop before it
                            if other_ext == 'mp4':
                                final_size = h_pos - 4  # MP4 header adjustment
                            else:
                                final_size = h_pos
                            found_end = True
                            break
                    if found_end: 
                        break

                # --- STRATEGY 3: EMPTY SPACE DETECTION ---
                if len(window) > scan_offset + 8192:
                    # Check last 8KB for empty space
                    tail = window[-8192:]
                    zero_count = tail.count(b'\x00')
                    
                    if zero_count > 7900:  # More than 96% zeros
                        # Find where zeros start
                        for i in range(len(window) - 1, scan_offset, -512):
                            if window[i] != 0:
                                final_size = i + 1
                                found_end = True
                                break
                        if found_end: 
                            break

                # Read more data
                new_chunk = disk.read(CHUNK_SIZE)
                if not new_chunk: 
                    # End of readable data
                    final_size = len(buffer)
                    break
                    
                buffer.extend(new_chunk)
                read_so_far += len(new_chunk)
                
                # Update scan offset for next iteration
                if footer:
                    # For images with footers, search newly read data
                    scan_offset = max(scan_offset, len(buffer) - len(new_chunk) - len(footer))
                else:
                    # For videos, search newly read data
                    scan_offset = max(scan_offset, len(buffer) - len(new_chunk) - 100)

            # --- EXTRACT CLEAN FILE DATA ---
            # Remove the alignment padding at the beginning
            if found_end and final_size > diff:
                valid_data = bytes(buffer[diff:final_size])
            elif not found_end and len(buffer) > diff:
                valid_data = bytes(buffer[diff:])
            else:
                disk.seek(saved_pos)
                return (None, "")
            
            # --- VALIDATION CHECKS ---
            # Verify file signature is correct
            expected_header = FILE_MARKERS[ext]['head']
            if ext == 'mp4':
                # MP4 should start with 'ftyp' but we need to check full header
                if len(valid_data) < 8 or valid_data[4:8] != expected_header:
                    disk.seek(saved_pos)
                    return (None, "")
            else:
                if not valid_data.startswith(expected_header):
                    disk.seek(saved_pos)
                    return (None, "")
            
            # Check minimum file sizes
            if ext in ['jpg', 'png'] and len(valid_data) < 2048:  # 2KB minimum for images
                disk.seek(saved_pos)
                return (None, "")
            
            if ext in ['mp4', 'avi'] and len(valid_data) < 10240:  # 10KB minimum for videos
                disk.seek(saved_pos)
                return (None, "")
            
            # Verify footer if expected
            if footer and found_end:
                if not valid_data.endswith(footer):
                    status = "Incomplete"

            disk.seek(saved_pos)
            return (valid_data, status)

        except Exception as e:
            try: 
                disk.seek(saved_pos)
            except: 
                pass
            return (None, "")

    def stop(self):
        self.is_running = False

# -----------------------------------------------------------------------------
# GUI CLASS
# -----------------------------------------------------------------------------
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Titan Recovery v5.0 - FIXED EXTRACTION")
        self.resize(1000, 600)
        self.setStyleSheet("""
            QMainWindow { background-color: #f0f0f0; }
            QLabel { font-size: 14px; font-weight: bold; }
            QTableWidget { background-color: white; border: 1px solid #ccc; }
            QPushButton { 
                background-color: #0078D7; 
                color: white; 
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #005fa3; }
            QPushButton:disabled { background-color: #cccccc; }
            QComboBox { padding: 6px; border: 1px solid #ccc; }
            QProgressBar { 
                border: 1px solid #ccc; 
                border-radius: 4px; 
                text-align: center; 
            }
            QProgressBar::chunk { 
                background-color: #0078D7; 
            }
        """)
        self.worker = None
        self.save_directory = ""
        self.init_ui()

    def init_ui(self):
        main = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔧 Titan Recovery v5.0 - Fixed Extraction Engine")
        title.setStyleSheet("font-size: 18px; color: #0078D7; padding: 10px;")
        layout.addWidget(title)
        
        # Drive selection
        d_layout = QHBoxLayout()
        d_layout.addWidget(QLabel("Select Drive:"))
        self.d_combo = QComboBox()
        self.refresh_drives()
        btn_r = QPushButton("🔄 Refresh")
        btn_r.clicked.connect(self.refresh_drives)
        d_layout.addWidget(self.d_combo)
        d_layout.addWidget(btn_r)
        layout.addLayout(d_layout)

        # Output folder selection
        o_layout = QHBoxLayout()
        self.l_out = QLabel("No output folder selected")
        self.l_out.setStyleSheet("color: #666; font-weight: normal;")
        btn_o = QPushButton("📁 Select Output Folder")
        btn_o.clicked.connect(self.select_output)
        o_layout.addWidget(btn_o)
        o_layout.addWidget(self.l_out, 1)
        layout.addLayout(o_layout)

        # Start button
        self.btn_s = QPushButton("▶️ Start Recovery Scan")
        self.btn_s.clicked.connect(self.start_scan)
        self.btn_s.setEnabled(False)
        self.btn_s.setStyleSheet("""
            QPushButton { 
                padding: 12px; 
                font-size: 16px; 
                background-color: #28a745; 
            }
            QPushButton:hover { background-color: #218838; }
            QPushButton:disabled { background-color: #cccccc; }
        """)
        layout.addWidget(self.btn_s)

        # Progress bar
        self.p_bar = QProgressBar()
        self.p_bar.setMinimum(0)
        self.p_bar.setMaximum(100)
        layout.addWidget(self.p_bar)
        
        # Status label
        self.l_stat = QLabel("Ready to scan")
        self.l_stat.setStyleSheet("color: #28a745; font-weight: normal; padding: 5px;")
        layout.addWidget(self.l_stat)

        # Results table
        table_label = QLabel("Recovered Files:")
        layout.addWidget(table_label)
        
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Filename", "Size", "Type", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)

        # Info footer
        info = QLabel("💡 This tool recovers deleted files by scanning raw disk sectors. Run as Administrator!")
        info.setStyleSheet("color: #666; font-size: 12px; font-weight: normal; padding: 10px;")
        layout.addWidget(info)

        main.setLayout(layout)
        self.setCentralWidget(main)

    def refresh_drives(self):
        self.d_combo.clear()
        drives = get_drives()
        if drives:
            self.d_combo.setEnabled(True)
            for l, p in drives: 
                self.d_combo.addItem(f"Drive {l}: ({p})", p)
        else:
            self.d_combo.setEnabled(False)
            self.d_combo.addItem("No drives found")

    def select_output(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.save_directory = folder
            self.l_out.setText(folder)
            self.l_out.setStyleSheet("color: #28a745; font-weight: normal;")
            self.check_ready()

    def check_ready(self):
        if self.save_directory and self.d_combo.isEnabled():
            self.btn_s.setEnabled(True)

    def start_scan(self):
        path = self.d_combo.currentData()
        self.btn_s.setEnabled(False)
        self.table.setRowCount(0)
        self.p_bar.setValue(0)
        
        self.worker = RecoveryWorker(path, self.save_directory)
        self.worker.progress_update.connect(self.p_bar.setValue)
        self.worker.status_update.connect(self.l_stat.setText)
        self.worker.file_found.connect(self.add_row)
        self.worker.error_occurred.connect(self.show_error)
        self.worker.finished_scan.connect(self.scan_finished)
        self.worker.start()

    def add_row(self, data):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(data['name']))
        self.table.setItem(r, 1, QTableWidgetItem(data['size']))
        self.table.setItem(r, 2, QTableWidgetItem(data['type']))
        
        status_item = QTableWidgetItem(data['status'])
        if data['status'] == "Recovered":
            status_item.setForeground(Qt.GlobalColor.darkGreen)
        else:
            status_item.setForeground(Qt.GlobalColor.darkYellow)
        self.table.setItem(r, 3, status_item)
        
        self.table.scrollToBottom()

    def scan_finished(self):
        self.btn_s.setEnabled(True)
        QMessageBox.information(self, "Scan Complete", 
                                f"Recovery scan finished!\n\n"
                                f"Files recovered: {self.table.rowCount()}\n"
                                f"Saved to: {self.save_directory}")

    def show_error(self, error_msg):
        self.btn_s.setEnabled(True)
        QMessageBox.critical(self, "Error", f"An error occurred:\n\n{error_msg}")

if __name__ == "__main__":
    if not is_admin():
        # Request admin privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = QApplication(sys.argv)
        w = RecoveryApp()
        w.show()
        sys.exit(app.exec())
