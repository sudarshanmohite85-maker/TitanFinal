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
# CONSTANTS & SIGNATURES
# -----------------------------------------------------------------------------
FILE_MARKERS = {
    'jpg':  {'head': b'\xFF\xD8\xFF', 'foot': b'\xFF\xD9'},
    'png':  {'head': b'\x89\x50\x4E\x47', 'foot': b'\x49\x45\x4E\x44\xAE\x42\x60\x82'},
    'mp4':  {'head': b'\x66\x74\x79\x70', 'foot': None}, 
    'avi':  {'head': b'\x52\x49\x46\x46', 'foot': None},
}

# List of all headers to detect "Start of Next File"
ALL_HEADERS = [m['head'] for m in FILE_MARKERS.values()]

CHUNK_SIZE = 1024 * 1024  # 1 MB read buffer
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
            
            self.status_update.emit(f"Scanning (v7.0 Fixed Alignment)...")

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
                        
                        # Adjust for MP4 'ftyp' (header starts 4 bytes earlier)
                        if ext == 'mp4': file_start = global_pos - 4
                        
                        self.status_update.emit(f"Found {ext.upper()} at {file_start}")
                        
                        # --- EXTRACTOR v7.0 ---
                        recovered_data = self.extract_file(disk, file_start, ext, markers['foot'])
                        
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
                                'status': 'Recovered'
                            })
                            
                            # Align skip to sector boundary to keep Windows happy
                            skip_len = len(recovered_data)
                            aligned_skip = (skip_len // SECTOR_SIZE) * SECTOR_SIZE
                            if aligned_skip > 0:
                                offset += aligned_skip
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
        v7.0 Extraction Logic (User Corrected):
        1. Aligns disk read to 512-byte sector.
        2. Calculates 'diff' (padding).
        3. Starts footer/next-header search IMMEDIATELY after file signature.
        """
        saved = disk.tell()
        aligned = (start_pos // SECTOR_SIZE) * SECTOR_SIZE
        diff = start_pos - aligned
        
        buffer = bytearray()
        
        try:
            disk.seek(aligned)
            
            # Limits: Images 20MB, Videos 3GB
            max_limit = 20 * 1024 * 1024 if ext in ['jpg', 'png'] else 3000 * 1024 * 1024
            
            read_so_far = 0
            # Initial Read
            chunk = disk.read(min(CHUNK_SIZE, max_limit))
            buffer.extend(chunk)
            read_so_far += len(chunk)

            # --- CORRECTED OFFSET LOGIC ---
            # We must start scanning immediately after the header.
            # 'diff' is the junk bytes before our file starts in the buffer.
            # 'header_len' is the size of the signature we just found.
            # scan_offset is relative to the start of 'buffer'
            header_len = len(FILE_MARKERS[ext]['head'])
            
            # If MP4, we found 'ftyp' at diff+4, so the header effectively covers that range.
            if ext == 'mp4': header_len += 4

            scan_offset = diff + header_len
            
            final_size_in_buffer = 0
            found_end = False
            
            while read_so_far < max_limit:
                window = buffer
                
                # --- 1. CHECK FOR EXPLICIT FOOTER (JPG/PNG) ---
                if footer:
                    f_pos = window.find(footer, scan_offset)
                    if f_pos != -1:
                        final_size_in_buffer = f_pos + len(footer)
                        found_end = True
                        break

                # --- 2. CHECK FOR NEXT HEADER (ALL FILES) ---
                # This is the "Termination Logic" for videos
                for header in ALL_HEADERS:
                    h_pos = window.find(header, scan_offset)
                    if h_pos != -1:
                        # Found start of NEXT file.
                        final_size_in_buffer = h_pos
                        
                        # Special case: If we hit 'ftyp', the file actually started 4 bytes prior
                        if header == b'\x66\x74\x79\x70':
                             final_size_in_buffer -= 4
                        
                        found_end = True
                        break
                
                if found_end: break

                # --- 3. CHECK FOR EMPTY SPACE (ZEROS) ---
                # Check last 4KB for zeros
                if len(window) > 4096:
                     tail = window[-4096:]
                     if tail == b'\x00' * 4096:
                         final_size_in_buffer = len(window) - 4096
                         found_end = True
                         break

                # Read More
                new_chunk = disk.read(CHUNK_SIZE)
                if not new_chunk: break
                buffer.extend(new_chunk)
                read_so_far += len(new_chunk)
                
                # Move scan_offset forward, but keep overlap for split markers
                scan_offset = len(buffer) - len(new_chunk) - 20 

            # --- DATA EXTRACTION ---
            if found_end:
                # We found a distinct end point
                valid_data = buffer[diff:final_size_in_buffer]
            else:
                # We hit max limit (blind carve)
                valid_data = buffer[diff:]

            # Sanity Check
            if len(valid_data) < 512: 
                disk.seek(saved)
                return None

            disk.seek(saved)
            return valid_data

        except:
            try: disk.seek(saved)
            except: pass
            return None

    def stop(self):
        self.is_running = False

# -----------------------------------------------------------------------------
# GUI CLASS
# -----------------------------------------------------------------------------
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Titan Recovery - VERSION 7.0 (OFFSET FIXED)")
        self.resize(1000, 600)
        self.setStyleSheet("""
            QMainWindow { background-color: #f0f0f0; }
            QLabel { font-size: 14px; }
            QTableWidget { background-color: white; }
            QPushButton { background-color: #0078D7; color: white; padding: 8px; }
        """)
        self.worker = None
        self.save_directory = ""
        self.init_ui()

    def init_ui(self):
        main = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Titan Recovery v7.0 (Corrected Sector Alignment)"))
        
        d_layout = QHBoxLayout()
        self.d_combo = QComboBox()
        self.refresh_drives()
        btn_r = QPushButton("Refresh")
        btn_r.clicked.connect(self.refresh_drives)
        d_layout.addWidget(self.d_combo)
        d_layout.addWidget(btn_r)
        layout.addLayout(d_layout)

        o_layout = QHBoxLayout()
        self.l_out = QLabel("No output folder")
        btn_o = QPushButton("Select Output")
        btn_o.clicked.connect(self.select_output)
        o_layout.addWidget(btn_o)
        o_layout.addWidget(self.l_out)
        layout.addLayout(o_layout)

        self.btn_s = QPushButton("Start Scan")
        self.btn_s.clicked.connect(self.start_scan)
        self.btn_s.setEnabled(False)
        layout.addWidget(self.btn_s)

        self.p_bar = QProgressBar()
        layout.addWidget(self.p_bar)
        self.l_stat = QLabel("Ready")
        layout.addWidget(self.l_stat)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Size", "Type", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        main.setLayout(layout)
        self.setCentralWidget(main)

    def refresh_drives(self):
        self.d_combo.clear()
        drives = get_drives()
        if drives:
            self.d_combo.setEnabled(True)
            for l, p in drives: self.d_combo.addItem(f"Drive {l}", p)
        else:
            self.d_combo.setEnabled(False)

    def select_output(self):
        f = QFileDialog.getExistingDirectory(self, "Select Output")
        if f:
            self.save_directory = f
            self.l_out.setText(f)
            self.check_ready()

    def check_ready(self):
        if self.save_directory and self.d_combo.isEnabled():
            self.btn_s.setEnabled(True)

    def start_scan(self):
        path = self.d_combo.currentData()
        self.btn_s.setEnabled(False)
        self.worker = RecoveryWorker(path, self.save_directory)
        self.worker.progress_update.connect(self.p_bar.setValue)
        self.worker.status_update.connect(self.l_stat.setText)
        self.worker.file_found.connect(self.add_row)
        self.worker.finished_scan.connect(lambda: self.btn_s.setEnabled(True))
        self.worker.start()

    def add_row(self, data):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(data['name']))
        self.table.setItem(r, 1, QTableWidgetItem(data['size']))
        self.table.setItem(r, 2, QTableWidgetItem(data['type']))
        self.table.setItem(r, 3, QTableWidgetItem(data['status']))

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = QApplication(sys.argv)
        w = RecoveryApp()
        w.show()
        sys.exit(app.exec())
