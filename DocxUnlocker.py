import sys
import os
import pikepdf
from msoffcrypto import OfficeFile
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QLineEdit, QMessageBox, QHBoxLayout
from PySide6.QtCore import QThread, Signal
import requests
import traceback


class DownloadThread(QThread):
    progress_changed = Signal(float)
    download_complete = Signal()

    def __init__(self, url, save_path):
        super().__init__()
        self.url = url
        self.save_path = save_path
        self.cancelled = False

    def run(self):
        try:
            response = requests.get(self.url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            block_size = 1024  # 1 Kilobyte
            bytes_downloaded = 0
            with open(self.save_path, 'wb') as f:
                for data in response.iter_content(block_size):
                    if self.cancelled:
                        self.log_message("Download cancelled.")
                        return
                    f.write(data)
                    bytes_downloaded += len(data)
                    progress_percentage = (bytes_downloaded / total_size) * 100
                    self.progress_changed.emit(progress_percentage)
            self.download_complete.emit()
        except Exception as e:
            traceback.print_exc()
            self.log_message(f"Error downloading password list: {str(e)}")

    def cancel_download(self):
        self.cancelled = True


class PasswordCrackerThread(QThread):
    log_message = Signal(str)
    crack_success = Signal(str)

    def __init__(self, file_path, pass_list_path):
        super().__init__()
        self.file_path = file_path
        self.pass_list_path = pass_list_path
        self.cancelled = False

    def run(self):
        if not os.path.exists(self.file_path) or not os.path.exists(self.pass_list_path):
            self.log_message.emit("File or password list not found.")
            return

        try:
            with open(self.pass_list_path, "r", encoding="utf-8") as f:
                passwords = (line.strip() for line in f)
                if self.file_path.endswith(("docx", "pptx", "xlsx")):
                    self.crack_office_file(passwords)
                elif self.file_path.endswith(".pdf"):
                    self.crack_pdf_file(passwords)
                else:
                    self.log_message.emit("Unsupported file type.")
        except UnicodeDecodeError:
            with open(self.pass_list_path, "rb") as f:
                passwords = (line.strip() for line in f)
                if self.file_path.endswith(("docx", "pptx", "xlsx")):
                    self.crack_office_file(passwords)
                elif self.file_path.endswith(".pdf"):
                    self.crack_pdf_file(passwords)
                else:
                    self.log_message.emit("Unsupported file type.")
        except Exception as e:
            self.log_message.emit(f"Error reading password list: {str(e)}")

    def crack_office_file(self, passwords):
        try:
            with open(self.file_path, "rb") as f:
                file = OfficeFile(f)
                for this_pass in passwords:
                    if self.cancelled:
                        self.log_message.emit("Cracking process cancelled.")
                        return
                    try:
                        file.load_key(password=this_pass, verify_password=True)
                        self.crack_success.emit(this_pass)
                        return
                    except Exception:
                        self.log_message.emit(
                            f"Incorrect Password: {this_pass}")
        except Exception as e:
            self.log_message.emit(f"Error opening file: {str(e)}")

    def crack_pdf_file(self, passwords):
        try:
            for one_pass in passwords:
                if self.cancelled:
                    self.log_message.emit("Cracking process cancelled.")
                    return
                try:
                    with pikepdf.open(self.file_path, password=one_pass) as pdf:
                        self.crack_success.emit(one_pass)
                        return
                except Exception:
                    self.log_message.emit(f"Incorrect Password: {one_pass}")
        except Exception as e:
            self.log_message.emit(f"Error opening file: {str(e)}")

    def cancel_cracking(self):
        self.cancelled = True


class PasswordCrackerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Cracker App")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.file_button_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_button_layout.addWidget(self.file_path_edit)
        self.file_button = QPushButton("Select Document (MS Office , PDF)")
        self.file_button.clicked.connect(self.select_file)
        self.file_button_layout.addWidget(self.file_button)
        self.layout.addLayout(self.file_button_layout)

        self.pass_list_button_layout = QHBoxLayout()
        self.pass_list_path_edit = QLineEdit()
        self.pass_list_button_layout.addWidget(self.pass_list_path_edit)
        self.pass_list_button = QPushButton("Select Password List")
        self.pass_list_button.clicked.connect(self.select_pass_list)
        self.pass_list_button_layout.addWidget(self.pass_list_button)
        self.layout.addLayout(self.pass_list_button_layout)

        self.download_passlist_button = QPushButton(
            "Download Default Password List")
        self.download_passlist_button.clicked.connect(self.download_pass_list)
        self.layout.addWidget(self.download_passlist_button)

        self.cancel_download_button = QPushButton("Cancel Download")
        self.cancel_download_button.clicked.connect(self.cancel_download)
        self.cancel_download_button.setEnabled(False)
        self.layout.addWidget(self.cancel_download_button)

        self.crack_button = QPushButton("Crack Password")
        self.crack_button.clicked.connect(self.crack_password)
        self.layout.addWidget(self.crack_button)

        self.cancel_crack_button = QPushButton("Cancel Crack")
        self.cancel_crack_button.clicked.connect(self.cancel_crack)
        self.cancel_crack_button.setEnabled(False)
        self.layout.addWidget(self.cancel_crack_button)

        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.clicked.connect(self.clear_log)
        self.layout.addWidget(self.clear_log_button)

        self.reset_button = QPushButton("Reset APP")
        self.reset_button.clicked.connect(self.reset_app)
        self.layout.addWidget(self.reset_button)

        self.log_text = QTextEdit()
        self.layout.addWidget(self.log_text)

        self.download_thread = None
        self.cracker_thread = None

    def log_message(self, message):
        self.log_text.append(message)
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum())

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File")
        if file_path:
            self.log_message(f"File selected: {file_path}")
            self.file_path_edit.setText(file_path)
            self.file_path_edit.setReadOnly(False)

    def select_pass_list(self):
        file_dialog = QFileDialog()
        pass_list_path, _ = file_dialog.getOpenFileName(
            self, "Select Password List")
        if pass_list_path:
            self.log_message(f"Password list selected: {pass_list_path}")
            self.pass_list_path_edit.setText(pass_list_path)
            self.pass_list_path_edit.setReadOnly(False)

    def download_pass_list(self):
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Password List", "", "Text Files (*.txt)")
        if save_path:
            url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
            self.download_thread = DownloadThread(url, save_path)
            self.download_thread.progress_changed.connect(self.update_progress)
            self.download_thread.download_complete.connect(
                self.download_complete)
            self.download_thread.start()
            self.download_passlist_button.setEnabled(False)
            self.cancel_download_button.setEnabled(True)

    def update_progress(self, progress_percentage):
        self.log_message(f"Download progress: {progress_percentage:.2f}%")

    def download_complete(self):
        self.log_message("Password list downloaded successfully.")
        self.download_passlist_button.setEnabled(True)
        self.cancel_download_button.setEnabled(False)

    def cancel_download(self):
        if self.download_thread:
            self.download_thread.cancel_download()
            self.download_passlist_button.setEnabled(True)
            self.cancel_download_button.setEnabled(False)
            self.log_message("Download cancelled.")

    def crack_password(self):
        file_path = self.file_path_edit.text()
        pass_list_path = self.pass_list_path_edit.text()

        if not file_path or not pass_list_path:
            QMessageBox.warning(
                self, "Warning", "Please select both file and password list.")
            return

        self.log_message("Starting password cracking process...")
        self.cracker_thread = PasswordCrackerThread(file_path, pass_list_path)
        self.cracker_thread.log_message.connect(self.log_message)
        self.cracker_thread.crack_success.connect(self.crack_success)
        self.cracker_thread.start()
        # Enable cancel button when cracking starts
        self.cancel_crack_button.setEnabled(True)

    def cancel_crack(self):
        if self.cracker_thread:
            self.cracker_thread.cancel_cracking()
            self.cancel_crack_button.setEnabled(False)
            self.log_message("Cracking process cancelled.")

    def crack_success(self, password):
        self.log_message(f"Password found: {password}")
        QMessageBox.information(self, "Success", f"Password found: {password}")

    def clear_log(self):
        self.log_text.clear()

    def reset_app(self):
        self.file_path_edit.clear()
        self.pass_list_path_edit.clear()
        self.log_text.clear()
        self.file_path_edit.setReadOnly(False)
        self.pass_list_path_edit.setReadOnly(False)
        self.log_message("Application reset.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordCrackerApp()
    window.show()
    sys.exit(app.exec())
