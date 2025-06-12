import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import sqlite3
import subprocess
from datetime import datetime
from analyzer import metadata, packer_detection, string_extractor, system_monitor
from analyzer import import_table, export_table, pe_sections, resource_viewer

# Ensure reports folder and database exist
os.makedirs("reports", exist_ok=True)
db_path = "reports/analysis_results.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    size INTEGER,
    date TEXT,
    metadata TEXT,
    packers TEXT,
    suspicious_strings TEXT,
    imports TEXT,
    exports TEXT,
    sections TEXT,
    resources TEXT
)''')
conn.commit()
conn.close()


class PEasyAnalyzerGUI:
    def __init__(self, app):
        self.app = app
        self.file_data = None
        self.dark_mode = True  # Start with dark mode for modern look
        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        self.style = ttk.Style()
        self.set_dark_theme()

    def set_dark_theme(self):
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#232629")
        self.style.configure("TLabel", background="#232629", foreground="#e0e0e0", font=("Segoe UI", 10))
        self.style.configure("TButton", background="#2d2f31", foreground="#e0e0e0", font=("Segoe UI", 10, "bold"))
        self.style.configure("TProgressbar", troughcolor="#232629", background="#4e9a06")
        self.style.configure("Treeview", background="#232629", fieldbackground="#232629", foreground="#e0e0e0")
        self.style.map("Treeview", background=[("selected", "#4e9a06")])

    def set_light_theme(self):
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#f4f4f4")
        self.style.configure("TLabel", background="#f4f4f4", foreground="#333", font=("Segoe UI", 10))
        self.style.configure("TButton", background="#0078D7", foreground="#fff", font=("Segoe UI", 10, "bold"))
        self.style.configure("TProgressbar", troughcolor="#f4f4f4", background="#0078D7")
        self.style.configure("Treeview", background="#fff", fieldbackground="#fff", foreground="#333")
        self.style.map("Treeview", background=[("selected", "#0078D7")])

    def setup_ui(self):
        # Destroy previous widgets if they exist (for theme switching)
        for widget in self.app.winfo_children():
            widget.destroy()

        self.app.title("🔐 PEasyAnalyzer - Static Malware Analysis")
        self.app.geometry("1000x700")
        self.app.configure(bg="#232629" if self.dark_mode else "#f4f4f4")

        # Sidebar for navigation
        self.sidebar = tk.Frame(self.app, bg="#181a1b" if self.dark_mode else "#eaeaea", width=180)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)

        self.logo_label = tk.Label(self.sidebar, text="🧬", font=("Segoe UI", 36),
                                  bg="#181a1b" if self.dark_mode else "#eaeaea",
                                  fg="#4e9a06" if self.dark_mode else "#0078D7")
        self.logo_label.pack(pady=(30, 10))
        self.appname_label = tk.Label(self.sidebar, text="PEasyAnalyzer", font=("Segoe UI", 16, "bold"),
                                      bg="#181a1b" if self.dark_mode else "#eaeaea",
                                      fg="#e0e0e0" if self.dark_mode else "#333")
        self.appname_label.pack(pady=(0, 30))

        self.analyze_btn = tk.Button(self.sidebar, text="🔍 Analyze", font=("Segoe UI", 12, "bold"),
                                     bg="#232629" if self.dark_mode else "#0078D7",
                                     fg="#e0e0e0" if self.dark_mode else "#fff",
                                     activebackground="#4e9a06" if self.dark_mode else "#005A9E",
                                     relief="flat", padx=10, pady=10, command=self.analyze_file)
        self.analyze_btn.pack(fill=tk.X, pady=5, padx=10)

        self.monitor_btn = tk.Button(self.sidebar, text="🛡 Monitor Syscalls", font=("Segoe UI", 12, "bold"),
                                     bg="#232629" if self.dark_mode else "#d9534f",
                                     fg="#e0e0e0" if self.dark_mode else "#fff",
                                     activebackground="#4e9a06" if self.dark_mode else "#c9302c",
                                     relief="flat", padx=10, pady=10, command=self.run_system_monitor)
        self.monitor_btn.pack(fill=tk.X, pady=5, padx=10)

        self.save_btn = tk.Button(self.sidebar, text="💾 Save Report", font=("Segoe UI", 12, "bold"),
                                  bg="#232629" if self.dark_mode else "#f0ad4e",
                                  fg="#e0e0e0" if self.dark_mode else "#fff",
                                  activebackground="#4e9a06" if self.dark_mode else "#ec971f",
                                  relief="flat", padx=10, pady=10, command=self.save_report, state=tk.DISABLED)
        self.save_btn.pack(fill=tk.X, pady=5, padx=10)

        self.reports_btn = tk.Button(self.sidebar, text="📂 View Reports", font=("Segoe UI", 12, "bold"),
                                     bg="#232629" if self.dark_mode else "#5cb85c",
                                     fg="#e0e0e0" if self.dark_mode else "#fff",
                                     activebackground="#4e9a06" if self.dark_mode else "#4cae4c",
                                     relief="flat", padx=10, pady=10, command=self.view_reports)
        self.reports_btn.pack(fill=tk.X, pady=5, padx=10)

        self.toggle_btn = tk.Button(self.sidebar, text="🌓 Theme", font=("Segoe UI", 10),
                                    bg="#232629" if self.dark_mode else "#0078D7",
                                    fg="#e0e0e0" if self.dark_mode else "#fff",
                                    activebackground="#4e9a06" if self.dark_mode else "#005A9E",
                                    relief="flat", command=self.toggle_theme)
        self.toggle_btn.pack(side=tk.BOTTOM, pady=20, padx=10, fill=tk.X)

        # Main content area
        self.main_frame = tk.Frame(self.app, bg="#232629" if self.dark_mode else "#f4f4f4")
        self.main_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.title_label = tk.Label(self.main_frame, text="Static Malware Analysis", font=("Segoe UI", 20, "bold"),
                                   bg="#232629" if self.dark_mode else "#f4f4f4",
                                   fg="#4e9a06" if self.dark_mode else "#0078D7")
        self.title_label.pack(anchor="nw", padx=20, pady=(20, 0))

        self.subtitle_label = tk.Label(self.main_frame,
                                       text="Analyze PE files for metadata, packers, imports, and more.",
                                       font=("Segoe UI", 12),
                                       bg="#232629" if self.dark_mode else "#f4f4f4",
                                       fg="#e0e0e0" if self.dark_mode else "#333")
        self.subtitle_label.pack(anchor="nw", padx=20, pady=(0, 10))

        self.progress = ttk.Progressbar(self.main_frame, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=20, pady=(0, 5))

        self.output_text = tk.Text(self.main_frame, wrap=tk.WORD, width=100, height=30,
                                   font=("Consolas", 11),
                                   bg="#181a1b" if self.dark_mode else "#fff",
                                   fg="#e0e0e0" if self.dark_mode else "#333",
                                   insertbackground="#e0e0e0" if self.dark_mode else "#333")
        self.output_text.pack(padx=20, pady=10, expand=True, fill=tk.BOTH)

        self.status_label = tk.Label(self.main_frame, text="Ready", anchor="w",
                                     bg="#232629" if self.dark_mode else "#f4f4f4",
                                     fg="#4e9a06" if self.dark_mode else "#0078D7",
                                     font=("Segoe UI", 10, "bold"))
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=(0, 10))

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.set_dark_theme()
        else:
            self.set_light_theme()
        self.setup_ui()
        self.app.update_idletasks()

    def analyze_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if not file_path:
            return

        self.output_text.delete(1.0, tk.END)
        self.status_label.config(text="Analyzing...")
        self.progress.start()
        self.save_btn.config(state=tk.DISABLED)
        self.app.update_idletasks()

        # Run analysis in a background thread
        threading.Thread(target=self._analyze_file_thread, args=(file_path,), daemon=True).start()

    def _analyze_file_thread(self, file_path):
        try:

            print("Extracting metadata...")
            meta = metadata.extract_metadata(file_path)
            self._update_progress("Extracted metadata...")
            print("Detecting packers...")
            packers = packer_detection.detect_packer(file_path)
            self._update_progress("Detected packers...")
            print("Extracting suspicious strings...")
            strings = string_extractor.extract_suspicious_strings(file_path)
            self._update_progress("Extracted suspicious strings...")
            print("Getting import table...")
            imports = import_table.get_import_table(file_path)
            self._update_progress("Parsed import table...")
            print("Getting export table...")
            exports = export_table.get_export_table(file_path)
            self._update_progress("Parsed export table...")
            print("Getting sections...")
            sections = pe_sections.get_pe_sections(file_path)
            self._update_progress("Parsed sections...")
            print("Getting resources...")
            resources = resource_viewer.get_resources(file_path)
            self._update_progress("Parsed resources...")

            self.app.after(0, self._display_analysis_results, meta, packers, strings, imports, exports, sections, resources, file_path)
        except Exception as e:
            print(f"Exception in analysis thread: {e}")
            self.app.after(0, self._display_error, str(e))
        finally:
            self.app.after(0, self.progress.stop)

    def _update_progress(self, msg):
        self.app.after(0, lambda: self.status_label.config(text=msg))

    def _display_analysis_results(self, meta, packers, strings, imports, exports, sections, resources, file_path):
        self.output_text.insert(tk.END, "\n📄 Metadata:\n")
        for k, v in meta.items():
            self.output_text.insert(tk.END, f"{k}: {v}\n")

        self.output_text.insert(tk.END, "\n🧪 Packer Detection:\n")
        for p in packers:
            self.output_text.insert(tk.END, f"- {p}\n")

        self.output_text.insert(tk.END, "\n🔍 Suspicious Strings (Top 50):\n")
        for s in strings[:50]:
            self.output_text.insert(tk.END, f"- {s}\n")

        self.output_text.insert(tk.END, "\n📥 Import Table (Top 10):\n")
        for imp in imports[:10]:
            self.output_text.insert(tk.END, f"- {imp}\n")
        if len(imports) > 10:
            self.output_text.insert(tk.END, f"...({len(imports)} total)\n")

        self.output_text.insert(tk.END, "\n📤 Export Table (Top 10):\n")
        for exp in exports[:10]:
            self.output_text.insert(tk.END, f"- {exp}\n")
        if len(exports) > 10:
            self.output_text.insert(tk.END, f"...({len(exports)} total)\n")

        self.output_text.insert(tk.END, "\n📦 Sections:\n")
        for sec in sections:
            self.output_text.insert(tk.END, f"- {sec}\n")

        self.output_text.insert(tk.END, "\n📚 Resources:\n")
        for res in resources:
            self.output_text.insert(tk.END, f"- {res}\n")

        self.file_data = {
            "filename": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
            "date": datetime.now().isoformat(),
            "metadata": str(meta),
            "packers": ", ".join(packers),
            "suspicious_strings": "\n".join(strings[:50]),
            "imports": "\n".join(str(i) for i in imports[:50]),
            "exports": "\n".join(str(e) for e in exports[:50]),
            "sections": "\n".join(str(s) for s in sections),
            "resources": "\n".join(str(r) for r in resources)
        }

        self.status_label.config(text="Analysis complete ✔")
        self.save_btn.config(state=tk.NORMAL)

    def _display_error(self, error_msg):
        self.output_text.insert(tk.END, f"❌ Error during analysis: {error_msg}\n")
        self.status_label.config(text="Analysis failed")

    def run_system_monitor(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if not file_path:
            return

        result = messagebox.askyesno("⚠️ Warning",
                                     "Running system call monitoring will execute the selected file, which might be malicious.\n\nDo you want to continue?")

        if not result:
            return

        proc_name = os.path.basename(file_path)
        self.status_label.config(text=f"Monitoring system calls for: {proc_name}")
        self.output_text.insert(tk.END, f"\n⚠️ Running system call monitor for: {proc_name}\n")
        self.output_text.insert(tk.END, "NOTE: This simulates syscall monitoring in this academic project.\n")

        try:
            success = system_monitor.run_system_monitor(proc_name)
            if not success:
                self.output_text.insert(tk.END, "❌ Process not found. Please run the target manually before monitoring.\n")
            else:
                self.output_text.insert(tk.END, "✅ Monitoring started. Check console for updates.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"❌ Error: {e}\n")


    def save_report(self):
        print("Save button clicked")
        print("file_data:", self.file_data)
        if not self.file_data:
            messagebox.showwarning("No Analysis", "Run an analysis before saving a report.")
            return

        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO analysis (filename, size, date, metadata, packers, suspicious_strings, imports, exports, sections, resources)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (self.file_data["filename"], self.file_data["size"], self.file_data["date"],
                   self.file_data["metadata"], self.file_data["packers"], self.file_data["suspicious_strings"],
                   self.file_data["imports"], self.file_data["exports"], self.file_data["sections"], self.file_data["resources"]))
        conn.commit()
        conn.close()

        self.status_label.config(text="Report saved ✔")
        self.save_btn.config(state=tk.DISABLED)
        messagebox.showinfo("Report Saved", "The analysis has been saved to the database.")

    def view_reports(self):
        """Attempt to open external report viewer, fall back to internal DB viewer."""
        try:
            script_path = os.path.join(os.path.dirname(__file__), "view_report.py")
            subprocess.run(["python", script_path], check=True)
        except FileNotFoundError:
            self.output_text.insert(tk.END, "⚠️ view_report.py not found. Falling back to internal report viewer.\n")
            self.view_reports_fallback()
        except subprocess.CalledProcessError as e:
            self.output_text.insert(tk.END, f"❌ Error running view_report.py: {str(e)}\n")
            self.view_reports_fallback()
        except Exception as e:
            self.output_text.insert(tk.END, f"❌ Unexpected error: {str(e)}\n")
            self.view_reports_fallback()

    def view_reports_fallback(self):
        top = tk.Toplevel(self.app)
        top.title("🗂 Previous Reports")
        top.geometry("700x400")

        tree = ttk.Treeview(top, columns=("Filename", "Size", "Date"), show="headings")
        tree.heading("Filename", text="Filename")
        tree.heading("Size", text="Size (bytes)")
        tree.heading("Date", text="Date")

        scrollbar = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(fill=tk.BOTH, expand=True)

        conn = sqlite3.connect(db_path)
        for row in conn.execute("SELECT filename, size, date FROM analysis ORDER BY date DESC"):
            tree.insert("", tk.END, values=row)
        conn.close()

        if self.dark_mode:
            top.configure(bg="#1e1e1e")
            tree_style = ttk.Style()
            tree_style.configure("Treeview", background="#252526", fieldbackground="#252526", foreground="white")
            tree_style.map("Treeview", background=[("selected", "#0078D7")])


def run_gui():
    root = tk.Tk()
    icon_path = os.path.join("assets", "peasy.ico")
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Icon load error: {e}")
    app = PEasyAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()