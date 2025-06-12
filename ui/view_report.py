import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os

db_path = "reports/analysis_results.db"
icon_path = "assets/peasy.ico"

class ReportViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("📋 PEasy Report Viewer")
        self.root.geometry("900x600")

        # Set icon
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        self.search_var = tk.StringVar()
        self.sort_column = None
        self.sort_reverse = False

        self.setup_ui()
        self.load_reports()

    def setup_ui(self):
        # Search bar
        search_frame = tk.Frame(self.root)
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(search_frame, text="🔎 Search by Filename:").pack(side=tk.LEFT)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        search_entry.bind("<KeyRelease>", lambda event: self.load_reports())

        # Treeview
        columns = ("ID", "Filename", "Size", "Date")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.tree.column(col, anchor="w", width=150)
        self.tree.column("ID", width=60, anchor="center")

        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))
        scrollbar.pack(side=tk.RIGHT, fill="y", padx=(0, 10))

        self.tree.bind("<Double-1>", self.show_details)

    def load_reports(self):
        query = "SELECT id, filename, size, date FROM analysis"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Filter by search
        search_term = self.search_var.get().strip()
        if search_term:
            query += " WHERE filename LIKE ?"
            cursor.execute(query + " ORDER BY date DESC", ('%' + search_term + '%',))
        else:
            cursor.execute(query + " ORDER BY date DESC")

        rows = cursor.fetchall()
        conn.close()

        # Apply sorting if needed
        if self.sort_column:
            index = {"ID": 0, "Filename": 1, "Size": 2, "Date": 3}[self.sort_column]
            rows.sort(key=lambda x: x[index], reverse=self.sort_reverse)

        # Refresh tree
        for row in self.tree.get_children():
            self.tree.delete(row)
        for row in rows:
            self.tree.insert("", tk.END, values=row)

    def sort_by_column(self, col):
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = False
        self.load_reports()

    def show_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        report_id = self.tree.item(selected[0])["values"][0]

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analysis WHERE id=?", (report_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            detail_window = tk.Toplevel(self.root)
            detail_window.title(f"📄 Report Details - ID {row[0]}")
            detail_window.geometry("800x650")
            if os.path.exists(icon_path):
                detail_window.iconbitmap(icon_path)

            report_text = tk.Text(detail_window, wrap=tk.WORD, font=("Consolas", 10))
            report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            report_text.insert(tk.END, f"🆔 ID: {row[0]}\n")
            report_text.insert(tk.END, f"📁 Filename: {row[1]}\n")
            report_text.insert(tk.END, f"📦 Size: {row[2]} bytes\n")
            report_text.insert(tk.END, f"🕓 Date: {row[3]}\n\n")
            report_text.insert(tk.END, "📄 Metadata:\n" + row[4] + "\n\n")
            report_text.insert(tk.END, "🧪 Packers:\n" + row[5] + "\n\n")
            report_text.insert(tk.END, "🔍 Suspicious Strings:\n" + row[6])
            report_text.config(state=tk.DISABLED)
        else:
            messagebox.showerror("Error", "Report not found.")

def run_report_viewer():
    root = tk.Tk()
    ReportViewer(root)
    root.mainloop()

if __name__ == "__main__":
    run_report_viewer()
