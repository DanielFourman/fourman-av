

import os
import sys
import queue
import shutil
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --------------------------------------------------------------------------- #
# Paths / config
# --------------------------------------------------------------------------- #
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_EXE   = os.path.join(APP_DIR, "scanner.exe")
HASHDB_PATH   = os.path.join(APP_DIR, "recent.csv")
QUARANTINE    = os.path.join(APP_DIR, "quarantine")

# abuse.ch MalwareBazaar "recent" export. Put your Auth-Key in the field.
API_URL_TMPL  = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        root.title("Fourman AV  —  SHA-256 signature scanner")
        root.geometry("820x600")
        root.minsize(700, 520)

        self.scan_folder = tk.StringVar(value="")
        self.quarantine  = tk.StringVar(value=QUARANTINE)
        self.auth_key    = tk.StringVar(value="")
        self.status      = tk.StringVar(value="Idle.")

        self.proc      = None            # running scanner subprocess
        self.msg_queue = queue.Queue()   # engine records -> UI thread
        self.total     = 0
        self.scanned   = 0
        self.detected  = 0

        self._build_ui()
        self.root.after(80, self._drain_queue)

    # ------------------------------------------------------------------ UI -- #
    def _build_ui(self):
        pad = dict(padx=8, pady=4)

        # --- top: folder selection ---
        top = ttk.LabelFrame(self.root, text="Targets")
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Scan folder:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(top, textvariable=self.scan_folder).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Browse…", command=self._pick_scan).grid(row=0, column=2, padx=6)

        ttk.Label(top, text="Quarantine:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(top, textvariable=self.quarantine).grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Browse…", command=self._pick_quar).grid(row=1, column=2, padx=6)

        top.columnconfigure(1, weight=1)

        # --- database row ---
        dbf = ttk.LabelFrame(self.root, text="Signature database (abuse.ch / MalwareBazaar)")
        dbf.pack(fill="x", **pad)

        ttk.Label(dbf, text="Auth-Key:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(dbf, textvariable=self.auth_key, show="*").grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(dbf, text="Update database", command=self._update_db).grid(row=0, column=2, padx=6)
        self.db_info = ttk.Label(dbf, text=self._db_status_text())
        self.db_info.grid(row=1, column=0, columnspan=3, sticky="w", padx=6, pady=(0, 4))
        dbf.columnconfigure(1, weight=1)

        # --- controls ---
        ctl = ttk.Frame(self.root)
        ctl.pack(fill="x", **pad)
        self.btn_scan = ttk.Button(ctl, text="▶  Start scan", command=self._start_scan)
        self.btn_scan.pack(side="left", padx=6)
        self.btn_stop = ttk.Button(ctl, text="■  Stop", command=self._stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(ctl, text="Open quarantine", command=self._open_quarantine).pack(side="left", padx=6)

        # --- progress ---
        prog = ttk.Frame(self.root)
        prog.pack(fill="x", **pad)
        self.pbar = ttk.Progressbar(prog, mode="determinate", maximum=100)
        self.pbar.pack(fill="x", padx=6, pady=(2, 2))

        counters = ttk.Frame(self.root)
        counters.pack(fill="x", **pad)
        self.lbl_scanned  = ttk.Label(counters, text="Scanned: 0")
        self.lbl_scanned.pack(side="left", padx=10)
        self.lbl_detected = ttk.Label(counters, text="Detected: 0", foreground="#b00020")
        self.lbl_detected.pack(side="left", padx=10)
        ttk.Label(counters, textvariable=self.status).pack(side="right", padx=10)

        # --- log ---
        logf = ttk.LabelFrame(self.root, text="Scan log")
        logf.pack(fill="both", expand=True, **pad)
        self.log = tk.Text(logf, height=12, wrap="none", state="disabled",
                           background="#111318", foreground="#e6e6e6",
                           insertbackground="#e6e6e6", font=("Consolas", 9))
        yscroll = ttk.Scrollbar(logf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=yscroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        self.log.tag_config("detect", foreground="#ff6b6b")
        self.log.tag_config("clean",  foreground="#7bd88f")
        self.log.tag_config("info",   foreground="#8ab4f8")
        self.log.tag_config("error",  foreground="#ffcc66")
        self.log.tag_config("quar",   foreground="#ffa94d")

    # --------------------------------------------------------------- helpers -- #
    def _db_status_text(self):
        if os.path.exists(HASHDB_PATH):
            size = os.path.getsize(HASHDB_PATH)
            return f"Database: recent.csv  ({size:,} bytes)"
        return "Database: not downloaded yet — click “Update database”."

    def _log(self, text, tag="info"):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _pick_scan(self):
        d = filedialog.askdirectory(title="Select folder to scan")
        if d:
            self.scan_folder.set(d)

    def _pick_quar(self):
        d = filedialog.askdirectory(title="Select quarantine folder")
        if d:
            self.quarantine.set(d)

    def _open_quarantine(self):
        q = self.quarantine.get() or QUARANTINE
        os.makedirs(q, exist_ok=True)
        try:
            os.startfile(q)  # Windows
        except AttributeError:
            subprocess.Popen(["xdg-open", q])

    # ------------------------------------------------------------- database -- #
    def _update_db(self):
        key = self.auth_key.get().strip()
        if not key:
            messagebox.showwarning(
                "Auth-Key required",
                "Enter your abuse.ch / MalwareBazaar Auth-Key first.\n\n"
                "Get one free at https://auth.abuse.ch/")
            return

        self.status.set("Downloading signatures…")
        self._log("Updating database via curl…", "info")

        def worker():
            url = API_URL_TMPL.format(key=key)
            # Also send the key as an Auth-Key header (newer API style).
            cmd = ["curl", "-sS", "-L",
                   "-H", f"Auth-Key: {key}",
                   "-o", HASHDB_PATH, url]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if r.returncode != 0:
                    self.msg_queue.put(("ERR", f"curl failed: {r.stderr.strip()}"))
                else:
                    self.msg_queue.put(("DBOK", None))
            except Exception as e:
                self.msg_queue.put(("ERR", f"download error: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    # ----------------------------------------------------------------- scan -- #
    def _start_scan(self):
        folder = self.scan_folder.get().strip()
        quar   = self.quarantine.get().strip() or QUARANTINE

        if not folder or not os.path.isdir(folder):
            messagebox.showerror("No folder", "Pick a valid folder to scan.")
            return
        if not os.path.exists(SCANNER_EXE):
            messagebox.showerror(
                "Engine missing",
                f"scanner.exe was not found next to this script:\n{SCANNER_EXE}\n\n"
                "Build it first (see README / build.bat).")
            return
        if not os.path.exists(HASHDB_PATH):
            messagebox.showerror("No database",
                                 "No signature database. Click “Update database” first.")
            return

        os.makedirs(quar, exist_ok=True)

        # reset state
        self.total = self.scanned = self.detected = 0
        self.pbar.configure(value=0, maximum=100, mode="indeterminate")
        self.pbar.start(15)
        self._set_counters()
        self.status.set("Starting engine…")
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._log(f"=== Scan started: {folder} ===", "info")

        cmd = [SCANNER_EXE, HASHDB_PATH, folder, quar]

        def reader():
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                for line in self.proc.stdout:
                    self.msg_queue.put(("LINE", line.rstrip("\n")))
                self.proc.wait()
            except Exception as e:
                self.msg_queue.put(("ERR", f"engine error: {e}"))
            finally:
                self.msg_queue.put(("EXIT", None))

        threading.Thread(target=reader, daemon=True).start()

    def _stop_scan(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.status.set("Stopping…")

    # -------------------------------------------------- engine record parse -- #
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "LINE":
                    self._handle_record(payload)
                elif kind == "DBOK":
                    self.db_info.configure(text=self._db_status_text())
                    self.status.set("Database updated.")
                    self._log("Database updated: " + self._db_status_text(), "info")
                elif kind == "ERR":
                    self.status.set("Error.")
                    self._log(payload, "error")
                elif kind == "EXIT":
                    self._scan_finished()
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _handle_record(self, line):
        if not line:
            return
        parts = line.split(" ", 1)
        tag = parts[0]
        rest = parts[1] if len(parts) > 1 else ""

        if tag == "HASHES":
            self._log(f"Loaded {rest} signatures.", "info")
        elif tag == "TOTAL":
            try:
                self.total = int(rest)
            except ValueError:
                self.total = 0
            self.pbar.stop()
            self.pbar.configure(mode="determinate",
                                maximum=max(self.total, 1), value=0)
            self.status.set(f"Scanning {self.total} files…")
            self._log(f"Found {self.total} files to scan.", "info")
        elif tag == "SCAN":
            self.status.set("Scanning: " + os.path.basename(rest))
        elif tag == "PROGRESS":
            try:
                self.scanned = int(rest)
            except ValueError:
                pass
            self.pbar.configure(value=self.scanned)
            self._set_counters()
        elif tag == "CLEAN":
            self._log("  clean   " + rest, "clean")
        elif tag == "DETECT":
            path, _, h = rest.partition("|")
            self.detected += 1
            self._set_counters()
            self._log(f"  THREAT  {path}", "detect")
            self._log(f"          sha256={h}", "detect")
        elif tag == "QUARANTINE":
            self._log("  moved -> " + rest, "quar")
        elif tag == "ERROR":
            self._log("  error   " + rest, "error")
        elif tag == "DONE":
            nums = rest.split()
            if len(nums) == 2:
                self.scanned, self.detected = int(nums[0]), int(nums[1])
                self._set_counters()

    def _set_counters(self):
        self.lbl_scanned.configure(text=f"Scanned: {self.scanned}")
        self.lbl_detected.configure(text=f"Detected: {self.detected}")

    def _scan_finished(self):
        self.pbar.stop()
        if self.total:
            self.pbar.configure(mode="determinate", maximum=max(self.total, 1),
                                value=self.total)
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status.set(f"Done. {self.detected} threat(s) found.")
        self._log(f"=== Scan finished: {self.scanned} scanned, "
                  f"{self.detected} detected ===",
                  "detect" if self.detected else "info")
        self.proc = None


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    AntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
