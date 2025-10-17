import tkinter as tk
from tkinter import ttk
import subprocess
from datetime import datetime

class GitLogViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("🌿 Git Log Viewer")
        self.page = 0
        self.items_per_page = 10
        self.all_commits = []

        self.setup_styles()

        # === Main Frame ===
        self.root.configure(bg='#1e1e2f')
        main_frame = ttk.Frame(root, padding="10", style="Main.TFrame")
        main_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        # === Title ===
        title_label = ttk.Label(main_frame, text="📦 Git Commit Viewer", style="Title.TLabel")
        title_label.grid(row=0, column=0, pady=(0, 10), sticky=tk.W)

        # === Branch Dropdown and Total Commits Frame ===
        branch_frame = ttk.Frame(main_frame, style="Main.TFrame")
        branch_frame.grid(row=1, column=0, sticky=tk.W, pady=(0,10))

        ttk.Label(branch_frame, text="🌿 Branch:", style="Label.TLabel").pack(side=tk.LEFT)
        self.branch_var = tk.StringVar()
        self.branch_dropdown = ttk.Combobox(branch_frame, textvariable=self.branch_var, state="readonly", width=30)
        self.branch_dropdown.pack(side=tk.LEFT, padx=5)
        self.branch_dropdown.bind("<<ComboboxSelected>>", self.on_branch_selected)

        # Total commits label
        self.total_commits_label = ttk.Label(branch_frame, text="Total Commits: 0", style="Label.TLabel")
        self.total_commits_label.pack(side=tk.LEFT, padx=20)

        # === Search Section ===
        search_frame = ttk.Frame(main_frame, style="Main.TFrame")
        search_frame.grid(row=2, column=0, pady=10, sticky=tk.W)

        ttk.Label(search_frame, text="🔍 Search:", style="Label.TLabel").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_commits)
        ttk.Entry(search_frame, textvariable=self.search_var, width=40).pack(side=tk.LEFT, padx=5)

        # === Table Section ===
        columns = ('No', 'Hash', 'Author', 'Ago', 'Date', 'Message')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15, style="Custom.Treeview")
        for col in columns:
            self.tree.heading(col, text=col)
            if col == 'Message':
                self.tree.column(col, width=350)
            elif col == 'No':
                self.tree.column(col, width=50, anchor='center')
            else:
                self.tree.column(col, width=110)
        self.tree.grid(row=3, column=0, sticky=tk.W+tk.E)

        self.tree.bind("<Double-1>", self.on_row_double_click)

        # === Navigation Buttons ===
        nav_frame = ttk.Frame(main_frame, style="Main.TFrame")
        nav_frame.grid(row=4, column=0, pady=15)

        ttk.Button(nav_frame, text="⏮ Start", command=self.go_start, style="Nav.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_frame, text="⬅ Previous", command=self.prev_page, style="Nav.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_frame, text="➡ Next", command=self.next_page, style="Nav.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_frame, text="⏭ End", command=self.go_end, style="Nav.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_frame, text="❌ Close", command=root.quit, style="Nav.TButton").pack(side=tk.LEFT, padx=20)

        self.load_branches()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Main.TFrame", background="#1e1e2f")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), foreground="#ffffff", background="#1e1e2f")
        style.configure("Label.TLabel", foreground="#ffffff", background="#1e1e2f", font=("Segoe UI", 10))
        style.configure("Nav.TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Treeview", 
                        background="#2c2c3c", 
                        foreground="#ffffff", 
                        fieldbackground="#2c2c3c", 
                        rowheight=25,
                        font=("Segoe UI", 9))
        style.map("Treeview", background=[('selected', '#4444aa')])
        style.configure("Custom.Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def load_branches(self):
        try:
            output = subprocess.check_output(
                'git branch --all --format="%(refname:short)"',
                shell=True
            ).decode("utf-8")

            branches = sorted(set([line.strip() for line in output.splitlines() if line.strip()]))
            self.branches = branches

            current_branch = subprocess.check_output(
                'git branch --show-current',
                shell=True
            ).decode("utf-8").strip()

            self.branch_dropdown['values'] = branches
            self.branch_var.set(current_branch if current_branch in branches else branches[0])

            self.load_git_log(branch=self.branch_var.get())
        except subprocess.CalledProcessError:
            self.branches = []
            self.branch_dropdown['values'] = []
            self.all_commits = []
            self.filtered_commits = []
            self.update_total_commits_label()

    def load_git_log(self, branch=None):
        if not branch:
            branch = self.branch_var.get() if hasattr(self, 'branch_var') else 'HEAD'

        cmd = f'git log {branch} --pretty=format:"%h|%an|%ar|%ad|%s" --date=iso'
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
            self.all_commits = []

            for line in output.split('\n'):
                if not line.strip():
                    continue

                parts = line.split('|', 4)
                if len(parts) != 5:
                    continue

                hash_val, author, ago, full_date, message = parts
                try:
                    dt = datetime.strptime(full_date.strip().split()[0], "%Y-%m-%d")
                    pretty_date = dt.strftime("%d %B %Y")
                except ValueError:
                    pretty_date = full_date.strip()

                self.all_commits.append([hash_val, author, ago, pretty_date, message])

            self.filtered_commits = self.all_commits.copy()
            self.page = 0
            self.update_total_commits_label()
            self.display_commits()

        except subprocess.CalledProcessError:
            self.all_commits = []
            self.filtered_commits = []
            self.tree.delete(*self.tree.get_children())
            self.update_total_commits_label()

    def update_total_commits_label(self):
        count = len(self.filtered_commits) if hasattr(self, 'filtered_commits') else 0
        self.total_commits_label.config(text=f"Total Commits: {count}")

    def display_commits(self):
        self.tree.delete(*self.tree.get_children())
        start = self.page * self.items_per_page
        end = start + self.items_per_page

        for i, commit in enumerate(self.filtered_commits[start:end], start=start + 1):
            self.tree.insert('', 'end', values=(i,) + tuple(commit))

    def filter_commits(self, *args):
        search_term = self.search_var.get().lower()
        self.filtered_commits = [
            commit for commit in self.all_commits
            if search_term in '|'.join(commit).lower()
        ]
        self.page = 0
        self.update_total_commits_label()
        self.display_commits()

    def next_page(self):
        if (self.page + 1) * self.items_per_page < len(self.filtered_commits):
            self.page += 1
            self.display_commits()

    def prev_page(self):
        if self.page > 0:
            self.page -= 1
            self.display_commits()

    def go_start(self):
        self.page = 0
        self.display_commits()

    def go_end(self):
        total = len(self.filtered_commits)
        if total > 0:
            self.page = (total - 1) // self.items_per_page
        else:
            self.page = 0
        self.display_commits()

    def on_branch_selected(self, event=None):
        selected_branch = self.branch_var.get()
        self.load_git_log(branch=selected_branch)
        self.search_var.set('')  # Clear search on branch change

    def on_row_double_click(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            return

        commit_values = self.tree.item(selected_item)['values']
        commit_hash = commit_values[1]

        try:
            detail = subprocess.check_output(
                f'git show --no-patch --pretty=fuller {commit_hash}',
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode('utf-8')
        except subprocess.CalledProcessError:
            detail = f"Error: Could not fetch details for {commit_hash}"

        self.show_commit_popup(commit_hash, detail)

    def show_commit_popup(self, commit_hash, detail_text):
        popup = tk.Toplevel(self.root)
        popup.title(f"🔎 Commit Details - {commit_hash}")
        popup.configure(bg='#1e1e2f')
        popup.geometry("700x500")

        frame = ttk.Frame(popup, padding="10", style="Main.TFrame")
        frame.pack(fill=tk.BOTH, expand=True)

        text_widget = tk.Text(frame, wrap=tk.WORD, bg='#2c2c3c', fg='white', insertbackground='white', font=("Consolas", 10))
        text_widget.insert(tk.END, detail_text)
        text_widget.configure(state='disabled')
        text_widget.pack(fill=tk.BOTH, expand=True)

        ttk.Button(frame, text="Close", command=popup.destroy, style="Nav.TButton").pack(pady=10)


if __name__ == '__main__':
    root = tk.Tk()
    app = GitLogViewer(root)
    root.mainloop()
