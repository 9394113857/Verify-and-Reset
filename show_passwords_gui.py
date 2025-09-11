import tkinter as tk
from tkinter import ttk, messagebox
from flaskblog import db, bcrypt
from flaskblog.models import User, PasswordHistory
from tabulate import tabulate
from app import app  # import your Flask app


def search_passwords():
    query_text = entry.get().strip()
    if not query_text:
        messagebox.showwarning("Input Error", "Please enter at least 1 character of the email.")
        return

    with app.app_context():
        users = User.query.filter(User.email.ilike(f"{query_text}%")).all()
        if not users:
            messagebox.showinfo("No Results", f"No users found starting with '{query_text}'.")
            return

        all_records = []
        sno = 1
        for user in users:
            histories = PasswordHistory.query.filter_by(user_id=user.id).all()
            for record in histories:
                timestamp_str = (
                    record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    if record.timestamp else "N/A"
                )
                all_records.append([
                    sno,
                    user.id,
                    user.username,
                    user.email,
                    record.password_hash,
                    timestamp_str
                ])
                sno += 1

        if not all_records:
            messagebox.showinfo("No Results", "No password history found for this user.")
            return

        table = tabulate(
            all_records,
            headers=["S.No", "User ID", "Username", "Email", "Password Hash", "History Timestamp"],
            tablefmt="grid"
        )
        text.delete(1.0, tk.END)
        text.insert(tk.END, table)


# Tkinter GUI setup
root = tk.Tk()
root.title("Password History Viewer")

# --- Dynamically detect screen size ---
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Adjust window size slightly smaller than full screen
window_width = int(screen_width * 0.95)
window_height = int(screen_height * 0.85)

# Apply to window
root.geometry(f"{window_width}x{window_height}+0+0")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

label = ttk.Label(frame, text="Enter starting part of Email (even 1 char works):")
label.grid(row=0, column=0, sticky=tk.W)

entry = ttk.Entry(frame, width=40)
entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

search_btn = ttk.Button(frame, text="Search", command=search_passwords)
search_btn.grid(row=0, column=2, padx=5)

# Make text area dynamically expand
text = tk.Text(root, wrap="none")
text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Stretch text widget dynamically
root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

root.mainloop()
