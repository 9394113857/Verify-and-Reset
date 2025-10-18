import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Functions
def calculate():
    try:
        # FD inputs
        fd_principal = float(fd_principal_entry.get())
        fd_months = float(fd_months_entry.get())
        fd_rate = float(fd_rate_entry.get())
        fd_comp = int(fd_comp_entry.get())

        # RD inputs
        rd_monthly = float(rd_monthly_entry.get())
        rd_months = float(rd_months_entry.get())
        rd_rate = float(rd_rate_entry.get())
        rd_comp = int(rd_comp_entry.get())

        # FD calculation
        t_fd = fd_months / 12
        r_fd = fd_rate / 100
        n_fd = fd_comp
        fd_maturity = fd_principal * (1 + r_fd/n_fd)**(n_fd*t_fd)
        fd_interest = fd_maturity - fd_principal
        fd_extra = fd_interest  # For FD, extra money = interest earned

        # RD calculation
        t_rd = rd_months / 12
        r_rd = rd_rate / 100
        n_rd = rd_comp
        rd_maturity = rd_monthly * ((1 + r_rd/n_rd)**(n_rd*t_rd) - 1) / (1 - (1 + r_rd/n_rd)**(-1/12))
        rd_total_principal = rd_monthly * rd_months
        rd_interest = rd_maturity - rd_total_principal
        rd_extra = rd_interest  # Extra money = interest

        # Show results
        fd_maturity_var.set(f"Maturity Value: ₹{round(fd_maturity,2)}")
        fd_interest_var.set(f"Interest Earned: ₹{round(fd_interest,2)}")
        fd_extra_var.set(f"Extra Money Gained: ₹{round(fd_extra,2)}")

        rd_maturity_var.set(f"Maturity Value: ₹{round(rd_maturity,2)}")
        rd_interest_var.set(f"Interest Earned: ₹{round(rd_interest,2)}")
        rd_extra_var.set(f"Extra Money Gained: ₹{round(rd_extra,2)}")

    except Exception as e:
        messagebox.showerror("Error", f"Invalid input! {e}")

def reset():
    # FD defaults
    fd_principal_entry.delete(0, tk.END)
    fd_principal_entry.insert(0, "72000")
    fd_months_entry.delete(0, tk.END)
    fd_months_entry.insert(0, "24")
    fd_rate_entry.delete(0, tk.END)
    fd_rate_entry.insert(0, "6.7")
    fd_comp_entry.delete(0, tk.END)
    fd_comp_entry.insert(0, "4")

    # RD defaults
    rd_monthly_entry.delete(0, tk.END)
    rd_monthly_entry.insert(0, "3000")
    rd_months_entry.delete(0, tk.END)
    rd_months_entry.insert(0, "24")
    rd_rate_entry.delete(0, tk.END)
    rd_rate_entry.insert(0, "6.7")
    rd_comp_entry.delete(0, tk.END)
    rd_comp_entry.insert(0, "4")

    fd_maturity_var.set("")
    fd_interest_var.set("")
    fd_extra_var.set("")

    rd_maturity_var.set("")
    rd_interest_var.set("")
    rd_extra_var.set("")

def exit_app():
    root.destroy()

# Main Window
root = tk.Tk()
root.title("💰 FD & RD Calculator with Interest")
root.geometry("800x500")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

# Title Label
title_label = tk.Label(root, text="FD & RD CALCULATOR", font=("Helvetica", 20, "bold"), bg="#f0f0f0", fg="#2c3e50")
title_label.pack(pady=10)

# Main Frame
main_frame = tk.Frame(root, bg="#f0f0f0")
main_frame.pack(fill="both", expand=True, padx=20, pady=10)

# FD Frame
fd_frame = ttk.LabelFrame(main_frame, text="Fixed Deposit (FD)")
fd_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")
fd_frame.columnconfigure(1, weight=1)

# FD Inputs
ttk.Label(fd_frame, text="Principal (₹)").grid(row=0, column=0, padx=5, pady=5, sticky="w")
fd_principal_entry = ttk.Entry(fd_frame, width=15)
fd_principal_entry.grid(row=0, column=1, padx=5, pady=5)
fd_principal_entry.insert(0,"72000")

ttk.Label(fd_frame, text="Time (Months)").grid(row=1, column=0, padx=5, pady=5, sticky="w")
fd_months_entry = ttk.Entry(fd_frame, width=15)
fd_months_entry.grid(row=1, column=1, padx=5, pady=5)
fd_months_entry.insert(0,"24")

ttk.Label(fd_frame, text="Annual Interest Rate (%)").grid(row=2, column=0, padx=5, pady=5, sticky="w")
fd_rate_entry = ttk.Entry(fd_frame, width=15)
fd_rate_entry.grid(row=2, column=1, padx=5, pady=5)
fd_rate_entry.insert(0,"6.7")

ttk.Label(fd_frame, text="Compounding per Year").grid(row=3, column=0, padx=5, pady=5, sticky="w")
fd_comp_entry = ttk.Entry(fd_frame, width=15)
fd_comp_entry.grid(row=3, column=1, padx=5, pady=5)
fd_comp_entry.insert(0,"4")

# FD Results
fd_maturity_var = tk.StringVar()
fd_interest_var = tk.StringVar()
fd_extra_var = tk.StringVar()

tk.Label(fd_frame, textvariable=fd_maturity_var, fg="#1abc9c", font=("Helvetica",12,"bold")).grid(row=4,column=0,columnspan=2,pady=3)
tk.Label(fd_frame, textvariable=fd_interest_var, fg="#16a085", font=("Helvetica",12,"bold")).grid(row=5,column=0,columnspan=2,pady=3)
tk.Label(fd_frame, textvariable=fd_extra_var, fg="#2ecc71", font=("Helvetica",12,"bold")).grid(row=6,column=0,columnspan=2,pady=3)

# RD Frame
rd_frame = ttk.LabelFrame(main_frame, text="Recurring Deposit (RD)")
rd_frame.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")
rd_frame.columnconfigure(1, weight=1)

# RD Inputs
ttk.Label(rd_frame, text="Monthly Deposit (₹)").grid(row=0, column=0, padx=5, pady=5, sticky="w")
rd_monthly_entry = ttk.Entry(rd_frame, width=15)
rd_monthly_entry.grid(row=0, column=1, padx=5, pady=5)
rd_monthly_entry.insert(0,"3000")

ttk.Label(rd_frame, text="Number of Months").grid(row=1, column=0, padx=5, pady=5, sticky="w")
rd_months_entry = ttk.Entry(rd_frame, width=15)
rd_months_entry.grid(row=1, column=1, padx=5, pady=5)
rd_months_entry.insert(0,"24")

ttk.Label(rd_frame, text="Annual Interest Rate (%)").grid(row=2, column=0, padx=5, pady=5, sticky="w")
rd_rate_entry = ttk.Entry(rd_frame, width=15)
rd_rate_entry.grid(row=2, column=1, padx=5, pady=5)
rd_rate_entry.insert(0,"6.7")

ttk.Label(rd_frame, text="Compounding per Year").grid(row=3, column=0, padx=5, pady=5, sticky="w")
rd_comp_entry = ttk.Entry(rd_frame, width=15)
rd_comp_entry.grid(row=3, column=1, padx=5, pady=5)
rd_comp_entry.insert(0,"4")

# RD Results
rd_maturity_var = tk.StringVar()
rd_interest_var = tk.StringVar()
rd_extra_var = tk.StringVar()

tk.Label(rd_frame, textvariable=rd_maturity_var, fg="#e67e22", font=("Helvetica",12,"bold")).grid(row=4,column=0,columnspan=2,pady=3)
tk.Label(rd_frame, textvariable=rd_interest_var, fg="#d35400", font=("Helvetica",12,"bold")).grid(row=5,column=0,columnspan=2,pady=3)
tk.Label(rd_frame, textvariable=rd_extra_var, fg="#f39c12", font=("Helvetica",12,"bold")).grid(row=6,column=0,columnspan=2,pady=3)

# Buttons Frame
btn_frame = tk.Frame(root, bg="#f0f0f0")
btn_frame.pack(pady=10)

calc_btn = tk.Button(btn_frame, text="Calculate", command=calculate, bg="#3498db", fg="white", width=15, font=("Helvetica",10,"bold"))
calc_btn.grid(row=0, column=0, padx=10)

reset_btn = tk.Button(btn_frame, text="Reset", command=reset, bg="#95a5a6", fg="white", width=15, font=("Helvetica",10,"bold"))
reset_btn.grid(row=0, column=1, padx=10)

exit_btn = tk.Button(btn_frame, text="Exit", command=exit_app, bg="#e74c3c", fg="white", width=15, font=("Helvetica",10,"bold"))
exit_btn.grid(row=0, column=2, padx=10)

root.mainloop()
