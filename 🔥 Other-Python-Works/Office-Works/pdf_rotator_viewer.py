import os
import fitz  # PyMuPDF
from PIL import Image, ImageTk
import PyPDF2
from tkinter import (
    Tk, Toplevel, filedialog, Button, Label, Listbox, Scrollbar,
    messagebox, Canvas, Frame, END, SINGLE, BOTH, Y
)


class PDFRotatorViewer:
    def __init__(self, master):
        self.master = master
        self.master.title("PDF Rotator & Viewer")
        self.master.geometry("700x550")
        self.master.configure(bg="white")

        self.folder_path = None
        self.pdf_files = []
        self.pdf_reader = None
        self.doc = None
        self.current_page_index = 0
        self.rotations = {}

        Button(master, text="Select Folder Containing PDFs", command=self.select_folder,
               width=30, font=("Arial", 12)).pack(pady=20)

        list_frame = Frame(master)
        list_frame.pack(fill='both', expand=True, padx=10)

        self.scrollbar = Scrollbar(list_frame)
        self.scrollbar.pack(side='right', fill=Y)

        self.pdf_listbox = Listbox(
            list_frame,
            yscrollcommand=self.scrollbar.set,
            selectmode=SINGLE,
            font=("Courier New", 11),
            width=60
        )
        self.pdf_listbox.pack(fill='both', expand=True)
        self.scrollbar.config(command=self.pdf_listbox.yview)

        Button(master, text="Open Selected PDF", command=self.load_selected_pdf,
               width=25, font=("Arial", 12)).pack(pady=10)

        self.save_main_btn = Button(master, text="💾 Save Rotated PDF", width=25,
                                    font=("Arial", 12), command=self.save_rotated_pdf, state="disabled")
        self.save_main_btn.pack(pady=5)

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path = folder
            self.load_pdf_list()

    def load_pdf_list(self):
        self.pdf_files.clear()
        self.pdf_listbox.delete(0, END)

        if not self.folder_path:
            return

        for filename in os.listdir(self.folder_path):
            if filename.lower().endswith('.pdf'):
                full_path = os.path.join(self.folder_path, filename)
                size_bytes = os.path.getsize(full_path)
                size_mb = size_bytes / (1024 * 1024)
                size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{int(size_bytes / 1024)} KB"
                self.pdf_files.append((filename, full_path, size_str))

        self.pdf_listbox.insert(END, f"{'File Name':50}\t{'Size'}")
        self.pdf_listbox.insert(END, "-" * 70)
        for fname, _, size_str in self.pdf_files:
            display_text = f"{fname:50}\t{size_str}"
            self.pdf_listbox.insert(END, display_text)

    def load_selected_pdf(self):
        idx = self.pdf_listbox.curselection()
        if not idx or idx[0] < 2:
            messagebox.showerror("Error", "Please select a valid PDF file!")
            return

        _, path, _ = self.pdf_files[idx[0] - 2]
        try:
            self.doc = fitz.open(path)
            self.pdf_reader = PyPDF2.PdfReader(path)
            self.current_page_index = 0
            self.rotations = {i: 0 for i in range(len(self.doc))}
            self.show_preview_window()
            self.save_main_btn.config(state="normal")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load PDF:\n{e}")

    def show_preview_window(self):
        self.preview_win = Toplevel(self.master)
        self.preview_win.title("PDF Preview & Rotate")
        self.preview_win.geometry("820x900")
        self.preview_win.configure(bg="white")

        main_frame = Frame(self.preview_win, bg="white")
        main_frame.pack(fill=BOTH, expand=True)

        self.canvas = Canvas(main_frame, width=700, height=600, bg="white")
        self.canvas.pack(pady=10)

        self.page_label = Label(main_frame, text="", font=("Arial", 14), bg="white")
        self.page_label.pack(pady=5)

        btn_frame = Frame(main_frame, bg="white")
        btn_frame.pack(pady=10)

        Button(btn_frame, text="Previous", width=12, command=self.show_previous_page).grid(row=0, column=0, padx=5)
        Button(btn_frame, text="Next", width=12, command=self.show_next_page).grid(row=0, column=1, padx=5)
        Button(btn_frame, text="Rotate Left", width=12, command=self.rotate_left).grid(row=0, column=2, padx=5)
        Button(btn_frame, text="Rotate Right", width=12, command=self.rotate_right).grid(row=0, column=3, padx=5)
        Button(btn_frame, text="Delete Page", width=12, fg="white", bg="red", command=self.delete_current_page).grid(row=0, column=4, padx=5)

        self.save_btn = Button(main_frame, text="💾 Save Rotated PDF", width=30, bg="#4CAF50", fg="white",
                               command=self.save_rotated_pdf)
        self.save_btn.pack(pady=20)

        self.update_page_image()

    def update_page_image(self):
        if not self.doc or len(self.doc) == 0:
            self.canvas.delete("all")
            self.page_label.config(text="No pages to display.")
            return

        if self.current_page_index >= len(self.doc):
            self.current_page_index = len(self.doc) - 1
        if self.current_page_index < 0:
            self.current_page_index = 0

        page = self.doc.load_page(self.current_page_index)
        rot = self.rotations.get(self.current_page_index, 0)

        mat = fitz.Matrix(2, 2).prerotate(rot)
        pix = page.get_pixmap(matrix=mat)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

        max_w, max_h = 700, 600
        scale = min(max_w / img.width, max_h / img.height, 1)
        img_resized = img.resize((int(img.width * scale), int(img.height * scale)), Image.LANCZOS)

        self.tk_img = ImageTk.PhotoImage(img_resized)
        self.canvas.delete("all")
        self.canvas.create_image((max_w - img_resized.width) // 2, 0, anchor='nw', image=self.tk_img)

        self.page_label.config(
            text=f"Page {self.current_page_index + 1} of {len(self.doc)} | Rotation: {rot}°")

    def show_next_page(self):
        if self.doc and self.current_page_index < len(self.doc) - 1:
            self.current_page_index += 1
            self.update_page_image()

    def show_previous_page(self):
        if self.doc and self.current_page_index > 0:
            self.current_page_index -= 1
            self.update_page_image()

    def rotate_left(self):
        if not self.doc:
            return
        self.rotations[self.current_page_index] = (self.rotations.get(self.current_page_index, 0) - 90) % 360
        self.update_page_image()

    def rotate_right(self):
        if not self.doc:
            return
        self.rotations[self.current_page_index] = (self.rotations.get(self.current_page_index, 0) + 90) % 360
        self.update_page_image()

    def delete_current_page(self):
        if not self.doc or len(self.doc) == 0:
            messagebox.showinfo("Info", "No pages to delete.")
            return

        confirm = messagebox.askyesno("Delete Page", f"Are you sure you want to delete page {self.current_page_index + 1}?")
        if not confirm:
            return

        self.doc.delete_page(self.current_page_index)

        new_rotations = {}
        for i in range(len(self.doc)):
            if i < self.current_page_index:
                new_rotations[i] = self.rotations.get(i, 0)
            else:
                new_rotations[i] = self.rotations.get(i + 1, 0)
        self.rotations = new_rotations

        if self.current_page_index >= len(self.doc):
            self.current_page_index = len(self.doc) - 1

        if len(self.doc) == 0:
            messagebox.showinfo("Info", "All pages deleted from the PDF.")
            self.save_main_btn.config(state="disabled")
            self.save_btn.config(state="disabled")
            self.canvas.delete("all")
            self.page_label.config(text="No pages to display.")
            return

        self.update_page_image()

    def save_rotated_pdf(self):
        if not self.doc or len(self.doc) == 0:
            messagebox.showerror("Error", "No PDF loaded or no pages to save.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Rotated PDF As",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")]
        )
        if not save_path:
            return

        writer = PyPDF2.PdfWriter()
        for i in range(len(self.doc)):
            page = self.pdf_reader.pages[i]
            rotation = self.rotations.get(i, 0)
            page.rotate(rotation)  # ✅ Replaces deprecated rotate_clockwise
            writer.add_page(page)

        with open(save_path, "wb") as f:
            writer.write(f)

        messagebox.showinfo("Success", f"PDF saved as:\n{os.path.basename(save_path)}")


if __name__ == "__main__":
    root = Tk()
    app = PDFRotatorViewer(root)
    root.mainloop()
