import os
import fitz  # PyMuPDF
from PIL import Image, ImageTk
import PyPDF2
from tkinter import Tk, Toplevel, filedialog, Button, Label, Entry, StringVar, messagebox, Canvas


class PDFSplitter:
    def __init__(self, master):
        self.master = master
        self.master.title("PDF Splitter")
        self.master.geometry("600x400")
        self.master.configure(bg="white")

        self.pdf_file_path = None
        self.pdf_reader = None
        self.output_path = None
        self.current_page_index = 0
        self.page_images = []

        # File Select Button
        self.select_button = Button(master, text="Select PDF File", command=self.select_pdf_file, width=25, font=("Arial", 12))
        self.select_button.pack(pady=40)

        self.output_label = None
        self.output_entry = None
        self.range_label = None
        self.range_entry = None
        self.save_button = None

        self.output_file_var = StringVar()
        self.page_range_var = StringVar()

    def select_pdf_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if file_path:
            self.pdf_file_path = file_path
            self.pdf_reader = PyPDF2.PdfReader(open(file_path, "rb"))
            self.load_pdf_preview(file_path)

    def load_pdf_preview(self, file_path):
        try:
            doc = fitz.open(file_path)
            self.page_images = []

            for page in doc:
                pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                self.page_images.append(img)

            self.show_preview_window()
            self.show_input_widgets()
        except Exception as e:
            messagebox.showerror("Error", f"Could not load PDF preview: {e}")

    def show_input_widgets(self):
        self.output_label = Label(self.master, text="Output File Name (e.g. Q-0001):", bg="white")
        self.output_label.pack(pady=(10, 2))
        self.output_entry = Entry(self.master, textvariable=self.output_file_var, width=30)
        self.output_entry.pack()

        self.range_label = Label(self.master, text="Page Range (e.g. 2-5):", bg="white")
        self.range_label.pack(pady=(10, 2))
        self.range_entry = Entry(self.master, textvariable=self.page_range_var, width=30)
        self.range_entry.pack()

        self.save_button = Button(self.master, text="Export Pages", command=self.save_selected_pages, width=20, font=("Arial", 12))
        self.save_button.pack(pady=15)

    def show_preview_window(self):
        self.preview_win = Toplevel(self.master)
        self.preview_win.title("PDF Preview")
        self.preview_win.geometry("700x750")
        self.preview_win.configure(bg="white")

        self.canvas = Canvas(self.preview_win, width=680, height=640, bg="white", highlightthickness=0)
        self.canvas.pack(pady=10)

        self.page_label = Label(self.preview_win, text="", font=("Arial", 10), bg="white")
        self.page_label.pack(pady=5)

        btn_frame = Label(self.preview_win, bg="white")
        btn_frame.pack(pady=5)

        Button(btn_frame, text="Previous", command=self.show_previous_page, width=10).grid(row=0, column=0, padx=5)
        Button(btn_frame, text="Next", command=self.show_next_page, width=10).grid(row=0, column=1, padx=5)

        self.image_on_canvas = None
        self.update_preview_image()

        self.preview_win.bind("<Left>", lambda event: self.show_previous_page())
        self.preview_win.bind("<Right>", lambda event: self.show_next_page())
        self.preview_win.focus_set()

    def update_preview_image(self):
        if self.page_images:
            img = self.page_images[self.current_page_index]
            img_resized = img.resize((680, 640), Image.Resampling.LANCZOS)
            self.tk_img = ImageTk.PhotoImage(img_resized)
            if self.image_on_canvas:
                self.canvas.itemconfig(self.image_on_canvas, image=self.tk_img)
            else:
                self.image_on_canvas = self.canvas.create_image(0, 0, anchor='nw', image=self.tk_img)

            current = self.current_page_index + 1
            total = len(self.page_images)
            self.page_label.config(text=f"Page {current} of {total}")

    def show_next_page(self):
        if self.current_page_index < len(self.page_images) - 1:
            self.current_page_index += 1
            self.update_preview_image()

    def show_previous_page(self):
        if self.current_page_index > 0:
            self.current_page_index -= 1
            self.update_preview_image()

    def save_selected_pages(self):
        try:
            output_base_name = self.output_file_var.get().strip()
            page_range = self.page_range_var.get().strip()

            if not output_base_name:
                messagebox.showerror("Error", "Please enter output file name like QH/QM-0000.")
                return
            if not page_range or '-' not in page_range:
                messagebox.showerror("Error", "Please enter valid page range like 1-4.")
                return
            if not self.pdf_reader:
                messagebox.showerror("Error", "Please select a PDF file first.")
                return
            if not self.output_path:
                self.output_path = filedialog.askdirectory()
                if not self.output_path:
                    messagebox.showerror("Error", "No output directory selected.")
                    return

            start_str, end_str = page_range.split('-')
            start_page = int(start_str)
            end_page = int(end_str)

            if start_page < 1 or end_page > len(self.pdf_reader.pages) or start_page > end_page:
                messagebox.showerror("Error", "Page range is invalid.")
                return

            output_filename = f"{output_base_name}.pdf"
            full_output_path = os.path.join(self.output_path, output_filename)

            pdf_writer = PyPDF2.PdfWriter()
            for page_num in range(start_page - 1, end_page):
                pdf_writer.add_page(self.pdf_reader.pages[page_num])

            with open(full_output_path, "wb") as output_file:
                pdf_writer.write(output_file)

            short_path = f"...{os.sep}" + os.path.basename(self.output_path)
            self.show_success_popup(output_filename, short_path)

            # Reset only page range input
            self.page_range_var.set("")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{e}")

    def show_success_popup(self, filename, short_path):
        popup = Toplevel(self.master)
        popup.title("Saved Successfully")
        popup.geometry("500x200")
        popup.configure(bg="white")

        Label(popup, text="File Saved!", font=("Helvetica", 14, "bold"), fg="green", bg="white").pack(pady=10)
        Label(popup, text=filename, font=("Helvetica", 18, "bold"), fg="black", bg="white").pack(pady=5)
        Label(popup, text=f"Saved to: {short_path}", font=("Helvetica", 10), wraplength=460, bg="white").pack(pady=5)

        Button(popup, text="OK", command=popup.destroy).pack(pady=10)
        popup.after(5000, popup.destroy)

    def exit_app(self):
        self.master.quit()


def main():
    root = Tk()
    app = PDFSplitter(root)
    root.mainloop()


if __name__ == "__main__":
    main()