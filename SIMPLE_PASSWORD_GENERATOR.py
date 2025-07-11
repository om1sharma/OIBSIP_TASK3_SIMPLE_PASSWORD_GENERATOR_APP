import tkinter as tk
import random

lowercase = list('abcdefghijklmnopqrstuvwxyz')
uppercase = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
digits = list('0123456789')
symbols = ['!', '@', '#', '*', '|', '$', '%', '&']
all_chars = lowercase + uppercase + digits + symbols

def generate_password():
    user_input = length_entry.get()
    if not user_input.isdigit():
        result_box.delete(0, tk.END)
        result_box.insert(0, "Enter a valid number!")
        result_box.config(width=32) 
        return

    length = int(user_input)
    if length < 8:
        result_box.delete(0, tk.END)
        result_box.insert(0, "Length must be at least 8.")
        result_box.config(width=32)
        return
    if length > 32:
        result_box.delete(0, tk.END)
        result_box.insert(0, "Max length is 32.")
        result_box.config(width=32)
        return
    if length >= 8 and length <= 32:
       result_box.config(width=length + 8)
    password = ''.join(random.choice(all_chars) for _ in range(length))
    result_box.delete(0, tk.END)
    result_box.insert(0, password)
    
def clear_entry(event):
    length_entry.delete(0, tk.END)

root = tk.Tk()
root.title("Password Generator")
root.geometry("400x250")
root.configure(bg="#9b59b6")  

tk.Label(root, text="Password Generator", font=("Arial", 18, "bold"), bg="#9b59b6", fg="white").pack(pady=10)

tk.Label(root, text="Password Length:", font=("Arial", 12), bg="#9b59b6", fg="white").pack()

length_entry = tk.Entry(root, font=("Arial", 12), justify='center')
length_entry.insert(0, "Enter length (min 8)")
length_entry.bind("<FocusIn>", clear_entry)
length_entry.pack(pady=5)

tk.Button(root, text="Generate", command=generate_password, font=("Arial", 12),
          bg="#6a0dad", fg="white", activebackground="#4b0082").pack(pady=10)

result_box = tk.Entry(root, font=("Arial", 12), justify='center')
result_box.pack(pady=10)

root.mainloop()
