import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import sqlite3
from collections import Counter

# Veritabanı bağlantısı ve tablo oluşturma
conn = sqlite3.connect('user.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')
conn.commit()


def word_frequency_distance(text1, text2):
    words1 = text1.lower().split()
    words2 = text2.lower().split()
    freq1 = Counter(words1)
    freq2 = Counter(words2)
    all_words = set(freq1.keys()).union(set(freq2.keys()))
    distance = sum(abs(freq1[word] - freq2[word]) for word in all_words)
    total_word_count = sum(freq1.values()) + sum(freq2.values())
    normalized_distance = distance / total_word_count
    return 1 - (normalized_distance / 2)


def jaccard_similarity(text1, text2):
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    similarity = len(intersection) / len(union)
    return similarity


def login():
    username = entry_username.get()
    password = entry_password.get()
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    if c.fetchone():
        messagebox.showinfo("Login Success", "You have successfully logged in.")
        show_menu()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")


def register():
    username = entry_username.get()
    password = entry_password.get()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        messagebox.showinfo("Registration Success", "You have successfully registered.")
    except sqlite3.IntegrityError:
        messagebox.showerror("Registration Failed", "This username is already taken.")


def select_file(entry):
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filepath:
        entry.delete(0, tk.END)
        entry.insert(0, filepath)


def compare_texts(entry1, entry2, method):
    file1 = entry1.get()
    file2 = entry2.get()
    try:
        with open(file1, 'r', encoding='utf-8') as file:
            text1 = file.read()
        with open(file2, 'r', encoding='utf-8') as file:
            text2 = file.read()

        if method == "frequency":
            score = word_frequency_distance(text1, text2)
        elif method == "jaccard":
            score = jaccard_similarity(text1, text2)

        messagebox.showinfo("Comparison Result", f"{method.capitalize()} Similarity Score: {score:.2f}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def change_password():
    new_password = simpledialog.askstring("New Password", "Enter new password:", show='*')
    if new_password:
        username = entry_username.get()
        c.execute('UPDATE users SET password=? WHERE username=?', (new_password, username))
        conn.commit()
        messagebox.showinfo("Success", "Password changed successfully.")


def show_menu():
    menu_window = tk.Toplevel(root)
    menu_window.title("Main Menu")
    tk.Button(menu_window, text="Compare Texts", command=lambda: show_compare(menu_window)).pack()
    tk.Button(menu_window, text="Change Password", command=change_password).pack()
    tk.Button(menu_window, text="Exit", command=menu_window.destroy).pack()


def show_compare(parent):
    compare_window = tk.Toplevel(parent)
    compare_window.title("Text Comparison")
    tk.Label(compare_window, text="File 1:").pack()
    entry_file1 = tk.Entry(compare_window, width=50)
    entry_file1.pack()
    tk.Button(compare_window, text="Select File", command=lambda: select_file(entry_file1)).pack()

    tk.Label(compare_window, text="File 2:").pack()
    entry_file2 = tk.Entry(compare_window, width=50)
    entry_file2.pack()
    tk.Button(compare_window, text="Select File", command=lambda: select_file(entry_file2)).pack()

    method_var = tk.StringVar(value="frequency")
    tk.Radiobutton(compare_window, text="Frequency Distance", variable=method_var, value="frequency").pack()
    tk.Radiobutton(compare_window, text="Jaccard Similarity", variable=method_var, value="jaccard").pack()

    tk.Button(compare_window, text="Compare",
              command=lambda: compare_texts(entry_file1, entry_file2, method_var.get())).pack()


# Kullanıcı Arayüzü
root = tk.Tk()
root.title("User Login/Register")
tk.Label(root, text="Username:").pack()
entry_username = tk.Entry(root)
entry_username.pack()
tk.Label(root, text="Password:").pack()
entry_password = tk.Entry(root, show="*")
entry_password.pack()
tk.Button(root, text="Login", command=login).pack()
tk.Button(root, text="Register", command=register).pack()
root.mainloop()
