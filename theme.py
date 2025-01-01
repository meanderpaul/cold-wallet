import tkinter as tk
import ttkbootstrap as ttk

def main():
    root = ttk.Window()
    style = ttk.Style(root)
    available_themes = style.theme_names()
    print("Available themes:", available_themes)

    # Use the first available theme as default
    default_theme = available_themes[0] if available_themes else "default"
    style.theme_use(default_theme)

    label = ttk.Label(root, text="Hello, World!", bootstyle="primary")
    label.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main()
