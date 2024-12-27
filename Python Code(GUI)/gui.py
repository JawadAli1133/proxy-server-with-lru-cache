import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import threading
import pyshark
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from tkinter import colorchooser


capture_flag = False
web_packets_count = 0
proxy_packets_count = 0
proxy_port = None
LIGHT_BACKGROUND = "#ffffff"
DARK_BACKGROUND = "#2e2e2e"
packets_data = []


def start_proxy_server():
    def run_server():
        import subprocess
        global proxy_port
        try:
            proxy_port = port_entry.get()
            if not str(proxy_port).isdigit():
                raise ValueError("Port must be a valid number.")
            subprocess.run(["./proxy", str(proxy_port)], check=True)
            messagebox.showinfo("Success", f"Proxy Server Started on Port {proxy_port}!")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Proxy Server.\n{e}")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

def insert_packet_data(packet_data):
    packet_list.insert("", "end", values=packet_data)

def capture_packets():
    global proxy_packets_count
    global web_packets_count
    global packets_data


    global capture_flag
    capture_flag = True

    try:
        capture = pyshark.LiveCapture(interface="wlp2s0")

        for packet in capture.sniff_continuously():
            if not capture_flag:
                capture.close()
                break

            try:
                if hasattr(packet, 'ip'):
                    src_addr = packet.ip.src
                    dst_addr = packet.ip.dst
                    protocol = packet.highest_layer
                    length = packet.length
                    timestamp = packet.sniff_time.strftime("%H:%M:%S")

                    if hasattr(packet, 'tcp'):
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                    else:
                        continue

                    packet_type = "None"

                    if hasattr(packet, 'http'):
                        print("A")
                        http_version = packet.http.get('version', 'N/A')
                        if http_version in ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']:
                            print("B")
                            packet_type = "Proxy"
                            proxy_packets_count += 1
                    elif dst_port in ["80", "443"] or src_port in ["80", "443"]:
                        packet_type = "Web"
                        web_packets_count += 1

                    if src_addr == "127.0.0.1" or dst_addr == "127.0.0.1":
                        packet_type = "Proxy"
                        proxy_packets_count += 1
                    if packet_type in ["Web", "Proxy"]:
                        packet_data = (
                            timestamp, src_addr, dst_addr, src_port, dst_port, protocol, length, packet_type)
                        packets_data.append(packet_data)
                        app.after(0, insert_packet_data, packet_data)

            except Exception as e:
                print(f"Error processing packet: {e}")

    except Exception as e:
        print(f"Error in packet capture: {e}")

def start_packet_capture():
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

def stop_packet_capture():
    global capture_flag
    capture_flag = False
    messagebox.showinfo("Capture Stopped", "Packet capture has been stopped.")

def filter_packets():
    global packets_data
    selected_column = column_combobox.get()
    filter_value = filter_entry.get()

    filtered_packets = []
    col_index = column_combobox.current()

    if col_index == 0:  # Timestamp
        filtered_packets = [packet for packet in packets_data if filter_value in packet[0]]
    elif col_index == 1:  # Source Address
        filtered_packets = [packet for packet in packets_data if filter_value in packet[1]]
    elif col_index == 2:  # Destination Address
        filtered_packets = [packet for packet in packets_data if filter_value in packet[2]]
    elif col_index == 3:  # Source Port
        filtered_packets = [packet for packet in packets_data if filter_value in packet[3]]
    elif col_index == 4:  # Destination Port
        filtered_packets = [packet for packet in packets_data if filter_value in packet[4]]
    elif col_index == 5:  # Protocol
        filtered_packets = [packet for packet in packets_data if filter_value in packet[5]]
    elif col_index == 6:  # Length
        filtered_packets = [packet for packet in packets_data if filter_value in packet[6]]

    for row in packet_list.get_children():
        packet_list.delete(row)

    for packet in filtered_packets:
        packet_list.insert("", "end", values=packet)

def refresh_packets():
    global packets_data
    for row in packet_list.get_children():
        packet_list.delete(row)

    for packet in packets_data:
        packet_list.insert("", "end", values=packet)

def exit_fullscreen(event=None):
    app.attributes("-fullscreen", False)

app = ttk.Window(themename="flatly")
app.title("Proxy Server Control Panel")
app.geometry("1500x800+100+100")
app.bind("<Escape>", exit_fullscreen)

style = ttk.Style()

style.configure("TNotebook", background="#ffffff", padding=5)
style.configure(
    "TNotebook.Tab",
    padding=[10, 5],
    font=("Helvetica", 12),
    background="#f0f0f0",
    foreground="black",
    relief="flat"
)

style.map(
    "TNotebook.Tab",
    background=[("selected", "#4CAF50")],
    foreground=[("selected", "white")]
)

style.configure("TNotebook", tabposition="nw")

title_label = ttk.Label(
    app,
    text="Proxy Server Using LRU Cache",
    font=("Arial", 24, "bold"),
    anchor="center",
    background=style.lookup("TLabel", "background"),  # Set initial background for light theme
)
title_label.pack(pady=20)

notebook = ttk.Notebook(app)
notebook.pack(pady=10, expand=True, fill="both")

main_app_frame = ttk.Frame(notebook)
packets_frame = ttk.Frame(notebook)
settings_frame = ttk.Frame(notebook)
visualize_packets_frame = ttk.Frame(notebook)

notebook.add(main_app_frame, text="Web Server")
notebook.add(packets_frame, text="Packets Visualization")
notebook.add(visualize_packets_frame, text="Visualize Packets")
notebook.add(settings_frame, text="Settings")



def visualize_packets():
    fig, ax = plt.subplots(figsize=(6, 4))

    # Function to update the plot
    def update(frame):
        ax.clear()  # Clear the previous plot
        categories = ['Web Packets', 'Proxy Packets']
        counts = [web_packets_count, proxy_packets_count]
        ax.bar(categories, counts, color=['#4CAF50', '#FF5722'])
        ax.set_title('Packet Distribution', fontsize=16)
        ax.set_xlabel('Packet Categories', fontsize=12)
        ax.set_ylabel('Number of Packets', fontsize=12)

    ani = FuncAnimation(fig, update, interval=1000)

    canvas = FigureCanvasTkAgg(fig, master=visualize_packets_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

def on_tab_changed(event):
    selected_tab = notebook.index(notebook.select())
    if selected_tab == 0:
        show_main_app_content()
    elif selected_tab == 1:
        show_packets_content()
    elif selected_tab == 2:
        show_visualize_packets_content()
    elif selected_tab == 3:
        show_settings_content()

notebook.bind("<<NotebookTabChanged>>", on_tab_changed)


def toggle_light_dark_mode():
    current_theme = style.theme_use()  # Get the current theme
    new_theme = 'darkly' if current_theme == 'flatly' else 'flatly'  # Toggle between themes
    style.theme_use(new_theme)  # Apply the new theme

    # Update the title label background based on the new theme's background color
    new_background = style.lookup("TLabel", "background")  # Get the new background color
    title_label.configure(background=new_background)

def change_background_color():
    print("Change Background Color clicked")  # Debugging line
    color = colorchooser.askcolor()[1]  # Get the color in hex format
    if color:
        app.configure(bg=color)  # Change the background color of the main app window
        for widget in app.winfo_children():
            widget.configure(bg=color)
    new_background = style.lookup("TLabel", "background")  # Get the new background color
    title_label.configure(background=new_background)

def reset_settings():
    print("Reset Settings clicked")  # Debugging line
    app.configure(bg="white")  # Reset background color to white
    style.theme_use('flatly')
    new_background = style.lookup("TLabel", "background")
    title_label.configure(background=new_background)


def show_main_app_content():
    for widget in settings_frame.winfo_children():
        widget.destroy()
    global port_entry

    content_frame = ttk.Frame(main_app_frame, width=400, height=400)
    content_frame.place(relx=0.5, rely=0.5, anchor="center")
    content_frame.configure(style="TFrame")

    server_label = ttk.Label(content_frame, text="Web Server", font=("Helvetica", 25,), anchor='n')
    server_label.pack(pady=10)

    port_label = ttk.Label(content_frame, text="Enter Port Number:", font=("Helvetica", 12))
    port_label.pack(pady=10)

    port_entry = ttk.Entry(content_frame, bootstyle="info", width=20)
    port_entry.pack(pady=5)
    port_entry.insert(0, "5674")

    start_btn = ttk.Button(content_frame, text="Start Proxy Server", command=start_proxy_server, bootstyle=SUCCESS)
    start_btn.pack(pady=10)

    exit_btn = ttk.Button(content_frame, text="Exit", command=app.quit, bootstyle=SECONDARY)
    exit_btn.pack(pady=10)


def show_packets_content():
    global packet_list, column_combobox, filter_entry

    if 'packet_list' not in globals():
        packets_label = ttk.Label(packets_frame, text="Packets Visualization", font=("Helvetica", 18), anchor=CENTER)
        packets_label.pack(pady=10)

        filter_frame = ttk.Frame(packets_frame)
        filter_frame.pack(pady=10)

        filter_label = ttk.Label(filter_frame, text="Select Column to Filter:", font=("Helvetica", 12))
        filter_label.pack(side= LEFT, padx=5)

        columns = (
            "Timestamp", "Source Address", "Destination Address", "Source Port", "Destination Port", "Protocol", "Length", "Packet Type")
        column_combobox = ttk.Combobox(filter_frame, values=columns, state="readonly", bootstyle="info")
        column_combobox.pack(side=LEFT, padx=5)
        column_combobox.set(columns[0])

        filter_entry = ttk.Entry(filter_frame, bootstyle="info", width=20)
        filter_entry.pack(side=LEFT, padx=5)

        filter_btn = ttk.Button(filter_frame, text="Filter", command=filter_packets, bootstyle=SUCCESS)
        filter_btn.pack(side=LEFT, padx=5)

        refresh_btn = ttk.Button(packets_frame, text="Refresh", command=refresh_packets, bootstyle=INFO)
        refresh_btn.pack(pady=10)

        columns = (
            "Timestamp", "Source Address", "Destination Address", "Source Port", "Destination Port", "Protocol", "Length", "Packet Type")
        packet_list = ttk.Treeview(packets_frame, columns=columns, show="headings", bootstyle=INFO)

        for col in columns:
            packet_list.heading(col, text=col)
            packet_list.column(col, width=150, anchor="center")

        packet_list.pack(fill="both", expand=True, pady=10)

        capture_buttons_frame = ttk.Frame(packets_frame)
        capture_buttons_frame.pack(pady=10, side=BOTTOM)

        start_capture_btn = ttk.Button(capture_buttons_frame, text="Start Capture", command=start_packet_capture,
                                       bootstyle=SUCCESS)
        start_capture_btn.pack(side=LEFT, padx=10)

        stop_capture_btn = ttk.Button(capture_buttons_frame, text="Stop Capture", command=stop_packet_capture,
                                      bootstyle=DANGER)
        stop_capture_btn.pack(side=LEFT, padx=10)
    else:
        refresh_packets()

def show_settings_content():
    for widget in settings_frame.winfo_children():
        widget.destroy()
    settings_label = ttk.Label(settings_frame, text="Settings", font=("Helvetica", 18), anchor=CENTER)
    settings_label.pack(pady=20)

    # Button to toggle between light and dark mode
    toggle_mode_button = ttk.Button(settings_frame, text="Toggle Light/Dark Mode", command=toggle_light_dark_mode,
                                    bootstyle=INFO)
    toggle_mode_button.pack(pady=10)

    # Button to change background color
    change_bg_button = ttk.Button(settings_frame, text="Change Background Color", command=change_background_color,
                                  bootstyle=INFO)
    change_bg_button.pack(pady=10)

    # Reset settings button
    reset_settings_button = ttk.Button(settings_frame, text="Reset Settings", command=reset_settings, bootstyle=INFO)
    reset_settings_button.pack(pady=10)

def show_visualize_packets_content():
    visualize_packets()

show_main_app_content()

app.mainloop()