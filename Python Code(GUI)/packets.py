import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import threading
import pyshark
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# Global flag to control packet capture
capture_flag = False

web_packets_count = 0
proxy_packets_count = 0
timestamps = []
web_packet_counts = []
proxy_packet_counts = []

def start_proxy_server():
    def run_server():
        import subprocess
        try:
            port = port_entry.get()
            if not str(port).isdigit():
                raise ValueError("Port must be a valid number.")
            subprocess.run(["./proxy", str(port)], check=True)
            messagebox.showinfo("Success", f"Proxy Server Started on Port {port}!")
        except ValueError as ve:
            messagebox.showerror("Invalid Input", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Proxy Server.\n{e}")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()


def insert_packet_data(packet_data):
    packet_list.insert("", "end", values=packet_data)


def capture_packets():
    global web_packets_count
    global proxy_packets_count
    global packets_data
    packets_data = []

    # Check if capture_flag is set to True, and then start capturing packets
    global capture_flag
    capture_flag = True

    try:
        capture = pyshark.LiveCapture(interface="wlp2s0")
        for packet in capture.sniff_continuously():
            if not capture_flag:  # Check the capture_flag to stop
                capture.close()
                break

            try:
                # Check if the packet has an IP layer
                if hasattr(packet, 'ip'):
                    src_addr = packet.ip.src
                    dst_addr = packet.ip.dst
                    protocol = packet.highest_layer
                    length = packet.length
                    timestamp = packet.sniff_time.strftime("%H:%M:%S")

                    # Extract ports based on the protocol
                    if hasattr(packet, 'tcp'):
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                    elif hasattr(packet, 'udp'):
                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport
                    else:
                        src_port = "N/A"
                        dst_port = "N/A"

                    # Differentiate based on protocol or destination port
                    if dst_port == "80" or dst_port == "443" or protocol == "HTTP" or protocol == "HTTPS":
                        # Web packet
                        packet_type = "Web"
                        web_packets_count += 1
                    elif dst_port == "8080" or dst_port == "3128":
                        # Proxy packet
                        packet_type = "Proxy"
                        proxy_packets_count += 1
                    else:
                        # Default to proxy if it's not clearly web-related
                        packet_type = "Proxy"
                        proxy_packets_count += 1

                    packet_data = (timestamp, src_addr, dst_addr, src_port, dst_port, protocol, length, packet_type)
                    packets_data.append(packet_data)

                    # Schedule the insert_packet_data method to be called in the main thread
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
    capture_flag = False  # Set the flag to False to stop the capture

    # Manually stop the capture by closing the capture session
    messagebox.showinfo("Capture Stopped", "Packet capture has been stopped.")


def filter_packets():
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
    for row in packet_list.get_children():
        packet_list.delete(row)

    for packet in packets_data:
        packet_list.insert("", "end", values=packet)


def exit_fullscreen(event=None):
    app.attributes("-fullscreen", False)


app = ttk.Window(themename="yeti")
app.title("Proxy Server Control Panel")
app.geometry("1500x800+100+100")
app.bind("<Escape>", exit_fullscreen)

title_label = ttk.Label(
    app,
    text="Proxy Server Using LRU Cache",
    font=("Arial", 24, "bold"),
    anchor="center",
    bootstyle="primary"
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


def visualize_packets():
    # Plot the comparison graph between web packets and proxy packets
    fig, ax = plt.subplots(figsize=(6, 4))

    # Assuming that the web and proxy counts are being updated correctly in real-time
    # You could maintain lists of the count of packets for each type over time
    # For simplicity, I'm using the total counts here, but you can update them over time as packets are captured
    time_stamps = [time.strftime("%H:%M:%S")]  # Example time, you'd collect this from packets
    web_counts = [web_packets_count]
    proxy_counts = [proxy_packets_count]

    ax.plot(time_stamps, web_counts, label="Web Packets", color='#4CAF50', marker='o', linestyle='-', linewidth=2)
    ax.plot(time_stamps, proxy_counts, label="Proxy Packets", color='#FF5722', marker='x', linestyle='-', linewidth=2)

    ax.set_title('Web vs Proxy Packets', fontsize=16)
    ax.set_xlabel('Time', fontsize=12)
    ax.set_ylabel('Packet Count', fontsize=12)

    ax.legend()

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


def show_main_app_content():
    global port_entry
    content_frame = ttk.Frame(main_app_frame, width=400, height=400)
    content_frame.place(relx=0.5, rely=0.5, anchor="center")
    content_frame.configure(style="TFrame")

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
    for widget in packets_frame.winfo_children():
        widget.destroy()

    packets_label = ttk.Label(packets_frame, text="Packets Visualization", font=("Helvetica", 18), anchor=CENTER)
    packets_label.pack(pady=10)

    # Filter Controls (Above the table)
    filter_frame = ttk.Frame(packets_frame)
    filter_frame.pack(pady=10)

    filter_label = ttk.Label(filter_frame, text="Select Column to Filter:", font=("Helvetica", 12))
    filter_label.pack(side=LEFT, padx=5)

    columns = (
        "Timestamp", "Source Address", "Destination Address", "Source Port", "Destination Port", "Protocol", "Length")
    column_combobox = ttk.Combobox(filter_frame, values=columns, state="readonly", bootstyle="info")
    column_combobox.pack(side=LEFT, padx=5)
    column_combobox.set(columns[0])

    filter_entry = ttk.Entry(filter_frame, bootstyle="info", width=20)
    filter_entry.pack(side=LEFT, padx=5)

    filter_btn = ttk.Button(filter_frame, text="Filter", command=filter_packets, bootstyle=SUCCESS)
    filter_btn.pack(side=LEFT, padx=5)

    refresh_btn = ttk.Button(packets_frame, text="Refresh", command=refresh_packets, bootstyle=INFO)
    refresh_btn.pack(pady=10)

    # Packets Table
    columns = (
        "Timestamp", "Source Address", "Destination Address", "Source Port", "Destination Port", "Protocol", "Length")
    packet_list = ttk.Treeview(packets_frame, columns=columns, show="headings", bootstyle=INFO)

    for col in columns:
        packet_list.heading(col, text=col)
        packet_list.column(col, width=150, anchor="center")

    packet_list.pack(fill="both", expand=True, pady=10)

    # Start / Stop Capture Buttons (At the Bottom)
    capture_buttons_frame = ttk.Frame(packets_frame)
    capture_buttons_frame.pack(pady=10, side=BOTTOM)

    start_capture_btn = ttk.Button(capture_buttons_frame, text="Start Capture", command=start_packet_capture,
                                   bootstyle=SUCCESS)
    start_capture_btn.pack(side=LEFT, padx=10)

    stop_capture_btn = ttk.Button(capture_buttons_frame, text="Stop Capture", command=stop_packet_capture,
                                  bootstyle=DANGER)
    stop_capture_btn.pack(side=LEFT, padx=10)


def show_settings_content():
    for widget in settings_frame.winfo_children():
        widget.destroy()

    settings_label = ttk.Label(settings_frame, text="Settings", font=("Helvetica", 18), anchor=CENTER)
    settings_label.pack(pady=20)

def show_visualize_packets_content():
    global visualize_packets_frame
    for widget in visualize_packets_frame.winfo_children():
        widget.destroy()

    visualize_packets_button = ttk.Button(visualize_packets_frame, text="Visualize Packets", command=visualize_packets, bootstyle=INFO)
    visualize_packets_button.pack(pady=10)

show_main_app_content()

app.mainloop()
