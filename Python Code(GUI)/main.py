import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import threading
import pyshark


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


def capture_packets():
    try:
        capture = pyshark.LiveCapture(interface="wlp2s0")
        for packet in capture.sniff_continuously():
            try:
                src_addr = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dst_addr = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else "N/A"
                length = packet.length if hasattr(packet, 'length') else "N/A"
                timestamp = packet.sniff_time.strftime("%H:%M:%S") if hasattr(packet, 'sniff_time') else "N/A"

                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
                else:
                    src_port = "N/A"
                    dst_port = "N/A"

                if "N/A" in [src_addr, dst_addr, protocol, length, timestamp, src_port, dst_port]:
                    continue

                packet_list.insert("", "end", values=(timestamp, src_addr, dst_addr, src_port, dst_port, protocol, length))
            except Exception as e:
                print(f"Error processing packet: {e}")

    except Exception as e:
        print(f"Error in packet capture: {e}")



def start_packet_capture():
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()


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

notebook.add(main_app_frame, text="Web Server")
notebook.add(packets_frame, text="Packets Visualization")
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

def on_tab_changed(event):
    selected_tab = notebook.index(notebook.select())
    if selected_tab == 0:
        show_main_app_content()
    elif selected_tab == 1:
        show_packets_content()
    elif selected_tab == 2:
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
    global packet_list
    for widget in packets_frame.winfo_children():
        widget.destroy()

    packets_label = ttk.Label(packets_frame, text="Packets Visualization", font=("Helvetica", 18), anchor=CENTER)
    packets_label.pack(pady=10)

    columns = (
    "Timestamp", "Source Address", "Destination Address", "Source Port", "Destination Port", "Protocol", "Length")
    packet_list = ttk.Treeview(packets_frame, columns=columns, show="headings", bootstyle=INFO)

    for col in columns:
        packet_list.heading(col, text=col)
        packet_list.column(col, width=150, anchor="center")

    packet_list.pack(fill="both", expand=True, pady=10)

    start_btn = ttk.Button(packets_frame, text="Start Capture", command=start_packet_capture, bootstyle=SUCCESS)
    start_btn.pack(pady=10)

def show_settings_content():
    for widget in settings_frame.winfo_children():
        widget.destroy()

    settings_label = ttk.Label(settings_frame, text="Settings", font=("Helvetica", 18), anchor=CENTER)
    settings_label.pack(pady=20)

show_main_app_content()

app.mainloop()