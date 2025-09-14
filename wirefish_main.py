import tkinter as tk
from tkinter import ttk
from scapy.all import sniff

def mostrar_paquete(pkt):
    if pkt.haslayer("IP"):
        ip = pkt["IP"]
        texto = f"{ip.src} → {ip.dst} | Protocolo: {ip.proto} | Tamaño: {len(pkt)} bytes"
        lista_paquetes.insert(tk.END, texto)


def iniciar_captura():
    lista_paquetes.delete(0, tk.END)  
    sniff(count=10, prn=mostrar_paquete)


ventana = tk.Tk()
ventana.title("WireFish - Sniffer básico")
ventana.geometry("600x400")


titulo = ttk.Label(ventana, text="MiniSniffer / WireFish", font=("Arial", 16))
titulo.pack(pady=10)


lista_paquetes = tk.Listbox(ventana, width=80, height=15)
lista_paquetes.pack(pady=10)

# Botón para iniciar la captura
boton_captura = ttk.Button(ventana, text="Iniciar captura", command=iniciar_captura)
boton_captura.pack(pady=10)

# Ejecutar la interfaz
ventana.mainloop()
