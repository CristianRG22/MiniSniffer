"""Interfaz Tkinter para WireFish; no contiene lógica de captura."""

from __future__ import annotations

import logging
import queue
import tkinter as tk
from tkinter import messagebox, ttk

from wirefish.core import SUPPORTED_PROTOCOLS, PacketRecord, PacketSniffer
from wirefish.utils import decode_payload

logger = logging.getLogger(__name__)
MAX_DISPLAYED_PACKETS = 10_000


class WireFishApp:
    """Construye y coordina la interfaz gráfica de WireFish."""

    def __init__(self, root: tk.Tk | None = None) -> None:
        self.root = root if root is not None else tk.Tk()
        self.sniffer = PacketSniffer(cache_size=MAX_DISPLAYED_PACKETS)
        self._events: queue.Queue[PacketRecord | Exception] = queue.Queue()
        self._closing = False

        self.root.title("WireFish - Network Analyzer")
        self.root.geometry("1100x650")
        self.root.minsize(800, 450)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.ip_filter = tk.StringVar()
        self.protocol_filter = tk.StringVar(value="Todos")
        self.max_packets = tk.IntVar(value=100)
        self.interface = tk.StringVar(value="Predeterminada")
        self.status = tk.StringVar(value="Estado: Detenido")

        self._configure_styles()
        self._create_widgets()
        self.root.after(100, self._process_events)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.configure("Header.TLabel", font=("Consolas", 14, "bold"))
        style.configure("Status.TLabel", font=("Arial", 10), foreground="gray")

    def _create_widgets(self) -> None:
        filters = ttk.LabelFrame(self.root, text="Filtros de captura", padding=10)
        filters.pack(fill=tk.X, padx=10, pady=6)

        ttk.Label(filters, text="IP origen/destino:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(filters, textvariable=self.ip_filter, width=18)
        self.ip_entry.grid(row=0, column=1, padx=5)

        ttk.Label(filters, text="Protocolo:").grid(
            row=0, column=2, sticky=tk.W, padx=(10, 0)
        )
        self.protocol_combo = ttk.Combobox(
            filters,
            textvariable=self.protocol_filter,
            values=SUPPORTED_PROTOCOLS,
            state="readonly",
            width=10,
        )
        self.protocol_combo.grid(row=0, column=3, padx=5)

        ttk.Label(filters, text="Máx. paquetes:").grid(
            row=0, column=4, sticky=tk.W, padx=(10, 0)
        )
        self.max_spinbox = ttk.Spinbox(
            filters, from_=1, to=10000, textvariable=self.max_packets, width=8
        )
        self.max_spinbox.grid(row=0, column=5, padx=5)

        ttk.Label(filters, text="Interfaz:").grid(
            row=0, column=6, sticky=tk.W, padx=(10, 0)
        )
        self.interface_combo = ttk.Combobox(
            filters,
            textvariable=self.interface,
            values=self._interface_choices(),
            state="readonly",
            width=27,
        )
        self.interface_combo.grid(row=0, column=7, padx=5)
        filters.columnconfigure(7, weight=1)

        controls = ttk.Frame(self.root)
        controls.pack(fill=tk.X, padx=10, pady=4)
        self.start_button = ttk.Button(
            controls, text="Iniciar captura", command=self._toggle_capture
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = ttk.Button(
            controls, text="Limpiar", command=self._clear_packets
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        ttk.Label(controls, textvariable=self.status, style="Status.TLabel").pack(
            side=tk.RIGHT, padx=5
        )

        columns = (
            "number",
            "timestamp",
            "source",
            "destination",
            "protocol",
            "size",
            "info",
        )
        self.tree = ttk.Treeview(
            self.root, columns=columns, show="headings", height=20, selectmode="browse"
        )
        headings = {
            "number": ("N.º", 55),
            "timestamp": ("Hora", 95),
            "source": ("Origen", 150),
            "destination": ("Destino", 150),
            "protocol": ("Protocolo", 85),
            "size": ("Tamaño", 75),
            "info": ("Información", 450),
        }
        for column, (title, width) in headings.items():
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=55, stretch=column == "info")

        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=(4, 10)
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=(4, 10))
        self.tree.bind("<Double-1>", self._show_details)

    def _interface_choices(self) -> tuple[str, ...]:
        try:
            return ("Predeterminada", *self.sniffer.interfaces())
        except Exception:
            logger.exception("No se pudo consultar la lista de interfaces")
            return ("Predeterminada",)

    def _toggle_capture(self) -> None:
        if self.sniffer.is_running:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self) -> None:
        try:
            limit = self.max_packets.get()
            selected_interface = self.interface.get()
            self.sniffer.start(
                self._events.put,
                self._events.put,
                ip_filter=self.ip_filter.get().strip(),
                protocol_filter=self.protocol_filter.get(),
                max_packets=limit,
                interface=(
                    None if selected_interface == "Predeterminada" else selected_interface
                ),
            )
        except (ValueError, RuntimeError, tk.TclError) as error:
            messagebox.showerror("No se pudo iniciar la captura", str(error), parent=self.root)
            return

        self._set_capturing_ui(True)

    def _stop_capture(self) -> None:
        self.sniffer.stop()
        self.start_button.configure(text="Deteniendo...", state=tk.DISABLED)
        self.status.set("Estado: Deteniendo...")

    def _set_capturing_ui(self, capturing: bool) -> None:
        if capturing:
            self.start_button.configure(text="Detener captura", state=tk.NORMAL)
            self.status.set("Estado: Capturando...")
            self._set_filter_controls(tk.DISABLED)
        else:
            self.start_button.configure(text="Iniciar captura", state=tk.NORMAL)
            self.status.set("Estado: Detenido")
            self._set_filter_controls(tk.NORMAL)

    def _set_filter_controls(self, state: str) -> None:
        self.ip_entry.configure(state=state)
        self.protocol_combo.configure(state="readonly" if state == tk.NORMAL else state)
        self.max_spinbox.configure(state=state)
        self.interface_combo.configure(state="readonly" if state == tk.NORMAL else state)

    def _process_events(self) -> None:
        if self._closing:
            return
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            if isinstance(event, Exception):
                messagebox.showerror("Error de captura", str(event), parent=self.root)
            else:
                self._insert_record(event)

        if self.status.get() != "Estado: Detenido" and not self.sniffer.is_running:
            self._set_capturing_ui(False)
        self.root.after(100, self._process_events)

    def _insert_record(self, record: PacketRecord) -> None:
        if self.sniffer.get_record(record.packet_id) is None:
            return
        was_at_bottom = self.tree.yview()[1] >= 0.98
        children = self.tree.get_children()
        if len(children) >= MAX_DISPLAYED_PACKETS:
            self.tree.delete(children[0])
        self.tree.insert(
            "",
            tk.END,
            iid=f"packet-{record.packet_id}",
            values=(
                record.packet_id,
                record.timestamp,
                record.source,
                record.destination,
                record.protocol,
                record.size,
                record.info,
            ),
        )
        if was_at_bottom:
            self.tree.yview_moveto(1.0)

    def _clear_packets(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.sniffer.clear_cache()

    def _show_details(self, event: tk.Event[tk.Misc]) -> None:
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        selection = self.tree.selection()
        if not selection:
            return
        try:
            packet_id = int(selection[0].removeprefix("packet-"))
        except ValueError:
            logger.warning("Identificador de paquete no válido: %s", selection[0])
            return
        record = self.sniffer.get_record(packet_id)
        if record is None:
            messagebox.showwarning(
                "Paquete no disponible",
                "El registro ya no está en la caché. Limpia la lista o vuelve a capturarlo.",
                parent=self.root,
            )
            return

        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Detalles del paquete {packet_id}")
        detail_window.geometry("720x520")
        detail_window.transient(self.root)
        text = tk.Text(detail_window, wrap=tk.NONE, font=("Consolas", 10))
        vertical = ttk.Scrollbar(detail_window, orient=tk.VERTICAL, command=text.yview)
        horizontal = ttk.Scrollbar(
            detail_window, orient=tk.HORIZONTAL, command=text.xview
        )
        text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        text.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        detail_window.rowconfigure(0, weight=1)
        detail_window.columnconfigure(0, weight=1)
        details = (
            f"Número:     {record.packet_id}\n"
            f"Hora:       {record.timestamp}\n"
            f"Origen:     {record.source}\n"
            f"Destino:    {record.destination}\n"
            f"Protocolo:  {record.protocol}\n"
            f"Tamaño:     {record.size} bytes\n"
            f"Información:{' ' if record.info else ''}{record.info}\n\n"
            "PAYLOAD\n"
            "-------\n"
            f"{decode_payload(record.payload)}"
        )
        text.insert("1.0", details)
        text.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        self._closing = True
        self.sniffer.stop()
        self.root.destroy()

    def run(self) -> None:
        """Inicia el bucle de eventos de Tkinter."""
        self.root.mainloop()
