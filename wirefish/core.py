"""Captura, filtrado, parsing y almacenamiento de paquetes."""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from scapy.all import DNS, IP, Raw, TCP, UDP, get_if_list, sniff
from scapy.packet import Packet

logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = ("Todos", "TCP", "UDP", "DNS", "HTTP")


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Datos de presentación de un paquete y su payload original."""

    packet_id: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    size: int
    info: str
    payload: bytes


def _dns_name(packet: Packet) -> str:
    """Obtiene el nombre consultado en DNS, si está disponible."""
    dns = packet[DNS]
    question = dns.qd
    name = getattr(question, "qname", b"") if question else b""
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace").rstrip(".") or "N/A"
    return str(name).rstrip(".") or "N/A"


def _http_summary(payload: bytes) -> str | None:
    """Devuelve la primera línea de una solicitud/respuesta HTTP reconocible."""
    if not payload:
        return None
    first_line = payload.splitlines()[0].decode("ascii", errors="replace").strip()
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
    if first_line.startswith("HTTP/") or payload.startswith(methods):
        return first_line[:180]
    return None


def parse_packet(packet: Packet, packet_id: int = 0) -> PacketRecord | None:
    """Convierte un paquete IPv4 de Scapy en un registro listo para mostrar."""
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    protocol = f"IP({ip_layer.proto})"
    info = ""

    if packet.haslayer(DNS):
        dns = packet[DNS]
        direction = "QUERY" if dns.qr == 0 else "RESPONSE"
        protocol = "DNS"
        info = f"{direction}: {_dns_name(packet)}"
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol = "TCP"
        info = f"SrcPort:{tcp.sport} -> DstPort:{tcp.dport} [{tcp.flags}]"
        http_line = _http_summary(payload)
        if http_line is not None:
            protocol = "HTTP"
            info = http_line
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        protocol = "UDP"
        info = f"SrcPort:{udp.sport} -> DstPort:{udp.dport}"
    elif ip_layer.proto == 1:
        protocol = "ICMP"

    return PacketRecord(
        packet_id=packet_id,
        timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
        source=ip_layer.src,
        destination=ip_layer.dst,
        protocol=protocol,
        size=len(packet),
        info=info,
        payload=payload,
    )


class PacketSniffer:
    """Gestiona la captura en un hilo de trabajo y cachea registros aceptados."""

    def __init__(self, cache_size: int = 1000) -> None:
        if cache_size < 1:
            raise ValueError("cache_size debe ser mayor que cero.")
        self._cache: OrderedDict[int, PacketRecord] = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._next_packet_id = 1
        self._captured_count = 0
        self._max_packets = 0
        self._ip_filter = ""
        self._protocol_filter = "Todos"
        self._interface: str | None = None
        self._on_packet: Callable[[PacketRecord], None] | None = None
        self._on_error: Callable[[Exception], None] | None = None

    @staticmethod
    def interfaces() -> list[str]:
        """Devuelve los nombres de interfaces visibles para Scapy."""
        return sorted(get_if_list(), key=str.casefold)

    @property
    def is_running(self) -> bool:
        """Indica si el hilo de captura está ejecutándose."""
        with self._lock:
            return self._running

    def start(
        self,
        on_packet: Callable[[PacketRecord], None],
        on_error: Callable[[Exception], None],
        *,
        ip_filter: str = "",
        protocol_filter: str = "Todos",
        max_packets: int = 100,
        interface: str | None = None,
    ) -> None:
        """Valida opciones y comienza la captura en un hilo separado."""
        if ip_filter:
            ipaddress.IPv4Address(ip_filter)
        if protocol_filter not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"Protocolo no soportado: {protocol_filter}")
        if max_packets < 1:
            raise ValueError("El límite de paquetes debe ser mayor que cero.")

        with self._lock:
            if self._running:
                raise RuntimeError("Ya hay una captura en curso.")
            self._stop_event.clear()
            self._captured_count = 0
            self._max_packets = max_packets
            self._ip_filter = ip_filter
            self._protocol_filter = protocol_filter
            self._interface = interface
            self._on_packet = on_packet
            self._on_error = on_error
            self._running = True
            self._thread = threading.Thread(
                target=self._capture_loop,
                name="wirefish-capture",
                daemon=True,
            )
            try:
                self._thread.start()
            except RuntimeError:
                self._running = False
                self._thread = None
                raise

    def stop(self) -> None:
        """Solicita detener la captura sin bloquear la interfaz gráfica."""
        self._stop_event.set()

    def clear_cache(self) -> None:
        """Elimina los registros conservados para la vista de detalles."""
        with self._lock:
            self._cache.clear()

    def get_record(self, packet_id: int) -> PacketRecord | None:
        """Busca un registro cacheado mediante su identificador estable."""
        with self._lock:
            return self._cache.get(packet_id)

    def _capture_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                sniff(
                    prn=self._process_packet,
                    store=False,
                    timeout=0.5,
                    iface=self._interface,
                )
        except PermissionError as error:
            self._report_error(
                PermissionError(
                    "No hay permisos para capturar paquetes. "
                    "Ejecuta WireFish como administrador/root."
                )
            )
            logger.exception("Permiso denegado al capturar paquetes")
        except OSError as error:
            self._report_error(
                OSError(
                    f"No se pudo abrir la interfaz de captura. "
                    f"Comprueba Npcap/permisos e interfaz seleccionada: {error}"
                )
            )
            logger.exception("Error de sistema al iniciar la captura")
        except Exception as error:
            self._report_error(error)
            logger.exception("Error inesperado durante la captura")
        finally:
            with self._lock:
                self._running = False

    def _process_packet(self, packet: Packet) -> None:
        record = parse_packet(packet)
        if record is None:
            return
        if self._ip_filter and self._ip_filter not in (
            record.source,
            record.destination,
        ):
            return
        if self._protocol_filter != "Todos" and record.protocol != self._protocol_filter:
            return

        with self._lock:
            if self._stop_event.is_set() or self._captured_count >= self._max_packets:
                return
            record = PacketRecord(
                packet_id=self._next_packet_id,
                timestamp=record.timestamp,
                source=record.source,
                destination=record.destination,
                protocol=record.protocol,
                size=record.size,
                info=record.info,
                payload=record.payload,
            )
            self._next_packet_id += 1
            self._captured_count += 1
            self._cache[record.packet_id] = record
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
            on_packet = self._on_packet
            if self._captured_count >= self._max_packets:
                self._stop_event.set()

        if on_packet is not None:
            on_packet(record)

    def _report_error(self, error: Exception) -> None:
        callback = self._on_error
        if callback is not None:
            callback(error)
