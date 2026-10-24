# WireFish

WireFish es un analizador de tráfico de red de escritorio escrito en Python. Captura paquetes IPv4 en tiempo real con Scapy y los presenta en una interfaz Tkinter, con filtros por dirección IP y protocolo, y una ventana de detalles para inspeccionar el payload.

## Características

- Captura en hilo separado para mantener la interfaz receptiva.
- Número secuencial por paquete, visible en la lista y en sus detalles.
- Filtros por IP de origen/destino y por TCP, UDP, DNS o HTTP.
- Reconocimiento de consultas/respuestas DNS y líneas HTTP visibles en TCP.
- Vista de detalles con payload decodificado o representado en hexadecimal si es binario.
- Caché de paquetes acotada y límite configurable de paquetes por captura.
- Autoscroll solo cuando la lista ya estaba posicionada al final.
- Selección de interfaz de red, incluida la posibilidad de elegir el adaptador loopback de Npcap en Windows.

> WireFish muestra los bytes disponibles en cada paquete capturado. No reensambla flujos TCP; por ello una petición HTTP fragmentada puede no reconocerse como HTTP.

## Requisitos

- Python 3.10 o posterior.
- Permisos del sistema operativo para capturar tráfico.
- En Windows, [Npcap](https://npcap.com/) instalado. Para tráfico loopback, instala Npcap con soporte de loopback y selecciona la interfaz `Npcap Loopback Adapter` (o su nombre equivalente) en la lista.

## Instalación

Desde la carpeta del proyecto, crea y activa un entorno virtual:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

En Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Uso

Inicia la aplicación:

```bash
python main.py
```

Indica opcionalmente una IP de origen/destino, el protocolo y el máximo de paquetes. Selecciona `Predeterminada` para dejar que Scapy use su interfaz predeterminada, o elige una interfaz concreta. Pulsa **Iniciar captura**; haz doble clic en una fila para ver sus detalles y payload. La captura termina al llegar al límite o al pulsar **Detener captura**.

En Windows, ejecuta la terminal con privilegios de administrador si la captura no tiene permisos. Para loopback, selecciona explícitamente el adaptador de Npcap correspondiente.

## Uso responsable

Captura únicamente tráfico propio o para el que tengas autorización. Los payloads pueden contener información privada o credenciales transmitidas sin cifrar; evita compartir capturas y cierra la aplicación cuando termines.

## Estructura

```text
wirefish/
├── __init__.py
├── core.py       # Captura, filtros, parsing y caché
├── ui.py         # Interfaz Tkinter y eventos
└── utils.py      # Decodificación y logging
main.py           # Punto de entrada
requirements.txt
README.md
.gitignore
```
