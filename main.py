"""Punto de entrada de la aplicación WireFish."""

from wirefish.ui import WireFishApp
from wirefish.utils import configure_logging


def main() -> None:
    """Inicializa logging y ejecuta la interfaz."""
    configure_logging()
    WireFishApp().run()


if __name__ == "__main__":
    main()