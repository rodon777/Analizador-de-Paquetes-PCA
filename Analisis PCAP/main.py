import pyshark
import os
from colorama import Fore, Style, init
from datetime import datetime

# Inicializar colorama
init(autoreset=True)

# Carpeta de exportaciones
EXPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export")

# Función para limpiar comillas de la ruta
def limpiar_ruta(ruta):
    return ruta.strip('"').strip("'")

# Función para mostrar ayuda
def mostrar_ayuda():
    print("\nComandos disponibles:")
    print("  exit                 - Termina el programa")
    print("  -h                   - Muestra esta ayuda")
    print("  -pl [num]            - Mostrar payload del paquete [num]")
    print("  -hex [num]           - Mostrar payload en hexadecimal del paquete [num]")
    print("  -hdr [num]           - Mostrar encabezados completos del paquete [num]")
    print("  -src [num]           - Mostrar IP de origen del paquete [num]")
    print("  -dst [num]           - Mostrar IP de destino del paquete [num]")
    print("  -proto [num]         - Mostrar protocolo principal del paquete [num]")
    print("  -all [num]           - Mostrar resumen completo del paquete [num]")
    print("  -filter=[PROTOCOLO]  - Mostrar solo paquetes que contengan ese protocolo")
    print("  -time=[HH:MM:SS]-[HH:MM:SS] - Filtrar paquetes por rango de hora")
    print("  -count               - Mostrar total de paquetes cargados")
    print("  -export [archivo]    - Exportar la info de paquetes a un archivo de texto")
    print("  -clear               - Limpiar la pantalla\n")

# Función para obtener payload
def obtener_payload(packet):
    tcp_payload = getattr(packet.tcp, 'payload', None) if hasattr(packet, 'tcp') else None
    udp_payload = getattr(packet.udp, 'payload', None) if hasattr(packet, 'udp') else None
    return tcp_payload or udp_payload

# Mensaje inicial
print("Aviso: Ingresa '-h' en cualquier momento para mostrar los comandos disponibles.")

# Bucle para solicitar archivo PCAP
while True:
    archivo = input("Ingresa la ruta del archivo PCAP: ").strip()
    if archivo.lower() == "-h":
        mostrar_ayuda()
        continue
    elif archivo.lower() == "exit":
        print("Programa terminado por el usuario.")
        exit()

    archivo = limpiar_ruta(archivo)

    try:
        cap = list(pyshark.FileCapture(archivo))  # Carga completa para acceso aleatorio
        break
    except FileNotFoundError:
        print(f"No se encontró el archivo: {archivo}, intenta de nuevo.")
    except Exception as e:
        print(f"Error al abrir el archivo: {e}")

# Mostrar resumen de paquetes
print("\nResumen de paquetes:")
print(f"{'Num':<5} {'Hora':<12} {'Protocolo':<10} {'Origen':<15} {'Destino':<15} {'Payload':<7}")
for i, packet in enumerate(cap):
    protocolo = packet.highest_layer
    src = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
    dst = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
    hora = packet.sniff_time.time()
    tiene_payload = bool(obtener_payload(packet))
    payload_str = Fore.GREEN + "Si" + Style.RESET_ALL if tiene_payload else Fore.RED + "No" + Style.RESET_ALL
    print(f"{i:<5} {hora} {protocolo:<10} {src:<15} {dst:<15} {payload_str:<7}")

# Bucle interactivo de comandos
while True:
    comando_input = input("\nIngresa un comando: ").strip()
    if not comando_input:
        continue

    if comando_input.lower() == "exit":
        print("Programa terminado por el usuario.")
        break
    elif comando_input.lower() == "-h":
        mostrar_ayuda()
        continue

    partes = comando_input.split()
    num = None
    cmds = []
    export_file = None

    # Procesar argumentos
    i = 0
    while i < len(partes):
        p = partes[i]
        if p.lower() == "-export":
            if i + 1 < len(partes) and not partes[i + 1].startswith("-"):
                export_file = partes[i + 1]
                i += 1
            else:
                print(Fore.RED + "Debe especificar un nombre para el archivo de exportación.")
        else:
            try:
                num = int(p)
            except ValueError:
                cmds.append(p.lower())
        i += 1

    salida_export = []

    # Ejecutar comandos
    for cmd in cmds:
        texto_salida = ""

        if cmd == "-pl":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -pl"
            else:
                payload = obtener_payload(cap[num])
                texto_salida = f"Payload paquete {num}: {bytes.fromhex(payload.replace(':', '')) if payload else 'No encontrado'}"

        elif cmd == "-hex":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -hex"
            else:
                payload = obtener_payload(cap[num])
                texto_salida = f"Payload hexadecimal paquete {num}: {payload if payload else 'No encontrado'}"

        elif cmd == "-hdr":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -hdr"
            else:
                texto_salida = f"Encabezados completos del paquete {num}:\n{cap[num]}"

        elif cmd == "-src":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -src"
            else:
                src = cap[num].ip.src if hasattr(cap[num], 'ip') else 'N/A'
                texto_salida = f"IP origen del paquete {num}: {src}"

        elif cmd == "-dst":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -dst"
            else:
                dst = cap[num].ip.dst if hasattr(cap[num], 'ip') else 'N/A'
                texto_salida = f"IP destino del paquete {num}: {dst}"

        elif cmd == "-proto":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -proto"
            else:
                texto_salida = f"Protocolo principal del paquete {num}: {cap[num].highest_layer}"

        elif cmd == "-all":
            if num is None:
                texto_salida = "Debe especificar el número de paquete para -all"
            else:
                packet = cap[num]
                protocolo = packet.highest_layer
                src = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                dst = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                hora = packet.sniff_time.time()
                payload_str = "Si" if obtener_payload(packet) else "No"
                texto_salida = f"Paquete {num}: Hora={hora}, Protocolo={protocolo}, Origen={src}, Destino={dst}, Payload={payload_str}"

        elif cmd == "-count":
            total = len(cap)
            con_payload = sum(1 for p in cap if obtener_payload(p))
            sin_payload = total - con_payload
            texto_salida = f"Total de paquetes: {total}\nPaquetes con payload: {con_payload}\nPaquetes sin payload: {sin_payload}"

        elif cmd.startswith("-filter"):
            args = cmd.split("=")
            if len(args) == 2:
                proto = args[1].upper()
                texto_salida += f"Paquetes filtrados por {proto}:\n"
                texto_salida += f"{'Num':<5} {'Hora':<12} {'Protocolo':<10} {'Origen':<15} {'Destino':<15} {'Payload':<7}\n"
                for i, p in enumerate(cap):
                    if any(proto in layer.layer_name.upper() for layer in p.layers):
                        src = p.ip.src if hasattr(p, 'ip') else 'N/A'
                        dst = p.ip.dst if hasattr(p, 'ip') else 'N/A'
                        hora = p.sniff_time.time()
                        payload_str = "Si" if obtener_payload(p) else "No"
                        texto_salida += f"{i:<5} {hora} {p.highest_layer:<10} {src:<15} {dst:<15} {payload_str:<7}\n"
            else:
                texto_salida = "Uso incorrecto de -filter. Ejemplo: -filter=TCP"
   
        elif cmd.startswith("-time"):
            args = cmd.split("=")
            if len(args) == 2:
                try:
                    rango = args[1].split("-")
                    if len(rango) != 2:
                        raise ValueError
                    inicio = datetime.strptime(rango[0], "%H:%M:%S").time()
                    fin = datetime.strptime(rango[1], "%H:%M:%S").time()

                    if inicio > fin:
                        texto_salida = Fore.RED + f"Advertencia: La hora de inicio {inicio} es posterior a la hora de fin {fin}."
                    else:
                        texto_salida += f"Paquetes filtrados entre {inicio} y {fin}:\n"
                        texto_salida += f"{'Num':<5} {'Hora':<12} {'Protocolo':<10} {'Origen':<15} {'Destino':<15} {'Payload':<7}\n"

                        for i, p in enumerate(cap):
                            paquete_hora = p.sniff_time.time()
                            if inicio <= paquete_hora <= fin:
                                src = p.ip.src if hasattr(p, 'ip') else 'N/A'
                                dst = p.ip.dst if hasattr(p, 'ip') else 'N/A'
                                tiene_payload = bool(obtener_payload(p))
                                payload_str = Fore.GREEN + "Sí" + Style.RESET_ALL if tiene_payload else Fore.RED + "No" + Style.RESET_ALL
                                texto_salida += f"{i:<5} {paquete_hora} {p.highest_layer:<10} {src:<15} {dst:<15} {payload_str:<7}\n"
                except ValueError:
                    texto_salida = Fore.RED + "Formato de hora incorrecto. Ejemplo: -time=10:30:00-11:15:00"
            else:
                # Si solo se escribió -time sin rango, mostrar rango total
                if cap:
                    hora_inicio = cap[0].sniff_time.time()
                    hora_fin = cap[-1].sniff_time.time()
                    texto_salida = f"Rango horario de la captura: {hora_inicio} - {hora_fin}"

        elif cmd == "-clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            texto_salida = "Pantalla limpia."

        else:
            texto_salida = f"Comando no reconocido: {cmd}"

        print(texto_salida)
        salida_export.append(texto_salida)

    # Exportar si se indicó
    if export_file:
        try:
            if not os.path.exists(EXPORT_DIR):
                os.makedirs(EXPORT_DIR)
            if not os.path.splitext(export_file)[1]:
                export_file += ".txt"
            export_path = os.path.join(EXPORT_DIR, export_file)
            with open(export_path, 'w', encoding='utf-8') as f:
                for linea in salida_export:
                    f.write(linea + "\n")
            print(Fore.GREEN + f"Información exportada correctamente en: {export_path}")
        except Exception as e:
            print(Fore.RED + f"Error al exportar: {e}")
