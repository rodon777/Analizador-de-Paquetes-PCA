# Analizador-de-Paquetes-PCA
El Analizador de Paquetes PCAP es una herramienta interactiva en Python diseñada para inspeccionar archivos de captura de red (.pcap). 

Herramienta interactiva en **Python** para analizar archivos de captura de red (**.pcap**) utilizando **PyShark**.  
Permite explorar paquetes, filtrar por protocolo o rango de tiempo, visualizar payloads y encabezados, así como exportar resultados a texto.  

Incluye interfaz de línea de comandos con **colores** mediante `colorama` para facilitar la lectura.

---

## Características
- Inspección de paquetes individuales.  
- Filtros por **protocolo** o **rango de tiempo**.  
- Visualización de **payloads** y **encabezados completos**.  
- Exportación de resultados a `.txt`.  
- Interfaz CLI con colores.  

---

## Requisitos
- **Python 3.8 o superior**
- Librerías de Python:  

```bash
pip install pyshark colorama

Nota: PyShark requiere Wireshark o TShark instalado y configurado en el PATH del sistema.
