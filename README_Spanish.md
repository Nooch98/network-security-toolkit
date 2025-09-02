# 🛡️ Deteccion de Ataques IPv4/IPv6

* **ARP Spoofing (Suplantacion de ARP):**
    * **Cómo lo detecta:** El script analiza los paquetes ARP para detectar posibles conflictos.
    Si la dirección IP del router (o de cualquier dispositivo en la red) se asocia con una dirección MAC inesperada en un paquete ARP, El script genera una alerta. Tambien tiene un modo de monitoreo proactivo que revisa periodicamente la caché ARP del sistema en busca de cambios sspechosos en la MAC del router.

* **ICMPv6 Spoofing (Suplantacion de IPv6):**
    * **Como lo detecta:** Similar a la deteccion ARP, el script monitorea los paquetes ICMPv6 Neighbor Discovery (ND) y Router Advertisement (RA). Si un dispositivo anuncia ser el router (Gateway) de IPv6 con una direccion MAC que no coincide con la MAC original del router legitimo, se genera una alerta.

* **DHCP Spoofing (Suplantacion DHCP):**
    * **Como lo detecta:** El script examina los paquetes DHCP. Si un paquete de respuesta DHCP proviene de una direccion IP que no es la del router o que no ha sido previamente identificada como una IP confiable, se considera una amenaza.

# 🌐 Detección de Ataques DNS y Web

* **DNS Spoofing (Suplantación de DNS):**
    * **Como lo detecta:** Cuando se realiza una consulta DNS, el script captura la solicitud y espera la respuesta. Si la respuesta contiene una direccion IP que no coincide con las direcciones legitimas para ese dominio (Obtenidas atraves de servidores DNS de confianza como 8.8.8.8 o 1.1.1.1), se genera una alerta. Esto previene que el trafico sea redirigido a sitios web maliciosos(Puede generar algun falso positivo)

* **SSLstrip (Ataque de Despojar SSL):**
    * **Como lo detecta:** El script monitoriza el trafico HTTP. Si detecta una conexion HTTP a un dominio que sabes que deberia usar HTTPS(como Google, Amazon, etc.), genera una alerta. Esto indica que un atacante podria haber eliminado el cifrado SSL/TLS, haciendo la conexion insegura.

# 🔬 Características Adicionales

* **Contramedidas Activas (`-c`):** Esta funcion permmite al script no solo detectar, sino tambien mitigar el ataque. Envia paquetes gratuitos de ARP y ND para restaurar las tablas de la red, corrigiendo las entradas alteradas por un atacante y restableciendo el flujo de trafico legitimo.

# 💻 Uso del script

* **Modo de deteccion simple:** Para monitorear la interfaz seleccionada de manera pasiva:
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface>
```
o puedes usar
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface> -p
```

* **Modo con Contramedidas:** Para monitorear la interfaz seleccionada y mitigar ataques detectados:
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface> -c
```

* **Usando IPs de confianza:** Para monitorear la red e indicar las ips de dispositivos confiables en la red:
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface> --trusted-ips 10.10.10.1,10.10.10.11
```

# ⚠️ Advertencia de Uso Ético y Legal
Este script esta creado para un uso Etico en redes propias o con autorizacion del administrador. Cualquier uso no autorizado de este script en una red de terceros podria ser ilegal y tener consecuencias legales

## 🛑 Limitaciones y Riesgos
El script utiliza contramedidas activas para mitigar ataques. Aunque es una funcion bastante util, tambien tiene algunos riesgos.

* **Riesgo de interrupcion de la red:** La funcion de contramedidas puede generar mucho trafico de red o enviar paquetes ARP o ND que, en redes mal configuradas o muy sensibles podrian causar una interrupcion temporal del servicio.

* **Falsos positivos:** Aunque se intenta ajustar la precision, se pueden generar falsas alarmas, especialmente en redes complejas o con configuraciones atipicas. Por lo tanto, cualquier alerta debe ser analizada.

## 📜 Responsabilidad

* **Descargo de responsabilidad:** Como creador original de este script no me hago responsable de cualquier mal uso o daño generado por un mal uso del script. Como usuario asumes la responsabilidad completa.
