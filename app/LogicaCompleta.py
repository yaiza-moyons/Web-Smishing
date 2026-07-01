import dns.resolver
import ssl
import socket
import certifi
import re
import requests
import os
import whois
from datetime import datetime
from urllib.parse import urlparse

#Fichero con dominios fiables
RUTA_SCRIPT = os.path.dirname(os.path.abspath(__file__))
FICHERO_LISTA_BLANCA = os.path.join(RUTA_SCRIPT, "lista_blanca.txt")

# =================================================================
# 0. NUEVO: OBTENER DOMINIO REGISTRABLE PARA WHOIS
# =================================================================
def obtener_dominio_registrable(dominio):
    """
    Extrae el dominio registrable (ej: sub.sub.dominio.com -> dominio.com)
    Necesario para que WHOIS funcione correctamente.
    """
    partes = dominio.split(".")
    if len(partes) >= 2:
        return ".".join(partes[-2:])
    return dominio

# =================================================================
# 1. EXTRACCIÓN Y LIMPIEZA (MEJORADA)
# =================================================================
def extraer_dominio_limpio(texto_sms):
    """
    Extrae el dominio principal de un enlace dentro de un SMS.
    Ahora detecta también acortadores y URLs más complejas.
    """
    patron = r'(https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?)'
    urls = re.findall(patron, texto_sms)

    if not urls:
        return None

    url = urls[0]
    if not url.startswith("http"):
        url = "http://" + url

    dominio = urlparse(url).netloc
    return dominio


def extraer_url_completa(texto_sms):
    patron = r'(https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?)'
    urls = re.findall(patron, texto_sms)
    if not urls:
        return None
    url = urls[0]
    if not url.startswith("http"):
        url = "http://" + url
    return url


# =================================================================
# 2. INFRAESTRUCTURA DNS (MEJORADA)
# =================================================================
def analizar_infraestructura_dns(dominio, timeout=2.5):
    """
    Obtiene registros A, MX y NS.
    Ahora también obtiene la IP real del dominio.
    """
    resultados = {"A": [], "MX": [], "NS": [], "IP": None}

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Obtener IP real
        try:
            resultados["IP"] = socket.gethostbyname(dominio)
        except:
            resultados["IP"] = None

        # Registros DNS
        for tipo in ["A", "MX", "NS"]:
            try:
                answers = resolver.resolve(dominio, tipo)
                resultados[tipo] = [str(r) for r in answers]
            except:
                resultados[tipo] = []

        return resultados

    except Exception as e:
        return {"error": str(e)}


# =================================================================
# 3. GEOLOCALIZACIÓN (MEJORADA)
# =================================================================
def geolocalizar_ip(ip, timeout=2.5):
    """
    Ahora también obtiene ASN e ISP, muy útil para detectar hosting sospechoso.
    """
    if not ip:
        return None

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,lat,lon,city,as,isp",
            timeout=timeout
        ).json()

        if response['status'] == 'success':
            return {
                "pais": f"{response['country']} ({response['countryCode']})",
                "lat": response['lat'],
                "lon": response['lon'],
                "ciudad": response['city'],
                "asn": response.get("as"),
                "isp": response.get("isp")
            }
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


# =================================================================
# 4. CERTIFICADO SSL (MEJORADO)
# =================================================================
def obtener_datos_ssl(dominio, timeout=2.5):
    """
    Ahora detecta certificados autofirmados y CA sospechosas.
    """
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with socket.create_connection((dominio, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()

                inicio = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                dias = (datetime.now() - inicio).days

                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])

                nombre_entidad = subject.get('organizationName') or subject.get('commonName', "No declarada")

                autofirmado = (subject == issuer)

                return {
                    "dias_vida": dias,
                    "org": nombre_entidad,
                    "ca": issuer.get('commonName', "Desconocida"),
                    "autofirmado": autofirmado
                }

    except socket.timeout:
        return None
    except Exception:
        return None


# =================================================================
# 5. WHOIS — RDAP (gratuito, sin API key, estándar IANA)
# =================================================================

_RDAP_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Endpoints conocidos para los TLDs más comunes (evita consultar el bootstrap cada vez)
_RDAP_CONOCIDOS = {
    "com":    "https://rdap.verisign.com/com/v1/",
    "net":    "https://rdap.verisign.com/net/v1/",
    "org":    "https://rdap.publicinterestregistry.org/rdap/",
    "info":   "https://rdap.identitydigital.services/rdap/",
    "xyz":    "https://rdap.centralnic.com/xyz/",
    "top":    "https://rdap.zdnsgtld.com/top/",
    "click":  "https://rdap.tucowsregistry.net/rdap/",
    "shop":   "https://rdap.gmoregistry.net/rdap/",
    "live":   "https://rdap.identitydigital.services/rdap/",
    "online": "https://rdap.radix.host/rdap/",
    # .es: Red.es no ofrece RDAP público ni WHOIS sin IP autorizada
}

_rdap_bootstrap_cache = None  # Se carga una sola vez por sesión



def _servidor_rdap_para_tld(tld):
    """Devuelve la URL base del servidor RDAP para un TLD dado."""
    global _rdap_bootstrap_cache

    if tld in _RDAP_CONOCIDOS:
        return _RDAP_CONOCIDOS[tld]

    # Para TLDs no conocidos, consultar el bootstrap de IANA (se cachea en memoria)
    try:
        if _rdap_bootstrap_cache is None:
            resp = requests.get("https://data.iana.org/rdap/dns.json", timeout=5)
            _rdap_bootstrap_cache = resp.json()

        for entry in _rdap_bootstrap_cache["services"]:
            tlds, servers = entry[0], entry[1]
            if tld in tlds and servers:
                return servers[-1]  # El último suele ser HTTPS
    except Exception:
        pass

    return None


def obtener_edad_dominio_rdap(dominio, timeout=2.5):
    """
    Consulta la fecha de registro usando RDAP.
    Devuelve los días desde la creación, o None si no está disponible.
    """
    try:
        dominio_base = obtener_dominio_registrable(dominio)
        tld = dominio_base.split(".")[-1].lower()

        servidor = _servidor_rdap_para_tld(tld)

        urls = []
        if servidor:
            urls.append(servidor.rstrip("/") + "/domain/" + dominio_base)
        urls.append(f"https://rdap.org/domain/{dominio_base}")  # fallback genérico

        for url in urls:
            try:
                r = requests.get(url, timeout=timeout, headers=_RDAP_HEADERS)
                if r.status_code != 200:
                    continue

                data = r.json()
                for evento in data.get("events", []):
                    if evento.get("eventAction") == "registration":
                        fecha_dt = datetime.fromisoformat(
                            evento["eventDate"].replace("Z", "+00:00")
                        )
                        return (datetime.now(fecha_dt.tzinfo) - fecha_dt).days
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        return None
    except Exception:
        return None


# =================================================================
# 6. COINCIDENCIA DE ENTIDAD (MEJORADA)
# =================================================================
def verificar_coincidencia_entidad(nombre_usuario, nombre_certificado):
    """
    Si el usuario NO introduce empresa:
    - Si el certificado NO tiene organización → penalizar
    - Si tiene organización → no penalizar
    """

    # Caso 1: no se introduce empresa → evaluar solo si hay organización
    if not nombre_usuario:
        if not nombre_certificado or "No declarada" in nombre_certificado:
            return False  # penaliza
        return True  # no penaliza

    # Caso 2: sí se introduce empresa → comparación normal
    u = re.sub(r'\W+', '', nombre_usuario.lower())
    c = re.sub(r'\W+', '', nombre_certificado.lower())

    sufijos = ['sa', 'sl', 'inc', 'corp', 'ltd']
    for s in sufijos:
        if u.endswith(s): u = u[:-len(s)]
        if c.endswith(s): c = c[:-len(s)]

    return u in c or c in u

def cargar_lista_blanca():
    """Lee la lista blanca directamente desde el fichero externo."""
    try:
        with open(FICHERO_LISTA_BLANCA, "r", encoding="utf-8") as f:
            # Lee cada línea, limpia espacios/saltos y descarta líneas vacías
            return [linea.strip() for linea in f if linea.strip()]
    except FileNotFoundError:
        # Por si acaso borras el archivo por error, que el programa no se rompa
        print(f"⚠️ Alerta: No se encontró '{FICHERO_LISTA_BLANCA}'. Trabajando sin lista blanca.")
        return []

def añadir_a_lista_blanca(dominio):
    """Añade un nuevo dominio al fichero si no está ya dentro."""
    dominios = cargar_lista_blanca()
    if dominio not in dominios:
        with open(FICHERO_LISTA_BLANCA, "a", encoding="utf-8") as f:
            f.write(f"{dominio}\n")
        print(f"--> [LISTA BLANCA] '{dominio}' añadido automáticamente por riesgo 0.")
    
# =================================================================
# 7. PUNTUACIÓN (MEJORADA)
# =================================================================
def calcular_puntos(dominio, dns_info, ssl_info, coincide, geo_info=None, edad_dominio=None):
    """
    Devuelve:
    - puntuación total
    - lista de penalizaciones aplicadas
    """
    penalizaciones = []
    puntos = 0

    #Cargo la lista con los dominios
    lista_blanca = cargar_lista_blanca()
    if any(dominio == db or dominio.endswith("." + db) for db in lista_blanca):
        return 0, ["Dominio en lista blanca: riesgo 0"]

    # --- 1. CERTIFICADO ---
    # Umbrales basados en análisis estadístico: media fraudulenta 24,20 días vs 105,10 días legítima
    if ssl_info:
        dias = ssl_info.get('dias_vida', 0)

        if dias < 25:
            puntos += 40
            penalizaciones.append("+40: Certificado en zona de riesgo (<25 días)")
        elif dias < 60:
            puntos += 20
            penalizaciones.append("+20: Certificado en zona de riesgo bajo (25-60 días)")

        if ssl_info.get("autofirmado"):
            puntos += 40
            penalizaciones.append("+40: Certificado autofirmado (muy sospechoso)")

    # --- 2. IDENTIDAD ---
    if coincide is False:
        puntos += 50
        penalizaciones.append("+50: La identidad del certificado no coincide con la empresa esperada")

    # --- 3. EDAD DEL DOMINIO ---
    # Rangos basados en análisis estadístico de muestras fraudulentas vs legítimas
    if edad_dominio is not None:
        if edad_dominio <= 2200:
            puntos += 30
            penalizaciones.append("+30: Dominio en riesgo crítico (0-2200 días)")
        elif edad_dominio <= 8800:
            puntos += 10
            penalizaciones.append("+10: Dominio en punto medio (2201-8800 días)")

    # --- 4. CA gratuita/automática (sin validación de identidad) ---
    # Intermedios de Let's Encrypt identificados en el análisis estadístico del TFG
    _intermedios_le = {"e1", "e2", "e5", "e6", "e7", "e8", "r3", "r4", "r10", "r11", "r12", "we1", "wr1"}
    ca_gratuita = False
    if ssl_info:
        ca_lower = ssl_info['ca'].lower().strip()
        ca_gratuita = (
            ca_lower in _intermedios_le or
            "let's encrypt" in ca_lower or
            any(c in ca_lower for c in ["zerossl", "cpanel", "cloudflare"])
        )
        if ca_gratuita:
            puntos += 15
            penalizaciones.append(f"+15: CA automática sin validación de identidad ({ssl_info['ca']})")

        # WR2 es el intermedio de Google Trust Services — solo debería aparecer en dominios de Google
        
        if ca_lower == "wr2":
            dominio_base = obtener_dominio_registrable(dominio).lower()
            cn_certificado = ssl_info.get('common_name', '').lower() # Asegúrate de que tu ssl_info extraiga el CN
            
            es_de_google = dominio_base.startswith("google.") or "google" in cn_certificado
            
            if not es_de_google:
                puntos += 40
                penalizaciones.append(f"+40: CA de Google (WR2) usada en un dominio ajeno a la compañía")

    # --- 5. TLD sospechoso ---
    tld_sospechosos = [
        # Genéricos localizados en smishing/phishing
        ".top", ".xyz", ".click", ".shop", ".live", ".online", ".lol", ".site",
        ".icu", ".vip", ".buzz", ".club", ".work", ".link", ".bid", ".win",
        ".loan", ".trade", ".review", ".party", ".date", ".faith", ".stream",
        ".racing", ".download", ".accountant", ".science", ".men", ".webcam",
        ".monster", ".sbs", ".cyou", ".cfd",
        # TLDs gratuitos/muy baratos 
        ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ]
    tld_sospechoso = any(dominio.endswith(t) for t in tld_sospechosos)

    if tld_sospechoso and ca_gratuita:
        puntos += 15
        penalizaciones.append("+15: TLD sospechoso combinado con CA gratuita (patrón típico de smishing)")
    elif tld_sospechoso:
        puntos += 20
        penalizaciones.append("+20: TLD sospechoso (.xyz, .top, .click, .lol, .site, etc.)")

    # --- 6. PALABRAS SOSPECHOSAS ---
    # --- 6. PALABRAS SOSPECHOSAS (AMPLIADA) ---
    palabras_phishing = [
        "verify", "secure", "login", "update", "alert", "sms", "track", "delivery",
        "reclamar", "paquete", "incidencia", "seguridad", "cuenta", "banca", 
        "tarjeta", "bloqueo", "activar", "soporte", "asistente", "recibir",
        "aduanas", "tasas", "envio", "identidad", "cliente", "aviso"
    ]
    if any(p in dominio.lower() for p in palabras_phishing):
        puntos += 15
        penalizaciones.append("+15: El dominio contiene palabras típicas de phishing")

    puntuacion_final = min(puntos, 100)
    
    if puntuacion_final == 0:
        print("   • 🎉 ¡Riesgo 0 detectado! Intentando escribir en el fichero...")
        dominio_base = obtener_dominio_registrable(dominio)
        añadir_a_lista_blanca(dominio_base)

    return puntuacion_final, penalizaciones

