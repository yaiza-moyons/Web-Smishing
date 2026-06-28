import os
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv

# Carga las variables de entorno definidas en el archivo .env
load_dotenv()

# Variables globales para reutilizar la conexión entre llamadas (patrón singleton)
_client = None
_collection = None


def _get_collection():
    """
    Devuelve la colección 'analisis' de MongoDB, abriendo la conexión
    solo la primera vez que se llama (conexión lazy).

    La URI de conexión se lee de la variable de entorno MONGO_URI,
    definida en el archivo .env del proyecto.

    Lanza EnvironmentError si MONGO_URI no está definida.
    """
    global _client, _collection

    # Si ya se abrió la conexión, la reutilizamos directamente
    if _collection is not None:
        return _collection

    uri = os.environ.get("MONGO_URI")
    if not uri:
        raise EnvironmentError("Variable de entorno MONGO_URI no definida.")

    # Conexión a Atlas con timeout de 5 segundos para no bloquear la app
    _client = MongoClient(uri, serverSelectionTimeoutMS=5000)

    # Base de datos: smishing_db  |  Colección: analisis
    _collection = _client["smishing_db"]["analisis"]
    return _collection


def guardar_analisis(dominio, url_completa, sms_texto, empresa_esperada, puntuacion,
                     dns_res, ssl_res, geo_info, edad_dominio, penalizaciones, tiempo_analisis=None):
    """
    Guarda o actualiza los metadatos de un análisis en MongoDB Atlas.

    Si el dominio ya existe en la colección, sobreescribe el documento
    con los datos más recientes, en el caso de que no existe, lo crea.

    Parámetros:
        dominio          (str)   Dominio analizado, p.ej. 'example.com'
        sms_texto        (str)   Texto completo del SMS introducido por el usuario
        empresa_esperada (str)   Empresa que el usuario indicó como posible suplantada
        puntuacion       (int)   Puntuación de riesgo entre 0 y 100
        dns_res          (dict)  Registros DNS obtenidos (A, MX, NS, IP)
        ssl_res          (dict)  Datos del certificado SSL (org, CA, días de vida...)
        geo_info         (dict)  Geolocalización de la IP (país, ciudad, ISP, ASN...)
        edad_dominio     (int)   Días desde la creación del dominio según RDAP
        penalizaciones   (list)  Lista de penalizaciones aplicadas durante el scoring

    Devuelve el _id del documento insertado/actualizado, o None si falla.
    Un fallo en MongoDB no interrumpe la app: solo imprime el error por consola.
    """

    # Convertir la puntuación numérica a una etiqueta de riesgo legible
    if puntuacion >= 70:
        nivel_riesgo = "FRAUDE"
    elif puntuacion > 20:
        nivel_riesgo = "SOSPECHOSO"
    else:
        nivel_riesgo = "SEGURO"

    # Documento que se guardará en la colección
    documento = {
        "timestamp": datetime.now(timezone.utc),   # Fecha y hora UTC del análisis
        "dominio": dominio,
        "url_completa": url_completa,
        "sms_texto": sms_texto,
        "empresa_esperada": empresa_esperada or None,
        "puntuacion": puntuacion,
        "nivel_riesgo": nivel_riesgo,
        "penalizaciones": penalizaciones,
        "dns": dns_res,
        "ssl": ssl_res,
        "geolocalizacion": geo_info,
        "edad_dominio_dias": edad_dominio,
        "tiempo_analisis_segundos": round(tiempo_analisis, 2) if tiempo_analisis is not None else None,
    }

    try:
        col = _get_collection()

        # Índice único sobre 'dominio' para garantizar un solo documento por dominio
        col.create_index("dominio", unique=True)

        # update_one con upsert=True: actualiza si existe, inserta si no existe
        resultado = col.update_one(
            {"dominio": dominio},   # Filtro: busca por dominio
            {"$set": documento},    # Acción: sobreescribe con los nuevos datos
            upsert=True,
        )
        return str(resultado.upserted_id or dominio)

    except Exception as e:
        print(f"[MongoDB] Error al guardar análisis: {e}")
        return None
