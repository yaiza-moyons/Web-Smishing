ANALIZADOR DE MENSAJES SMSM (DETECCIÓN DE SMISHING)

Esta aplicación permite pegar el texto de un SMS sospechoso para comprobar en tiempo real si se trata de una estafa (smishing). Evalúa el texto, analiza técnicamente sus enlaces y guarda de forma segura los metadatos en la base de datos.


1) REQUISITOS PREVIOS
Antes de ejecutar el proyecto, es neccesario tener instalado en el ordenador:
- Docker Desktop: se debe abrir la aplicación Docker Desktop antes de lanzar el Paso 3. Si la aplicación no está abierta y funcionando de fondo, el sistema dará error.
- Github: para descargar el código.

2) GUÍA DE INSTALACIÓN

Paso 1: Descargar código fuente desde el repositorio de GitHub: 
git clone  https://github.com/yaiza-moyons/Web-Smishing

Paso 2: Configurar credenciales en fichero .env
MONGO_URI=mongodb+srv://admin:admin@cluster0.kaewczj.mongodb.net/?appName=Cluster0

Paso 3: Arrancar entorno Docker
Asegurarse que el Docker Desktop está abierto. En el terminal, accediendo a la carpeta del proyecto, se levanta el contenedor:
cd <nombre_de_la_carpeta_del_proyecto>
docker-compose up --build

Paso 4: Abrir la apalicación web
Abre el navegador de Intenet y entra en: 
http://localhost:8501
