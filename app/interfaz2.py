import streamlit as st
import LogicaCompleta as motor
import pandas as pd
import requests
import mongo
import time

st.set_page_config(page_title="Analizador de SMS", layout="centered")

# --- LÓGICA DE ESTADO ---
if 'analizado' not in st.session_state: # si es false muestra formulario, si es True muestra resultados
    st.session_state.analizado = False

st.markdown("<h1 style='text-align: center; color: #1E3A8A;'>Analizador de SMS</h1>", unsafe_allow_html=True)

# --- ESCENA 1: FORMULARIO ---
if not st.session_state.analizado:

    #Cuadro para SMS
    st.markdown("### Introduzca el cuerpo del mensaje")
    sms_text = st.text_area("Cuerpo", label_visibility="collapsed", height=150, key="txt_sms")

    #Cuadro para empresa
    st.markdown("### (Opcional) Empresa suplantada")
    empresa_esperada = st.text_input("Empresa", label_visibility="collapsed", key="txt_empresa")

    #Botón de analizar
    if st.button("Iniciar análisis", width="stretch", key="btn_main"):
        if not sms_text:
            st.warning("Escriba un mensaje primero.")
        else:
            st.session_state.sms_a_procesar = sms_text
            st.session_state.empresa_a_procesar = empresa_esperada
            st.session_state.analizado = True # Para que se cambie a la otra escena, la de los resultados
            st.rerun()

# --- ESCENA 2: RESULTADOS --- Cuando interuptor a True
else:
    with st.spinner("Realizando escaneo forense..."):

        #1) Pide la URL
        dom = motor.extraer_dominio_limpio(st.session_state.sms_a_procesar)
        # 1.1) No hay dominio --> muestra error
        if not dom:
            st.error("URL no detectada en el mensaje.")
            if st.button("Volver"):
                st.session_state.analizado = False
                st.rerun()
        #1.2) HAy dominio --> realiza las consultas técnicas
        else:
            url_completa = motor.extraer_url_completa(st.session_state.sms_a_procesar)
            inicio = time.time()

            t0 = time.time()
            dns_res = motor.analizar_infraestructura_dns(dom)
            #time.sleep(5.0)
            t_dns = time.time() - t0

            t0 = time.time()
            ssl_res = motor.obtener_datos_ssl(dom)
            #time.sleep(5.0)
            t_ssl = time.time() - t0

            if t_dns > 2.5 or t_ssl > 2.5:
                st.error("Exceso de tiempo de espera (Timeout): El servidor de destino o los servicios de red externos tardan demasiado en responder.")
                if st.button("Volver"):
                    st.session_state.analizado = False
                    st.rerun()
            #1.2.1) No tiene SSl --> lanza alerta
            elif not ssl_res:
                st.error(" Riesgo Crítico: No hay SSL o el servidor no responde.")
                if st.button("Volver"):
                    st.session_state.analizado = False
                    st.rerun()
            #1.2.2) Sí tiene SSL --> cruza los datos y calcula la puntuación
            else:
                coincide = None
                if st.session_state.empresa_a_procesar:
                    coincide = st.session_state.empresa_a_procesar.lower() in ssl_res['org'].lower()

                t0 = time.time()
                edad = motor.obtener_edad_dominio_rdap(dom)
                t_rdap = time.time() - t0

                t0 = time.time()
                geo = motor.geolocalizar_ip(dns_res["IP"])
                t_geo = time.time() - t0

                # Cálculo final de puntuación con todos los parámetros
                puntos, detalles = motor.calcular_puntos(dom, dns_res, ssl_res, coincide, geo, edad)
                tiempo_total = time.time() - inicio

                mongo.guardar_analisis(
                    dominio=dom,
                    url_completa=url_completa,
                    sms_texto=st.session_state.sms_a_procesar,
                    empresa_esperada=st.session_state.empresa_a_procesar,
                    puntuacion=puntos,
                    dns_res=dns_res,
                    ssl_res=ssl_res,
                    geo_info=geo,
                    edad_dominio=edad,
                    penalizaciones=detalles,
                    tiempo_analisis=tiempo_total,
                )

                # SEMÁFORO DE RIESGO
                st.divider()
                st.subheader(f"Informe de riesgos para: {dom}")
                st.caption(f"Análisis completado en {tiempo_total:.2f} segundos")
                
                col_v, col_a, col_r = st.columns(3) #tres columnas por tres partes del semaforo

                #VERDE = SEGURO --> PUNTOS <20 
                with col_v:
                    op = 1 if puntos <= 20 else 0.1
                    st.markdown(f"<div style='background-color: #28a745; padding: 20px; border-radius: 10px; opacity: {op}; text-align: center; color: white; font-weight: bold;'>SEGURO</div>", unsafe_allow_html=True)
                
                #AMARILLO = SOSPECHOSO --> PUNTOS ENTRE 20 Y 70
                with col_a:
                    op = 1 if 20 < puntos < 70 else 0.1
                    st.markdown(f"<div style='background-color: #ffc107; padding: 20px; border-radius: 10px; opacity: {op}; text-align: center; color: black; font-weight: bold;'>SOSPECHOSO</div>", unsafe_allow_html=True)
                
                #ROJO = FRAUDE --> PUNTOS >70
                with col_r:
                    op = 1 if puntos >= 70 else 0.1
                    st.markdown(f"<div style='background-color: #dc3545; padding: 20px; border-radius: 10px; opacity: {op}; text-align: center; color: white; font-weight: bold;'>FRAUDE</div>", unsafe_allow_html=True)
                
                st.markdown(f"<h2 style='text-align: center;'>Puntuación: {puntos}/100</h2>", unsafe_allow_html=True)

                # MAPA VISUALIZACIÓN UBI IP
                #Si hay dirección IP
                if dns_res['A']:
                    geo = motor.geolocalizar_ip(dns_res['A'][0])
                    if geo:
                        st.markdown(f"📍 **Servidor ubicado en:** {geo['pais']} ({geo['ciudad']})")
                        df_map = pd.DataFrame({'lat': [geo['lat']], 'lon': [geo['lon']]} )
                        st.map(df_map)

                # --- EL BOTÓN DE MÁS INFORMACIÓN ---
                with st.expander("🔍 Ver detalles técnicos detallados"): #Menú despegable
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write("**Datos del Certificado SSL:**")
                        st.write(f"- Organización: `{ssl_res['org']}`")
                        st.write(f"- Autoridad Certificadora: `{ssl_res['ca']}`")
                        st.write(f"- Días desde emisión: `{ssl_res['dias_vida']}`")
                        
                        # --- NUEVO CAMPO DE VALIDACIÓN DE IDENTIDAD ---
                        st.divider() # Una línea fina para separar
                        if st.session_state.empresa_a_procesar:
                            if coincide:
                                st.success(f"Identidad Verificada: El certificado pertenece a **{st.session_state.empresa_a_procesar}**.")
                            else:
                                st.error(f" Alerta de Identidad: Se esperaba **{st.session_state.empresa_a_procesar}** pero el certificado es de **{ssl_res['org']}**.")
                        else:
                            st.info(" No se proporcionó una empresa para validar la identidad.")
                    with c2:
                        st.write("**Registros de Red (DNS):**")
                        st.write(f"- IP Servidor (A): `{dns_res['A']}`")
                        st.write(f"- Servidores Correo (MX): `{dns_res['MX']}`")
                        st.write(f"- Servidores Nombre (NS): `{dns_res['NS']}`")

                        st.divider()
                        st.write("**Información RDAP:**")
                        if edad is not None:
                            st.write(f"- Edad del dominio: `{edad}` días")
                        else:
                            st.write("- No se pudo obtener información RDAP")

                        st.divider()
                        st.write("**Información de Geolocalización:**")
                        if geo:
                            st.write(f"- País: `{geo['pais']}`")
                            st.write(f"- Ciudad: `{geo['ciudad']}`")
                            st.write(f"- ISP: `{geo['isp']}`")
                            st.write(f"- ASN: `{geo['asn']}`")
                        else:
                            st.write("- No se pudo obtener geolocalización")

                    # --------- TIEMPOS DE ANÁLISIS ---------
                    st.divider()
                    st.write("### ⏱ Tiempos de análisis")
                    st.dataframe(
                        pd.DataFrame({
                            "Módulo": ["DNS", "SSL/TLS", "RDAP", "Geolocalización", "Total"],
                            "Tiempo (s)": [
                                round(t_dns, 2),
                                round(t_ssl, 2),
                                round(t_rdap, 2),
                                round(t_geo, 2),
                                round(tiempo_total, 2)
                            ]
                        }),
                        hide_index=True,
                        width="stretch"
                    )

                     # --------- NUEVA SECCIÓN: DETALLES DE PUNTUACIÓN ---------
                    st.divider()
                    st.write("### 🧮 Factores que han aumentado el riesgo")

                    if detalles:
                        for d in detalles:
                            st.write(f"- {d}")
                    else:
                        st.write("✔ No se aplicaron penalizaciones. El dominio parece legítimo.")
                # Espaciado y botón de reinicio
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔄 Analizar otro mensaje", width="stretch"):
                    st.session_state.analizado = False
                    st.rerun()
