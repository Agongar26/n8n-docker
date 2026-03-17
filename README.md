# Práctica n8n: WAF - Detección de Inyección SQL (SQLi)

## 1. Descripción del incidente que se detecta
Este flujo actúa como un WAF (Web Application Firewall) básico, diseñado para detectar y mitigar **intentos de Inyección SQL (SQLi)** en tiempo real. Analiza los datos de entrada (payloads) enviados a través de formularios web simulados (como inicios de sesión o cajas de búsqueda) en busca de comandos maliciosos comunes. El objetivo es prevenir que un atacante extraiga información o modifique la base de datos subyacente de la aplicación.

## 2. Explicación de la lógica de detección
El flujo se activa mediante un **Webhook** que recibe peticiones `POST` simulando el tráfico web (IP, usuario y payload). A continuación, la lógica se desarrolla en dos pasos:
1. **Nodo Code (JavaScript):** Normaliza el payload convirtiéndolo a minúsculas (`toLowerCase()`) para asegurar que el análisis sea insensible a mayúsculas/minúsculas y evitar técnicas de evasión.
2. **Nodo IF (Evaluación Lógica):** Utiliza código JavaScript nativo y expresiones regulares (`.test()`) para inspeccionar el payload normalizado. Busca palabras clave críticas de SQL, independientemente del texto que las rodee: `.*(union|select|insert|update|delete|drop).*`. 
   * Si detecta estos comandos (rama `True`), clasifica el tráfico como un ataque.
   * Si no los detecta (rama `False`), asume que es tráfico legítimo y detiene el análisis.

## 3. Justificación de los criterios utilizados
Se ha optado por este escenario y lógica de detección por varias razones:
* **Realismo:** La inyección SQL sigue siendo una de las vulnerabilidades más críticas y comunes (OWASP Top 10).
* **Precisión:** El uso de expresiones regulares combinadas con la normalización del texto en el nodo `Code` proporciona un método robusto para detectar múltiples variantes de un mismo ataque sin generar falsos positivos en el tráfico normal.
* **Respuesta Proporcional Multicanal:** Se implementa una respuesta técnica completa. Primero, **persistencia forense** guardando la evidencia del ataque (IP, usuario, payload) en una tabla específica (`sqli_incidents`) de PostgreSQL. Posteriormente, se escala el incidente con **dos alertas simultáneas**: un correo electrónico al equipo SOC vía Mailhog y un mensaje instantáneo de Telegram al administrador, garantizando una notificación inmediata del incidente crítico.

## 4. Instrucciones para probar el workflow
Para probar el correcto funcionamiento del workflow, se deben realizar dos pruebas utilizando herramientas como Postman o cURL, enviando peticiones `POST` a la URL del Webhook de prueba de n8n.

**Prueba Positiva (Simulación de Ataque):**
1. Activar "Listen for Test Event" en el Webhook de n8n.
2. Enviar la siguiente petición `POST` en formato JSON:
   ```json
   {
     "ip": "192.168.1.55",
     "username": "admin",
     "payload": "admin UNION SELECT * FROM passwords"
   }

   ![alt text](image.png)