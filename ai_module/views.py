from django.shortcuts import render

from decouple import config
import requests
import json

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated


class ReviewDiagramView(APIView):
    """
    Vista para revisar diagramas usando IA
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Método POST para revisar un diagrama
        """
        data = request.data
        diagramType = data.get('diagramType')
        intermediateLanguage = data.get('intermediateLanguage')
        userPrompt = data.get('userPrompt')

        prefixes_info = """
        Prefijos de ID por tipo de componente:
        - Actividades: activity (actv), simpleAction (actn), acceptEvent (acce), acceptTimeEvent (acct), sendSignal (smsg), callOperation (cllo), callBehavior (cllb), initialNode (intl), finalNode (finl), finalFlowNode (ffin), decisionControl (dcsn), mergeNode (mrge), parallelizationNode (prll), connectorNode (cnnt), dataNode (data), objectNode (objc), exceptionHandling (exhn), InterruptActivityRegion (iar), note (note).
        - Secuencia: lifeLine (lobj), altFragment (altf), optFragment (optf), loopFragment (loop), breakFragment (brkf), seqFragment (seqf), strictFragment (strf), parFragment (parf), note (note).
        """

        # Instrucciones específicas por tipo de diagrama
        if diagramType == "activities":
            specific_rules = """
            Reglas UML de Actividades:
            1. Todo diagrama debe tener un 'initialNode' (intl).
            2. Los 'decisionControl' (dcsn) deben tener al menos dos flujos de salida con 'guards' (condiciones) claras.
            3. No debe haber nodos aislados; todos deben estar conectados por 'edges'.
            4. Las acciones ('actions') deben ser atómicas dentro del contexto y nombrarse con verbos claros (ej. 'Procesar pago' en lugar de 'pago')
            5. Diferencia correctamente el fin del flujo: usa 'flow final node' para terminar un solo camino concurrente, y 'activity final node' para terminar toda la actividad.
            6. PROACTIVIDAD: Si el sistema maneja datos importantes (ej. guardar un ticket, actualizar perfil), sugiere utilizar un 'data store' para representar memoria persistente o 'object nodes' explícitos.
            7. PROACTIVIDAD: Si el flujo es propenso a fallas (ej. cobros con tarjeta, caídas de red), sugiere añadir un 'exception handler' o una 'interruptible activity region' para mitigar los errores.
            8. PROACTIVIDAD (Concurrencia): Si detectas tareas independientes, sugiere usar un 'parallelizationNode' (prll) para indicar que ocurren al mismo tiempo.
            """
        else: # sequence
            specific_rules = """
            Reglas UML de Secuencia:
            1. Los mensajes (edges) deben seguir un orden cronológico coherente (yPos ascendente).
            2. Si hay un 'create', debe apuntar a una 'lifeLine' (lobj).
            3. Los fragmentos (altf, optf, loop, etc.) deben contener mensajes válidos asignados a su 'fragmentId'.
            4. Verifica la coherencia entre mensajes 'sync', 'async' y 'reply'.
            5. PROACTIVIDAD (Lógica Condicional): Si detectas que un flujo puede tener varios caminos (ej. éxito o error), sugiere envolver los mensajes en un 'altFragment' (altf) o usar un 'optFragment' (optf) si es un paso opcional.
            6. PROACTIVIDAD (Repetición): Si una tarea se ejecuta múltiples veces, sugiere un 'loopFragment' (loop).
            7. PROACTIVIDAD (Concurrencia/Orden): Si hay llamadas a servicios que no dependen entre sí, sugiere un 'parFragment' (parf)[cite: 479]. Si el orden es estrictamente necesario, sugiere un 'strictFragment' (strf).
            """
        
        
        llm_response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {config('OPENROUTER_API_KEY')}",
            },
            data=json.dumps({
                "models": [
                    "google/gemini-2.5-flash",
                    "google/gemini-2.5-flash-lite",
                    "openai/gpt-4o-mini-2024-07-18",
                    # "meta-llama/llama-3.3-70b-instruct"
                ],
                "route": "fallback",
                "temperature": 0.2,
                "max_tokens": 10000,
                "messages": [
                {
                    "role": "system",
                    "content": f"""
                        Eres un experto en Ingeniería de Software y estándar UML. Tu rol es revisar diagramas de {diagramType} representados en un lenguaje intermedio y generar sugerencias de mejora puntuales.

                        {prefixes_info}

                        OBJETIVOS DE REVISIÓN:
                        1. Validar que el diagrama siga estrictamente las reglas formales de UML.
                        2. Detectar errores de flujo, lógica, o mala redacción en los elementos.
                        3. Visión Arquitectónica (PROACTIVO): Entender el dominio del negocio que el usuario intenta modelar (ej. e-commerce, soporte técnico, logística) y proponer proactivamente la adición de elementos UML que mejoren el diseño, clarifiquen responsabilidades o hagan el sistema más robusto.

                        TONO Y ESTILO (ESTRICTO):
                        - Eres un asistente técnico directo y objetivo. 
                        - ESTÁ PROHIBIDO felicitar al usuario o usar frases de relleno como "Buen trabajo", "El flujo principal es correcto", "Excelente", etc. Ve directo al problema y a la solución.
                        - Lenguaje: Español, profesional y conciso.

                        REGLA DE ORO SOBRE IDs (CERO TOLERANCIA):
                        Los IDs internos (ej. 'actn_123', 'seq_456', 'mrge_xaP', 'altf_82H') NUNCA deben aparecer en el texto que lee el usuario. 
                        - Si el elemento TIENE TEXTO: usa su tipo y su nombre truncado (ej. "La acción 'Validar login'", "El fragmento 'loop [x < 5]'").
                        - Si el elemento NO TIENE TEXTO (como un 'mergeNode', 'initialNode', o un fragmento de secuencia sin título/guarda): referéncialo por su tipo y los elementos que conecta o encapsula.
                            * CORRECTO (Actividades): "El nodo de decisión que sigue a 'Procesar pago'...", "El nodo de fusión que lleva a 'Identificar problema'...".
                            * CORRECTO (Secuencia): "El fragmento 'alt' que envuelve el mensaje 'procesarPago()'", "El fragmento opcional ('opt') que involucra a la línea de vida 'BaseDeDatos'...", "La transición de retorno hacia 'Cliente'...".
                            * INCORRECTO: "El nodo mrge_xaPNpKSf...", "El fragmento altf_82H...", "La transición hacia dcsn_123...".
                        Los IDs SOLO se usarán como las llaves (keys) del objeto JSON de respuesta.

                        {specific_rules}

                        INSTRUCCIONES DE SALIDA (MUY IMPORTANTE):
                        - Genera sugerencias solo para los elementos que realmente requieran corrección o mejora. Si un elemento está perfecto, ignóralo.
                        - Genera al menos una sugerencia de MEJORA DE DISEÑO basada en el contexto del sistema. Explica brevemente *por qué* esa adición mejoraría el modelo (ej. "Para este flujo de soporte, se sugiere...").
                        - **RESTRICCIÓN ABSOLUTA:** Cualquier componente nuevo que sugieras añadir DEBE existir obligatoriamente en la lista de "Prefijos de ID por tipo de componente" proporcionada arriba. No inventes tipos de nodos.
                        - Si el contexto proporcionado por el usuario no coincide con el diagrama, infiere la intención basándote en el contenido de los nodos.

                        EJEMPLO DE FORMATO DE SALIDA (JSON):
                        {{
                        "generalDescription": "El flujo principal es correcto, pero la lógica de decisión en el proceso de pago es ambigua.",
                        "suggestions": [
                            {{ "dcsn_xyz123": "Falta definir la condición (guard) para el flujo de rechazo. Sugerencia: añadir '[Crédito insuficiente]'." }},
                            {{ "actn_abc456": "El nombre 'hacer cosas' es vago. Usa un verbo en infinitivo más descriptivo como 'Procesar Factura'." }}
                        ]
                        }}
                        """
                },
                {
                    "role": "user",
                    "content": f"Analiza este diagrama UML de {diagramType}: {intermediateLanguage} y aquí esta el contexto del diagrama que estoy modelando: {userPrompt}"
                }
                ],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                    "name": "UMLFeedback",
                    "strict": False,
                    "schema": {
                        "type": "object",
                        "properties": {
                        "generalDescription": {
                            "type": "string",
                            "description": "Feedback general sobre el diagrama, inconsistencias globales o consejos de diseño UML."
                        },
                        "suggestions": {
                            "type": "array",
                            "description": "Lista de objetos donde cada llave es el ID del componente y el valor es la sugerencia específica.",
                            "items": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                            }
                        }
                        },
                        "required": [
                        "generalDescription",
                        "suggestions"
                        ],
                        "additionalProperties": False
                    }
                    }
                },
            })
        )

        data = llm_response.json()

        if 'error' in data:
            print(f"Error de OpenRouter: {data['error']['message']}")
            return Response(
                {"error": "La IA no pudo procesar el diagrama", "details": data['error']}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        if 'usage' in data:
            usage = data.get('usage', {})
            cost = usage.get('cost')
            print("USO DE TOKENS:======================")
            print(f"  - Modelo Usado: {data.get('model')}")
            print(f"  - Tokens de Entrada: {usage.get('prompt_tokens')}")
            print(f"  - Tokens de Salida: {usage.get('completion_tokens')}")
            print(f"  - Tokens Totales: {usage.get('total_tokens')}")
            if cost is not None:
                print(f"  - Costo Estimado: ${cost:.6f}")
            else:
                print("  - Costo Estimado: N/A")
            print("======================================")

        print("RESPUESTA DE LA IA:======================", data['choices'][0]['message']['content'])
        
        return Response(data['choices'][0]['message']['content'], status=status.HTTP_200_OK)