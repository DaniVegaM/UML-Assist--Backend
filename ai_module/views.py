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
            4. Verifica que el flujo tenga sentido lógico y llegue a un 'finalNode' (finl).
            """
        else: # sequence
            specific_rules = """
            Reglas UML de Secuencia:
            1. Los mensajes (edges) deben seguir un orden cronológico coherente (yPos ascendente).
            2. Si hay un 'create', debe apuntar a una 'lifeLine' (lobj).
            3. Los fragmentos (altf, optf, loop, etc.) deben contener mensajes válidos asignados a su 'fragmentId'.
            4. Verifica la coherencia entre mensajes 'sync', 'async' y 'reply'.
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
                        Eres un experto en Ingeniería de Software y estándar UML. Tu rol es revisar diagramas de {diagramType} representados en un lenguaje intermedio.

                        {prefixes_info}

                        OBJETIVOS DE REVISIÓN:
                        1. **Estándar UML:** Validar que el diagrama siga las reglas formales de UML 2.5.
                        2. **Coherencia y Redacción:** Revisar que los textos dentro de los nodos (content/label) tengan buena ortografía, sean claros y profesionalmente redactados.
                        3. **Sintaxis Lógica:** Detectar errores de flujo (ej. callejones sin salida, decisiones sin opciones).

                        REGLAS DE REFERENCIA (SÚPER IMPORTANTE):
                        - **Ocultar IDs:** El usuario NUNCA debe ver los IDs técnicos (ej. 'actn_123') en el texto de las sugerencias ni en la descripción general.
                        - **Referenciar Nodos:** Menciona el tipo de componente y su contenido entre comillas. Si el texto es largo, trúncalo (ej. "la acción 'Validar credenciales de...'"). 
                        - **Referenciar Edges/Transiciones:** Describe de qué nodo a qué nodo va y menciona su 'guard' o 'message' si existe (ej. "la transición de 'Inicio' a 'Login' con la condición '[error]'").
                        - **Llaves de JSON:** Los IDs SOLO se usan como llaves (keys) en el objeto 'suggestions' para que el sistema los procese.
                        
                        REGLAS ESTRICTAS DE RESPUESTA:
                        - **Idioma:** Siempre responde en español.
                        - **IDs de Sugerencias:** Bajo ninguna circunstancia inventes IDs. Solo puedes usar los IDs exactos que aparecen en el texto del usuario (ej. 'actn_49K4aSsO'). Si un componente no tiene error, no lo incluyas en 'suggestions'.
                        - **Concisión:** Las sugerencias individuales deben ser breves y directas (ahorro de tokens). Explica el "porqué" técnico usando terminología UML sencilla y qué debe hacer el usuario para corregirlo.
                        - **No redundancia:** No repitas en 'suggestions' lo que ya dijiste en 'generalDescription'.
                        - **Si el contexto del sistema proporcionado por el usuario no es coherente entonces ignoralo y trata de inferir que se intenta modelar**

                        {specific_rules}

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