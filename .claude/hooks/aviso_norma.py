"""Disparador Stop de Claude Code: avisa si Almudena da una norma y no se escribe en ningún sitio.

Lee el JSON que Claude Code manda por la entrada estándar. Si en el turno que acaba hay un mensaje suyo
con pinta de norma y después no se tocó ningún sitio de guardado, contesta {"decision":"block","reason":...};
si no, no dice nada y no gasta tokens. Nunca escribe en archivos ni copia su texto al aviso.
Prueba: python Automatizacion/hooks/prueba_aviso_norma.py · Medir: python Automatizacion/hooks/medir_aviso_norma.py
"""
import glob
import json
import os
import re
import sys

MOTIVO = (
    "Almudena puede haber dado una norma en este turno y no se ha guardado en ningún sitio. "
    "Si es una norma, aplica la skill escribir-norma. "
    "Si no es una norma, contesta solo «No es norma» y nada más."
)

NORMA = re.compile(
    r"\b(a partir de ahora|de ahora en adelante|desde ahora|de aqu[ií] en adelante|en adelante"
    r"|que no se vuelva a|no se vuelva a|no vuelvas a|no volv[aá]is a"
    r"|cada vez que|como regla|nueva (norma|regla)|(norma|regla) nueva|cambia la norma"
    r"|siempre|nunca|jam[aá]s)\b",
    re.I,
)
# Habla normal que no es norma: se quita de la frase antes de buscar.
FRASE_HECHA = re.compile(r"\b(como|de|para|casi|no) siempre\b|\bsiempre y cuando\b|\bcasi nunca\b|\bnunca m[aá]s\b", re.I)
# Lo ya pasado («no he hecho esto nunca», «siempre he contado con») cuenta su historia, no manda nada.
PASADO = re.compile(r"\b(he|has|ha|hemos|han|hab[ií]a\w*)\s+(\w+\s+){0,2}?\w+(ado|ido|cho|sto)\b", re.I)
ENTRECOMILLADO = re.compile(r"«[^»]*»|\"[^\"]*\"|“[^”]*”")
# shortcut: más de 3000 caracteres se toma por material pegado, no por una orden; subir si se escapan normas.
LARGO_MAXIMO = 3000
ENCARGO_AUTOMATICO = re.compile(
    r"^\s*(Lee Automatizaci[oó]n/|Background \(from the session|This session is being continued)|Autorizaci[oó]n de Almudena"
)
BLOQUES_AJENOS = re.compile(r"<(pasted_content|system-reminder)\b[^>]*>.*?(</\1>|\Z)", re.S)
LINEA_UTIL = re.compile(r'"type":\s*"(user|assistant)"|"queued_command"|"stop_hook_summary"')
GIT_COMMIT = re.compile(r"\bgit\b[^|;&\n]*\bcommit\b")


def texto_de(contenido):
    if isinstance(contenido, str):
        return contenido
    if isinstance(contenido, list):
        return "\n".join(b.get("text", "") for b in contenido if isinstance(b, dict) and b.get("type") == "text")
    return ""


def limpiar(texto):
    """Su texto sin lo pegado ni los avisos del sistema; vacío si no es de ella."""
    texto = BLOQUES_AJENOS.sub("", texto or "").strip()
    if texto.startswith("<") or ENCARGO_AUTOMATICO.search(texto):
        return ""
    return texto


def mensaje_suyo(e):
    """El texto si el evento es un mensaje escrito por ella; si no, cadena vacía."""
    if e.get("type") == "attachment":  # lo que escribe a mitad de turno llega así, no como «user»
        a = e.get("attachment") or {}
        if a.get("type") != "queued_command" or a.get("commandMode") != "prompt" or a.get("isMeta"):
            return ""
        return limpiar(texto_de(a.get("prompt")))
    if e.get("type") != "user" or e.get("isMeta") or e.get("isSidechain"):
        return ""
    if (e.get("origin") or {}).get("kind", "human") != "human":
        return ""
    return limpiar(texto_de((e.get("message") or {}).get("content")))


def frases_de_norma(texto):
    if len(texto) > LARGO_MAXIMO:
        return []
    salen = []
    for frase in re.findall(r"[^.!?\n]+[.!?]*", ENTRECOMILLADO.sub("", texto)):
        frase = frase.strip()
        if frase.endswith("?") or frase.startswith("¿") or PASADO.search(frase):
            continue
        if NORMA.search(FRASE_HECHA.sub("", frase)):
            salen.append(frase)
    return salen


def guarda(e):
    """True si el evento toca un sitio de guardado: un .md editado o un commit."""
    if e.get("type") != "assistant":
        return False
    contenido = (e.get("message") or {}).get("content")
    for b in contenido if isinstance(contenido, list) else []:
        if not isinstance(b, dict) or b.get("type") != "tool_use":
            continue
        entrada = b.get("input") or {}
        if b.get("name") in ("Edit", "Write", "MultiEdit") and str(entrada.get("file_path", "")).lower().endswith(".md"):
            return True
        if b.get("name") in ("Bash", "PowerShell") and GIT_COMMIT.search(str(entrada.get("command", ""))):
            return True
    return False


def frontera(e):
    """Evento que marca el final de un turno."""
    if e.get("type") == "system":
        return e.get("subtype") == "stop_hook_summary"
    return e.get("type") == "assistant" and (e.get("message") or {}).get("stop_reason") in ("end_turn", "stop_sequence")


def leer(ruta):
    """Eventos útiles del archivo; se saltan por texto las líneas enormes que no importan (resultados, capturas)."""
    eventos = []
    with open(ruta, encoding="utf-8", errors="replace") as f:
        for linea in f:
            if '"tool_use_id"' in linea or not LINEA_UTIL.search(linea):
                continue
            try:
                eventos.append(json.loads(linea))
            except ValueError:
                pass
    return eventos


def turno_actual(eventos):
    """Los eventos del turno que acaba, tanto si su último mensaje ya está escrito en el archivo como si no."""
    fin = len(eventos)
    while fin and frontera(eventos[fin - 1]):
        fin -= 1
    inicio = fin
    while inicio and not frontera(eventos[inicio - 1]):
        inicio -= 1
    return eventos[inicio:]


def subagentes_guardan(transcript, desde, hasta=None):
    """Mira si un subagente guardó algo después de `desde` (hora del mensaje) y, al medir, antes de `hasta`."""
    carpeta = os.path.splitext(transcript)[0]
    for ruta in glob.glob(os.path.join(glob.escape(carpeta), "subagents", "**", "*.jsonl"), recursive=True):
        for e in leer(ruta):
            if guarda(e) and e.get("timestamp", "") >= desde and (hasta is None or e.get("timestamp", "") <= hasta):
                return True
    return False


def hay_norma_sin_guardar(eventos, transcript, hasta=None):
    """Decide sobre los eventos de un turno."""
    primera = next((i for i, e in enumerate(eventos) if frases_de_norma(mensaje_suyo(e))), None)
    if primera is None:
        return False
    if any(guarda(e) for e in eventos[primera:]):
        return False
    return not subagentes_guardan(transcript, eventos[primera].get("timestamp", ""), hasta)


def main():
    datos = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    if datos.get("stop_hook_active"):  # ya avisó en este turno: sin esto entraría en bucle
        return
    ruta = datos["transcript_path"]
    if hay_norma_sin_guardar(turno_actual(leer(ruta)), ruta):
        sys.stdout.write(json.dumps({"decision": "block", "reason": MOTIVO}))


if __name__ == "__main__":
    try:
        main()
    except BaseException:  # nunca debe bloquearla ni enseñarle un error
        pass
    sys.exit(0)
