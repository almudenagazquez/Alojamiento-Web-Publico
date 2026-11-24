# Inactivo: Almudena decidió el 24/11/2026 no activarlo; ningún settings.json lo llama.
"""Disparador PreToolUse de Claude Code: «lo que nunca se rompe se asegura con bloqueos» (MANUAL 0.3, 7.8).

Matcher: Write|Edit|MultiEdit|Bash|PowerShell. Lee el JSON de la herramienta por la entrada estándar y:
  A) bloquea escribir algo con pinta de clave secreta real (va a Bitwarden) en un archivo de un repositorio git
     o en la memoria de Claude (.claude/projects/<x>/memory/); fuera de eso (temporales, scratchpad) pasa;
  B) bloquea borrados recursivos o masivos de rutas protegidas (Drive, brutos, biblioteca, disco externo).
Salida: 0 deja pasar; 2 bloquea y el motivo va por stderr a Claude.
A prueba de fallos: cualquier error deja pasar y se apunta en <temp>/bloqueos_errores.log. Nunca escribe en el repo.
Interruptor: BLOQUEOS_OFF=1. Pruebas: python Automatizacion/hooks/test_bloqueos.py

Límites conocidos (deja pasar): borrados dentro de `python -c` (shutil.rmtree, os.remove), `xargs rm`,
rutas que vienen de una tubería (`Get-ChildItem X | Remove-Item -Recurse`), subcomandos `$(...)`,
variables que no sean HOME/USERPROFILE/TEMP, `robocopy /MIR` y comillas escapadas dentro de comillas dobles.
Los cuerpos de heredoc (<<EOF, <<-EOF) y de here-strings de PowerShell (@'…'@, @"…"@) no se leen como órdenes,
y lo que va tras « #» al principio de una palabra es comentario. Límite: `<<` dentro de comillas se toma
igual por heredoc, y un heredoc sin delimitador de cierre se come el resto del comando (deja pasar).
Secretos: una ruta relativa sin cwd deja pasar.
"""
import datetime
import json
import os
import posixpath
import re
import sys
import tempfile
import traceback
import unicodedata

# ---------------------------------------------------------------- rutas protegidas (que Almudena las confirme)
# Se compara por COMPONENTES de la ruta (carpetas enteras, sin mayúsculas), no por letra de unidad:
# D: es el disco de trabajo en el PC y el disco Elements en el portátil.
PROTEGIDAS = {
    "ia para pymes",            # carpeta raíz de Drive sincronizada desde el PC
    "otros ordenadores",        # Drive en el portátil: G:\Otros ordenadores\Mi PC\…
    "mi unidad", "my drive",    # Drive montado (G:\Mi unidad)
    "mi pc",                    # el PC principal visto desde Drive
    "retirado",                 # lo retirado del disco externo
    "copias del repositorio",
    "fotos años",
    "mis vídeos", "mis videos",
    "videos off",
    "sobre mí", "sobre mi",
    "brutos",                   # salvo Contenido/metricas/…/brutos (texto versionado en git)
    "historias_personales",
    "biblioteca",               # la carpeta; el script biblioteca.py es otro componente
    "drivefs",                  # caché de Google Drive para escritorio
}
# «DRIVE» solo cuenta como segundo componente tras la unidad (F:\DRIVE), y F: entera es el disco externo del PC.
UNIDAD_EXTERNA = "f:"
BRUTOS_DEL_REPO = "/contenido/metricas/"

# Nunca se bloquea un destino con alguno de estos componentes, aunque esté bajo ruta protegida.
EXENTAS = {"node_modules", ".git", "__pycache__", ".pytest_cache", ".venv", "venv", "dist", "build",
           ".cache", "tmp", "temp"}
CLON = "clon del repositorio (uso técnico, no tocar)"  # el clon del PC vive dentro de Drive; git ya lo protege

MSG_BORRADO = ("Bloqueado (MANUAL 0.3, 7.8): {cmd} borra {ruta}, que es una ruta protegida (Drive, brutos, "
               "biblioteca o disco externo). Nada se borra sin su copia comprobada en el disco externo y el "
               "permiso de Almudena. Si de verdad toca, díselo a ella; interruptor BLOQUEOS_OFF=1.")
MSG_SECRETO = ("Bloqueado (MANUAL 0.3): lo que vas a escribir parece una clave secreta ({tipo}). Guárdala en "
               "Bitwarden; aquí solo el nombre de la entrada. Si es un falso positivo, BLOQUEOS_OFF=1.")

# ---------------------------------------------------------------- A) secretos
# (tipo, patrón, exige mayúsculas + minúsculas + dígitos para no saltar con nombres de ejemplo)
SECRETOS = [
    ("clave de Anthropic", re.compile(r"(?<![\w-])sk-ant-[A-Za-z0-9_-]{20,}"), True),
    ("clave sk-", re.compile(r"(?<![\w-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}"), True),
    ("token de GitHub", re.compile(r"(?<![\w-])gh[posu]_[A-Za-z0-9]{30,}"), True),
    ("token de GitHub", re.compile(r"(?<![\w-])github_pat_[A-Za-z0-9_]{30,}"), True),
    ("clave de AWS", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"), False),
    ("token de Slack", re.compile(r"(?<![\w-])xox[bpas]-[A-Za-z0-9-]{10,}"), False),
    ("clave de Google", re.compile(r"(?<![\w-])AIza[A-Za-z0-9_-]{35}"), False),
    ("clave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----[ \t]*\r?\n"
                                 r"(?:[A-Za-z-]+:[^\n]*\n|\r?\n)*[A-Za-z0-9+/=\r\n]{40,}"), False),
    ("token Bearer", re.compile(r"(?i:bearer)\s+[A-Za-z0-9._~+/=-]{30,}"), True),
]
MARCADORES = ("xxxx", "....", "tu-clave", "tu_clave", "tu_", "your", "example", "ejemplo", "redacted",
              "<", "{{", "${", "token")


def _es_marcador(trozo, patron_bearer):
    bajo = trozo.lower()
    cuerpo = bajo[len("bearer"):] if patron_bearer else bajo  # «token» en «Bearer TOKEN…» es marcador; en el prefijo no
    if any(m in (cuerpo if m == "token" else bajo) for m in MARCADORES):
        return True
    return re.search(r"(.)\1{7,}", trozo) is not None  # todo el mismo carácter repetido


def _aleatorio(trozo):
    return any(c.islower() for c in trozo) and any(c.isupper() for c in trozo) and any(c.isdigit() for c in trozo)


def en_repo_o_memoria(ruta, cwd=None):
    """True si `ruta` cae dentro de un repositorio git (hay `.git` en alguna carpeta de encima, aunque la del
    archivo aún no exista) o en la memoria de Claude. Ruta relativa sin cwd: False (deja pasar)."""
    if not ruta:
        return False
    if not os.path.isabs(ruta):
        if not cwd:
            return False
        ruta = os.path.join(cwd, ruta)
    ruta = os.path.abspath(ruta)
    if re.search(r"/\.claude/projects/[^/]+/memory/", ruta.replace("\\", "/").lower()):
        return True
    carpeta = os.path.dirname(ruta)
    while True:
        if os.path.exists(os.path.join(carpeta, ".git")):
            return True
        arriba = os.path.dirname(carpeta)
        if arriba == carpeta:
            return False
        carpeta = arriba


def revisar_texto_secreto(texto, ruta, cwd=None):
    """Motivo del bloqueo si `texto`, que se va a escribir en `ruta`, lleva un secreto; si no, None."""
    ruta_n = (ruta or "").replace("\\", "/").lower()
    nombre = ruta_n.rsplit("/", 1)[-1]
    if nombre in ("bloqueos.py", "test_bloqueos.py") or "/node_modules/" in ruta_n:
        return None
    if not isinstance(texto, str) or not texto.strip() or not en_repo_o_memoria(ruta, cwd):
        return None
    for tipo, patron, mezcla in SECRETOS:
        for m in patron.finditer(texto):
            trozo = m.group(0)
            if _es_marcador(trozo, tipo == "token Bearer") or (mezcla and not _aleatorio(trozo)):
                continue
            return MSG_SECRETO.format(tipo=tipo)
    return None


# ---------------------------------------------------------------- B) borrados
HEREDOC = re.compile(r"(?<!<)<<(?!<)-?[ \t]*(['\"]?)([A-Za-z_][\w.-]*)\1")
HERE_STRING = re.compile(r"@(['\"])[ \t]*$")


def quitar_cuerpos(comando):
    """El comando sin los cuerpos de heredoc ni de here-strings de PowerShell (son texto, no órdenes)."""
    lineas, salida, i = comando.split("\n"), [], 0
    while i < len(lineas):
        linea = lineas[i]
        i += 1
        m = HERE_STRING.search(linea)
        if m:
            salida.append(linea[:m.start()] + '""')
            cierre = m.group(1) + "@"
            while i < len(lineas) and not lineas[i].lstrip().startswith(cierre):
                i += 1
            if i < len(lineas):
                salida.append(lineas[i].lstrip()[2:])  # lo que sigue a '@ (p. ej. «| Set-Content x») sí se revisa
                i += 1
            continue
        salida.append(linea)
        for m in HEREDOC.finditer(linea):
            while i < len(lineas) and lineas[i].strip() != m.group(2):
                i += 1
            i += 1  # salta la línea del delimitador de cierre
    return "\n".join(salida)


def trocear(comando):
    """Lista de órdenes (cada una, lista de palabras) separadas por ; && || | & y saltos de línea."""
    comando = quitar_cuerpos(comando)
    ordenes, palabras, actual, citado = [], [], [], False

    def cerrar_palabra():
        nonlocal actual, citado
        if actual or citado:
            palabras.append("".join(actual))
        actual, citado = [], False

    def cerrar_orden():
        nonlocal palabras
        cerrar_palabra()
        if palabras:
            ordenes.append(palabras)
        palabras = []

    i, n = 0, len(comando)
    while i < n:
        c = comando[i]
        if c == "#" and not actual and not citado:  # comentario: «# …» hasta el salto de línea
            fin = comando.find("\n", i)
            i = n if fin < 0 else fin
            continue
        if c in "'\"":
            j = comando.find(c, i + 1)
            if j < 0:
                raise ValueError("comillas sin cerrar")
            actual.append(comando[i + 1:j])
            citado, i = True, j + 1
            continue
        if c == "\\" and comando[i + 1:i + 2] == " ":  # «IA\ para\ PYMES» en bash
            actual.append(" ")
            i += 2
            continue
        if c in " \t":
            cerrar_palabra()
        elif c in "\r\n;|":
            cerrar_orden()
        elif c == "&" and not ((actual and actual[-1].endswith(">")) or comando[i + 1:i + 2] == ">"):
            cerrar_orden()
        else:
            actual.append(c)
        i += 1
    cerrar_orden()
    return ordenes


def _norm(texto):
    return unicodedata.normalize("NFC", texto).lower()


def _absoluta(ruta):
    """Ruta absoluta en forma «c:/a/b» o «/a/b», normalizada y en minúsculas."""
    ruta = ruta.replace("\\", "/")
    m = re.match(r"^/([a-zA-Z])(/|$)", ruta)  # Git Bash: /c/Users → c:/Users
    if m:
        ruta = m.group(1) + ":/" + ruta[3:]
    m = re.match(r"^([a-zA-Z]):(.*)$", ruta)
    if m:
        resto = posixpath.normpath("/" + m.group(2).lstrip("/"))
        return _norm(m.group(1) + ":" + resto)
    return _norm(posixpath.normpath(ruta))


def _casa():
    return _absoluta(os.path.expanduser("~"))


def _temporal():
    return _absoluta(tempfile.gettempdir())


VARIABLES_CASA = ("${home}", "$home", "$env:userprofile", "$env:home", "%userprofile%", "$userprofile",
                  "%homedrive%%homepath%")
VARIABLES_TEMP = ("$env:temp", "$env:tmp", "%temp%", "%tmp%", "${tmpdir}", "$tmpdir")


def resolver(palabra, directorio):
    """Ruta absoluta normalizada de `palabra`, o None si no se puede saber con seguridad."""
    if not palabra:
        return None
    ruta = palabra
    if ruta == "~" or ruta.startswith(("~/", "~\\")):
        ruta = _casa() + ruta[1:]
    bajo = ruta.lower()
    for variables, valor in ((VARIABLES_CASA, _casa), (VARIABLES_TEMP, _temporal)):
        for v in variables:
            if bajo.startswith(v):
                ruta, bajo = valor() + ruta[len(v):], (valor() + ruta[len(v):]).lower()
    if "$" in ruta or "`" in ruta or re.search(r"%\w+%", ruta) or ruta.startswith("~"):
        return None  # variable que no entendemos: se deja pasar
    plana = ruta.replace("\\", "/")
    if re.match(r"^([a-zA-Z]:|/)", plana):
        return _absoluta(plana)
    if not directorio:
        return None
    return _absoluta(directorio.rstrip("/") + "/" + plana)


def _es_raiz_o_casa(ruta):
    return (ruta == "/" or re.fullmatch(r"[a-z]:/?", ruta) is not None or ruta == _casa()
            or re.fullmatch(r"([a-z]:)?/(users|home)(/[^/]+)?", ruta) is not None or ruta == "/root")


def _sin_comodines(ruta):
    """La carpeta antes del primer componente con * o ?."""
    partes = ruta.split("/")
    for i, p in enumerate(partes):
        if "*" in p or "?" in p:
            base = "/".join(partes[:i])
            return base + "/" if base.endswith(":") or base == "" else base
    return ruta


def ruta_protegida(ruta):
    """True si la ruta absoluta normalizada cae bajo una ruta protegida y fuera de las exenciones."""
    partes = [p for p in ruta.split("/") if p]
    if any(p in EXENTAS for p in partes) or "/.claude/worktrees/" in ruta + "/":
        return False
    if CLON in partes[:-1]:
        return False
    tmp = _temporal()
    if ruta == tmp or ruta.startswith(tmp + "/") or "/appdata/local/temp" in ruta:
        return False
    if not partes:
        return False
    if partes[0] == UNIDAD_EXTERNA:
        return True
    if re.fullmatch(r"[a-z]:", partes[0]) and len(partes) > 1 and partes[1] == "drive":
        return True
    for p in partes:
        if p == "brutos" and BRUTOS_DEL_REPO in ruta + "/":
            continue
        if p in PROTEGIDAS:
            return True
    return False


def _nombre(palabra):
    nombre = palabra.lstrip("({&").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return nombre[:-4] if nombre.endswith(".exe") else nombre


PREFIJOS = {"sudo", "command", "exec", "env", "nohup", "time", "&", "builtin"}
BORRAR = {"rm", "remove-item", "ri", "del", "erase", "rd", "rmdir"}
CMD_BORRAR = {"del", "erase", "rd", "rmdir"}
SOLO_CARPETAS = {"rd", "rmdir"}
CON_VALOR = {"-include", "-exclude", "-filter", "-erroraction", "-ea", "-stream", "-credential"}
CAMBIAR_DIR = {"cd", "chdir", "pushd", "set-location", "sl"}


def _recursivo(bandera):
    b = bandera.lower().split(":", 1)[0]
    if b in ("/s", "--recursive") or (len(b) >= 2 and "-recurse".startswith(b)):
        return True
    return re.fullmatch(r"-[rRfivdI]+", bandera) is not None and "r" in b


def _motivo(orden, ruta):
    texto = " ".join(orden)
    return MSG_BORRADO.format(cmd=texto if len(texto) <= 120 else texto[:117] + "...", ruta=ruta)


def _revisar_destinos(orden, destinos, directorio, recursivo):
    for d in destinos:
        comodin = "*" in d or "?" in d
        if not (recursivo or comodin):
            continue
        ruta = resolver(d, directorio)
        if ruta is None:
            continue
        if recursivo and _es_raiz_o_casa(_sin_comodines(ruta)):
            return _motivo(orden, d)
        if ruta_protegida(ruta):
            return _motivo(orden, d)
    return None


def _revisar_orden(orden, directorio):
    """(motivo o None, directorio tras la orden)."""
    while orden and (_nombre(orden[0]) in PREFIJOS or re.match(r"^\w+=", orden[0])):
        orden = orden[1:]
    if not orden:
        return None, directorio
    nombre, args = _nombre(orden[0]), orden[1:]

    if nombre in CAMBIAR_DIR:
        destino = next((a for a in args if not a.startswith("-") and a.lower() != "/d"), "~")
        return None, resolver(destino, directorio)

    if nombre == "cmd" and args and args[0].lower() in ("/c", "/k"):
        return _revisar_orden(args[1:], directorio)
    if nombre in ("bash", "sh", "zsh", "powershell", "pwsh"):
        for i, a in enumerate(args[:-1]):
            if a.lower() in ("-c", "-command"):
                return revisar_borrado(" ".join(args[i + 1:]), directorio), directorio
        return None, directorio

    if nombre in BORRAR:
        recursivo, destinos, saltar, fin_opciones = False, [], False, False
        for a in args:
            if saltar:
                saltar = False
            elif fin_opciones:
                destinos.append(a)
            elif a == "--":
                fin_opciones = True
            elif ">" in a:
                continue
            elif a.startswith("-"):
                if a.lower() in CON_VALOR:
                    saltar = True
                recursivo = recursivo or _recursivo(a)
            elif nombre in CMD_BORRAR and re.fullmatch(r"/[a-zA-Z](:\S*)?", a):
                recursivo = recursivo or _recursivo(a)
            else:
                destinos.append(a)
        if nombre in SOLO_CARPETAS and not recursivo:
            return None, directorio  # rmdir sin /s solo borra carpetas vacías
        return _revisar_destinos(orden, destinos, directorio, recursivo), directorio

    if nombre == "git":
        i, carpeta = 0, directorio
        while i < len(args) and args[i].startswith("-"):
            if args[i] == "-C" and i + 1 < len(args):
                carpeta = resolver(args[i + 1], directorio)
                i += 1
            elif args[i] == "-c":
                i += 1
            i += 1
        if i >= len(args) or args[i] != "clean":
            return None, directorio
        banderas = [a for a in args[i + 1:] if a.startswith("-") and not a.startswith("--")]
        largas = [a for a in args[i + 1:] if a.startswith("--")]
        letras = "".join(b[1:] for b in banderas)
        if "n" in letras or "--dry-run" in largas:
            return None, directorio
        if not (set(letras) & set("fdx") or "--force" in largas):
            return None, directorio
        caminos = [a for a in args[i + 1:] if not a.startswith("-")]
        if carpeta is None:
            return None, directorio
        destinos = [resolver(c, carpeta) for c in caminos] or [carpeta]
        for d in destinos:
            if d and ruta_protegida(d.rstrip("/") + "/_"):  # git clean borra lo de dentro, no la carpeta
                return _motivo(orden, d), directorio
        return None, directorio

    if nombre == "find":
        borra = "-delete" in args or any(
            a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args) and _nombre(args[i + 1]) == "rm"
            for i, a in enumerate(args))
        if not borra:
            return None, directorio
        caminos = []
        for a in args:
            if a in ("-H", "-L", "-P") and not caminos:
                continue
            if a.startswith(("-", "(", "!", "\\(")):
                break
            caminos.append(a)
        return _revisar_destinos(orden, caminos or ["."], directorio, True), directorio

    return None, directorio


def revisar_borrado(comando, cwd):
    """Motivo del bloqueo si `comando` borra en masa una ruta protegida; si no, None. Ante la duda, None."""
    try:
        ordenes = trocear(comando)
    except ValueError:
        return None
    directorio = resolver(cwd, None) if isinstance(cwd, str) and cwd else None
    for orden in ordenes:
        motivo, directorio = _revisar_orden(orden, directorio)
        if motivo:
            return motivo
    return None


# ---------------------------------------------------------------- decisión
def decidir(entrada):
    """(código, mensaje): (0, "") deja pasar; (2, motivo) bloquea."""
    if os.environ.get("BLOQUEOS_OFF") == "1" or not isinstance(entrada, dict):
        return 0, ""
    herramienta = entrada.get("tool_name")
    datos = entrada.get("tool_input")
    if not isinstance(datos, dict):
        return 0, ""
    motivo = None
    if herramienta in ("Write", "Edit", "MultiEdit"):
        ruta = str(datos.get("file_path") or "")
        if herramienta == "Write":
            textos = [datos.get("content")]
        elif herramienta == "Edit":
            textos = [datos.get("new_string")]
        else:
            textos = [e.get("new_string") for e in datos.get("edits") or [] if isinstance(e, dict)]
        cwd = entrada.get("cwd") if isinstance(entrada.get("cwd"), str) else None
        motivo = next((m for m in (revisar_texto_secreto(t, ruta, cwd) for t in textos) if m), None)
    elif herramienta in ("Bash", "PowerShell"):
        comando = datos.get("command")
        if isinstance(comando, str):
            motivo = revisar_borrado(comando, entrada.get("cwd"))
    return (2, motivo) if motivo else (0, "")


def _apuntar_error():
    try:
        with open(os.path.join(tempfile.gettempdir(), "bloqueos_errores.log"), "a", encoding="utf-8") as f:
            f.write("%s\n%s\n" % (datetime.datetime.now().isoformat(), traceback.format_exc(limit=5)))
    except Exception:
        pass


def main():
    if os.environ.get("BLOQUEOS_OFF") == "1":
        return 0
    try:
        crudo = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        if not crudo.strip():
            return 0
        codigo, mensaje = decidir(json.loads(crudo))
        if codigo == 2:
            sys.stderr.buffer.write(mensaje.encode("utf-8"))
            sys.stderr.flush()
        return codigo
    except BaseException:  # nunca debe parar el trabajo por un fallo propio
        _apuntar_error()
        return 0


if __name__ == "__main__":
    sys.exit(main())
