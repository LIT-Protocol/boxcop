"""Bounded command-text heuristics; NOT a shell parser or execution sandbox.

These inspect submitted strings only. Quoting, indirection, scripts and file
contents can evade them; conservative matches can also be false positives.
"""
import re
import posixpath

INTERPRETERS = frozenset({
    'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'perl', 'ruby',
    'node', 'php', 'pwsh', 'powershell', 'iex', 'invoke-expression',
    'eval', 'source', '.',
})
WRAPPERS = frozenset({'sudo', 'doas', 'env', 'nohup', 'exec', 'command', 'time'})
WRAPPER_VALUE_FLAGS = {
    'sudo': {'-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T', '--user', '--group', '--host'},
    'doas': {'-u', '-C'},
    'env': {'-u', '--unset', '-C', '--chdir', '-S', '--split-string'},
    'time': {'-o', '--output', '-f', '--format'},
}
ASSIGNMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=')
PYTHON = re.compile(r'python(?:[23](?:\.\d+)?)?\Z')
# Boundaries accept absolute paths, but not similarly named executables/URLs.
NETWORK = re.compile(
    r'(?<![\w.-])(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ssh|ftp|telnet|'
    r'https?|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)(?:\.exe)?(?![\w.-]|://)', re.I,
)
FETCH = re.compile(
    r'(?<![\w.-])(?:curl|wget|nc|ncat|netcat|socat|iwr|irm|'
    r'Invoke-WebRequest|Invoke-RestMethod)(?:\.exe)?(?![\w.-])|'
    r'\b(?:DownloadString|DownloadData|FromBase64String)\b', re.I,
)
DECODE = re.compile(
    r'\bbase64\b[^|;\r\n]*(?:\s--decode\b|\s-[A-Za-z]*[dD][A-Za-z]*\b)|'
    r'\bopenssl\s+(?:enc|base64)\b[^|;\r\n]*\s-d\b|'
    r'\bxxd\b[^|;\r\n]*\s-r\b', re.I,
)
SEPARATORS = re.compile(r';|&&|\|\||[\r\n]')


def _name(word):
    return word.strip('"\'(){}').replace('\\', '/').rsplit('/', 1)[-1].lower().removesuffix('.exe')


def _command_words(stage):
    # A pipe can occur inside quoted `sh -c` text, so shlex would reject split
    # pieces with unmatched quotes. This intentionally limited tokenizer handles
    # common wrappers; it does not pretend to parse shell quoting or expansion.
    words = [word.strip('"\'(){}') for word in stage.strip().lstrip('&').split()]
    index = 0
    while index < len(words):
        word = words[index]
        if ASSIGNMENT.match(word):
            index += 1
            continue
        wrapper = _name(word)
        if wrapper not in WRAPPERS:
            return words[index:]
        index += 1
        while index < len(words) and words[index].startswith('-'):
            option = words[index]
            index += 1
            if option == '--':
                break
            if option in WRAPPER_VALUE_FLAGS.get(wrapper, set()):
                index += 1
    return []


def _interpreter(word):
    name = _name(word)
    return name in INTERPRETERS or bool(PYTHON.fullmatch(name))


def _reads_stdin_as_data(words):
    """The one exempt idiom: `python -m json.tool` parses stdin, never runs it."""
    if not PYTHON.fullmatch(_name(words[0])) or "-m" not in words:
        return False
    index = words.index("-m")
    flags_before = words[1:index]
    return (index + 1 < len(words) and words[index + 1] == "json.tool"
            and all(flag.startswith("-") and flag not in {"-", "-c"} for flag in flags_before))


def _source(text):
    return bool(FETCH.search(text) or DECODE.search(text))


def has_network_tool(text: str) -> bool:
    return bool(NETWORK.search(text))


# A common inline JSON reader. Recognize the complete literal program before
# splitting shell regions, since it contains a Python statement separator.
JSON_READER = re.compile(
    r"""(?<=\|)\s*python(?:[23](?:\.\d+)?)?\s+-c\s+(?P<quote>["'])"""
    r"""import\s+json,\s*sys;\s*print\(json\.load\(sys\.stdin\)"""
    r"""(?:\[(?:'\w+'|"\w+"|\d+)\])*\)(?P=quote)(?=\s|[|;&]|$)"""
)
# A plain curl GET writes to stdout. It leaves no downloaded file for a
# subsequent interpreter when its output is neither redirected nor piped.
STDOUT_GET = re.compile(
    r"""\s*curl\s+(?:(?:-[sfSL]+|(?:-m|--max-time)\s+\d+)\s+)*"""
    r"""https?://[A-Za-z0-9./_:%?=~-]+\s*"""
)


def remote_execution(text: str) -> bool:
    """Flag recognizable fetch/decode flows into execution, without running them."""
    text = JSON_READER.sub(" python -m json.tool ", text)
    for region in SEPARATORS.split(text):
        # PowerShell commonly passes expression-valued downloads without a pipe.
        if re.search(r'\b(?:iex|invoke-expression)\b', region, re.I) and _source(region):
            return True
        if re.search(r'\bmshta(?:\.exe)?\b\s+["\']?(?:https?://|javascript:|vbscript:)', region, re.I):
            return True
        ps = re.search(r'\b(?:powershell|pwsh)(?:\.exe)?\b(.*)', region, re.I)
        if ps:
            flags = re.findall(r'(?:^|\s)-([A-Za-z]+)(?=\s|$)', ps[1])
            if any(flag.lower() == 'ec' or 'encodedcommand'.startswith(flag.lower()) for flag in flags):
                return True

        sourced = False
        for stage in region.split('|'):
            words = _command_words(stage)
            if sourced and words and _interpreter(words[0]) and not _reads_stdin_as_data(words):
                return True
            sourced |= _source(stage)

        # $(download), <(download) or backticks directly supplying code/script
        # input. A fetched argument to a named local script is not treated as code.
        for marker in re.finditer(r'\$\(|<\(|`', region):
            end = region.find('`' if marker[0] == '`' else ')', marker.end())
            if end < 0 or not _source(region[marker.end():end]):
                continue
            words = _command_words(region[:marker.start()])
            if not words or not _interpreter(words[0]):
                continue
            name = _name(words[0])
            args = [arg for arg in words[1:] if arg]
            code_flag = any(arg.lower() in {'-c', '-e', '-r', '-command'} for arg in args)
            if name in {'eval', 'source', '.', 'iex', 'invoke-expression'} or code_flag or not args:
                return True
    return False


def download_then_execute(text: str) -> bool:
    """Less certain sequential download/execution; the policy warns, not allows."""
    regions = SEPARATORS.split(text)
    downloaded = False
    for region in regions:
        words = _command_words(region)
        if downloaded and words and (
            _interpreter(words[0]) or re.search(r'\bchmod\b[^;\r\n]*\+x\b', region)
        ):
            return True
        downloaded |= bool(FETCH.search(region)) and not STDOUT_GET.fullmatch(region)
    return False


# Conventional credential stores, by path. Identity *use* (ssh -i, IdentityFile,
# curl --key/--cert) authenticates with a key instead of sending the file, so it
# is excluded. Public keys, known_hosts, authorized_keys and ssh config are not
# secrets. Variables, globs, scripts and renamed copies can evade these checks.
HOME_PREFIX = re.compile(r"^(?:~|\$HOME|\$\{HOME\}|/home/[^/]+|/Users/[^/]+|/root)(?=/|$)")
CREDENTIAL_FILES = frozenset({
    ".aws/credentials", ".netrc", ".kube/config", ".docker/config.json", ".git-credentials",
    ".pgpass", ".npmrc", ".pypirc", ".config/gcloud/application_default_credentials.json",
    ".config/gcloud/credentials.db", ".azure/accessTokens.json", ".azure/msal_token_cache.json",
})
CREDENTIAL_DIRS = frozenset({".ssh", ".aws", ".gnupg", ".kube", ".config/gcloud", ".azure"})
SSH_NOT_SECRET = frozenset({"known_hosts", "known_hosts2", "authorized_keys", "authorized_keys2", "config"})
IDENTITY_FLAGS = frozenset({"-i", "--key", "--cert", "--identity", "--identity-file", "--private-key", "identityfile"})
DOTENV_TEMPLATES = frozenset({"example", "sample", "template", "dist", "defaults"})
TOKEN_SPLIT = re.compile(r"[\s|;&()<>]+")


def _credential_path(token: str, include_dotenv: bool) -> bool:
    path = token
    if "=@" in path:  # curl -F field=@file
        path = path.split("=@", 1)[1]
    elif path.startswith("@"):  # curl --data-binary @file
        path = path[1:]
    name = path.rstrip("/").rsplit("/", 1)[-1]
    if include_dotenv and (name == ".env" or name.startswith(".env.") and name[5:].lower() not in DOTENV_TEMPLATES):
        return True
    if '://' in path:
        return False
    home = HOME_PREFIX.match(path)
    relative = path[home.end():] if home else path
    relative = posixpath.normpath(relative).strip('/').rstrip('*').rstrip('/')
    # Conventional stores remain sensitive under relative paths and copied
    # directory trees. This is lexical matching, not filesystem resolution.
    components = relative.split('/')
    for index, component in enumerate(components):
        if component in {'.aws', '.ssh', '.gnupg', '.kube', '.docker', '.config', '.azure'} or component in CREDENTIAL_FILES:
            relative = '/'.join(components[index:])
            break
    if relative in CREDENTIAL_FILES or relative in CREDENTIAL_DIRS or relative.startswith(".gnupg/"):
        return True
    directory, _, name = relative.rpartition("/")
    return directory == ".ssh" and name not in SSH_NOT_SECRET and not name.endswith(".pub")


def _candidate_paths(text: str):
    skip_next = False
    for token in TOKEN_SPLIT.split(text):
        bare = token.strip("\"'`")
        if not bare:
            continue
        if skip_next:
            skip_next = False
            continue
        lowered = bare.lower()
        if lowered in IDENTITY_FLAGS:
            skip_next = True
            continue
        if lowered.startswith(("identityfile=", "--key=", "--cert=", "--private-key=")):
            continue
        if lowered.startswith("-i") and HOME_PREFIX.match(bare[2:]):
            continue
        yield bare


def credential_file_reference(text: str, *, include_dotenv: bool = True) -> bool:
    """Whether command text names a conventional credential store (not identity use)."""
    return any(_credential_path(path, include_dotenv) for path in _candidate_paths(text))


def credential_file_egress(text: str) -> bool:
    """A credential store reference combined with a network tool; never reads the file."""
    return has_network_tool(text) and credential_file_reference(text)
