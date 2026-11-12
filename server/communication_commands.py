"""Recognize literal outbound commands, without executing inspected input.

This is a bounded shell/inline-code recognizer, not an interpreter. In particular,
it does not resolve aliases, load scripts or follow imports.
"""
import re
import shlex


# Keep operators distinct from quoted arguments (shlex alone loses that detail).
TOKEN = re.compile(r'''[ \t\r]+|\#[^\n]*|[;&|()\n]+|[<>]+|(?:[^\s;&|()<>\\'"#]+|\\[\s\S]|'[^']*'|"(?:\\[\s\S]|[^"\\])*")+''')
ASSIGNMENT = re.compile(r'[A-Za-z_][A-Za-z_0-9]*=.*', re.S)
JS_LITERAL = re.compile(r'''//[^\n]*|/\*[\s\S]*?\*/|'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"|`(?:\\[\s\S]|[^`\\])*`''')
GMAIL_SEND = re.compile(r'\busers\s*\.\s*(?:messages|drafts)\s*\.\s*send\s*\(')


def _segments(command):
    """Yield literal argument vectors; never treat quoted separators as operators."""
    args, offset, redirect = [], 0, False
    for match in TOKEN.finditer(command):
        if match.start() != offset:
            return  # Unsupported/unbalanced shell syntax.
        offset = match.end()
        raw = match.group()
        if raw.startswith('#') or raw[0] in ' \t\r':
            continue
        if raw[0] in ';&|()\n':
            if args:
                yield args
            args, redirect = [], False
        elif raw[0] in '<>':
            if raw in ('<<', '<<<'):
                return  # Here-documents/strings need a full shell parser.
            if args and args[-1].isdigit():
                args.pop()  # Redirection file descriptor, not a command argument.
            redirect = True
        else:
            try:
                word, = shlex.split(raw)
            except ValueError:
                return
            if redirect:
                redirect = False
            else:
                args.append(word)
    if offset == len(command) and args:
        yield args


def _unwrap(args):
    """Common literal execution wrappers; command -v/-V are lookups."""
    args = list(args)
    while args:
        if ASSIGNMENT.fullmatch(args[0]):
            args.pop(0)
            continue
        exe = args[0].rsplit('/', 1)[-1]
        if exe not in {'env', 'sudo', 'command', 'exec', 'nohup'}:
            break
        args.pop(0)
        while args and args[0].startswith('-'):
            option = args.pop(0)
            if option == '--':
                break
            if exe == 'command' and ('v' in option or 'V' in option):
                return []
            if option in {'--help', '--version'}:
                return []
            if (exe == 'env' and option in {'-u', '--unset', '-C', '--chdir'}) or (
                    exe == 'sudo' and option in {'-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T'}):
                if args:
                    args.pop(0)
        # Remaining assignments/wrappers are handled on the next iteration.
    return args


def _node_source(args):
    # Stop at the script operand or --: subsequent -e flags are script arguments.
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == '--' or not arg.startswith('-'):
            return None
        if arg in {'-e', '--eval', '-p', '--print'}:
            return args[index + 1] if index + 1 < len(args) else None
        if arg.startswith(('--eval=', '--print=')):
            return arg.split('=', 1)[1]
        if arg.startswith(('-e', '-p')) and len(arg) > 2:
            return arg[2:]
        if arg in {'-r', '--require', '--import', '--loader', '--experimental-loader', '--input-type'}:
            index += 1
        index += 1
    return None


def _cli_send(exe, args):
    # Global options may precede the command path. Message bodies, query text and
    # other option values must not become verbs just because they contain send.
    args = list(args)
    while args and args[0].startswith('-'):
        option = args.pop(0)
        if option == '--':
            break
        if option in {'--account', '--client', '--format'}:
            if not args:
                return False
            args.pop(0)
        elif option in {'--json', '--plain', '--no-input'} or option.startswith(
                ('--account=', '--client=', '--format=')):
            continue
        else:
            return False
    routes = (('gmail', 'send'), ('gmail', 'send-message'), ('gmail', 'messages', 'send'),
              ('gmail', 'drafts', 'send')) if exe == 'gog' else (
                  ('gmail', '+send'), ('gmail', 'users', 'messages', 'send'),
                  ('gmail', 'users', 'drafts', 'send'))
    return any(tuple(args[:len(route)]) == route for route in routes)


def external_communication(command, *, depth=0):
    if depth > 4:
        return False
    for words in _segments(command):
        args = _unwrap(words)
        # Literal commands following common shell control keywords.
        if args and args[0] in {'if', 'then', 'elif', 'else', 'do', '!', '{'}:
            args = _unwrap(args[1:])
        if not args:
            continue
        exe, rest = args[0].rsplit('/', 1)[-1], args[1:]
        if exe in {'mail', 'mailx', 'sendmail'}:
            return True
        if exe in {'gog', 'gws'} and _cli_send(exe, rest):
            return True
        if exe == 'curl' and any(re.match(r'^smtps?://', arg) or
                                 re.match(r'^--url=smtps?://', arg) for arg in rest):
            return True
        if exe in {'sh', 'bash', 'zsh', 'dash', 'ksh'}:
            for index, arg in enumerate(rest):
                if arg == '--' or not arg.startswith('-'):
                    break
                if 'c' in arg[1:] and index + 1 < len(rest):
                    if external_communication(rest[index + 1], depth=depth + 1):
                        return True
                    break
        if exe in {'node', 'nodejs'}:
            source = _node_source(rest)
            # Only inspect evaluated code, excluding comments and string examples.
            if source and GMAIL_SEND.search(JS_LITERAL.sub(' ', source)):
                return True
    return False
