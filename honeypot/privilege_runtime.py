# Privilege Runtime
# runs the documented sudo and find lab path inside the virtual filesystem, never a host shell

# Imports
from copy import copy
import shlex

from .cmdline import Stage
from .privilege_profile import BASE_USER, HIGH_USER, REVIEW_PATH, granted, parse_delegation
from .processes import ProcessError
from .tools import VFSTools
from .vfs import FSError


_SAVED = ('username', 'cwd', 'oldpwd', '_identity', '_process_session', 'shell_pid', 'last_background_pid')


def leave_shell(controller, session):
    parent = getattr(session, '_privilege_parent', None)
    if not parent:
        return False
    if controller.processes:
        controller.processes.close_session(session, include_parents=False)
    for key, value in parent.items():
        if value is None:
            session.__dict__.pop(key, None)
        else:
            setattr(session, key, value)
    session._privilege_parent = None
    session.last_exit_status = 0
    return True


async def run(controller, session, stage, stdin, *, piped=False, on_token=None):
    from .controller import StageResult
    if session.username != BASE_USER or not controller.filesystem:
        return None
    parsed = parse_delegation(stage.argv)
    if not parsed or stage.argv[1:] in (['-l'], ['-n', '-l'], ['-ln']):
        return None
    target, command = parsed
    def result(text='', status=0, flags=None):
        return StageResult(stage.raw, 'profile', text, ok=status == 0, exit_code=status, flags=flags or [])
    fs = controller.filesystem
    if (target != HIGH_USER or not granted(fs, session) or
            command[:2] != ['/usr/bin/find', REVIEW_PATH]):
        return result('sudo: command not permitted for this user', 1)
    elevated = copy(session)
    elevated.username, elevated._identity = HIGH_USER, None
    view = fs.vfs.for_realm(session.realm or 'unknown')
    if HIGH_USER not in view.passwd_users():
        return result('sudo: unknown user '+HIGH_USER, 1)
    # Bounded support for the grant's plain listing and -exec forms
    args = command[2:]
    if args[:2] not in (['-maxdepth', '0'], ['-maxdepth', '1']):
        return result('find: supported review depth is -maxdepth 0 or 1', 2)
    rest = args[2:]
    access = VFSTools(fs, elevated)
    try:
        access.resolve('/usr/bin/find', follow=True, want='x')
        access.resolve(REVIEW_PATH, follow=True, want="x")
    except FSError as exc:
        return result('find: '+str(exc), 1)
    if rest in ([], ['-print']):
        inner = Stage(argv=command, raw=shlex.join(command))
        observed, _ = await controller._run_stage(elevated, inner, stdin, piped=piped, on_token=on_token)
        observed.command = stage.raw; observed.flags.append('virtual_delegated_find')
        return observed
    if args[:2] != ['-maxdepth', '0'] or len(rest) < 3 or rest[0] != '-exec' or rest[-1] != ';':
        return result('find: unsupported review expression', 2)
    executable = rest[1:-1]
    if '{}' in executable:
        executable = [REVIEW_PATH if arg == '{}' else arg for arg in executable]
    if executable[0] in ('/bin/sh', '/bin/bash'):
        try:
            shell = access.resolve(executable[0], follow=True, want='x')
            if not shell.is_file:
                return result('find: '+executable[0]+': not a regular executable file', 1)
        except FSError as exc:
            return result('find: '+str(exc), 1)
        if executable[1:] in ([], ['-i']):
            if piped or stdin is not None:
                return result('sh: interactive review shell requires a terminal command', 2)
            # A new virtual shell owns its own jobs and PID, and the parent stays alive
            parent = {key: getattr(session, key, None) for key in _SAVED}
            parent_pid = getattr(session, 'shell_pid', 1)
            session._privilege_parent = parent
            session.username, session._identity = HIGH_USER, None
            session.__dict__.pop('_process_session', None)
            session.last_background_pid = None
            if controller.processes:
                try:
                    controller.processes.open_subshell(session, parent_pid, argv=executable)
                except BaseException as exc:
                    # Process allocation must not leave an elevated identity behind
                    for key, value in parent.items():
                        if value is None: session.__dict__.pop(key, None)
                        else: setattr(session, key, value)
                    session._privilege_parent = None
                    if isinstance(exc, ProcessError):
                        return result(str(exc), exc.code)
                    raise
            return result(flags=['virtual_privilege_shell'])
        if len(executable) == 3 and executable[1] == '-c':
            response = await controller.handle(elevated, executable[2], on_token=on_token)
            return result(response.output, getattr(elevated, 'last_exit_status', 0), ['virtual_delegated_find'])
        return result('sh: unsupported review shell options', 2)
    inner = Stage(argv=executable, raw=shlex.join(executable))
    observed, _ = await controller._run_stage(elevated, inner, stdin, piped=piped, on_token=on_token)
    observed.command = stage.raw; observed.flags.append('virtual_delegated_find')
    return observed
