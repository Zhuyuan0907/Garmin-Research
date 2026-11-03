#!/usr/bin/env python3
"""Bounded supervision of registered host children; no audio/device APIs.

All registered children use their own sessions. Normal cleanup keeps the
existing signal convention: SIGINT for the player, SIGTERM for upstream.
This class owns only its opened logs and the PIPE handles made by Popen.
"""
import math
import os
import signal
import subprocess
import threading
import time


class PipelineSupervisor:
    def __init__(self, *, duration_seconds, shutdown_grace_seconds=5.0,
                 kill_grace_seconds=2.0, poll_seconds=0.05, max_children=8):
        for name, value in (('duration_seconds', duration_seconds),
                            ('shutdown_grace_seconds', shutdown_grace_seconds),
                            ('kill_grace_seconds', kill_grace_seconds), ('poll_seconds', poll_seconds)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(name + ' must be positive and finite')
        if type(max_children) is not int or not 1 <= max_children <= 16:
            raise ValueError('max_children must be 1..16')
        self.duration_seconds = duration_seconds
        self.shutdown_grace_seconds = shutdown_grace_seconds
        self.kill_grace_seconds = kill_grace_seconds
        self.poll_seconds = poll_seconds
        self.max_children = max_children
        self.started = time.monotonic()
        self.children = {}
        self.logs = {}
        self.result = None
        self.player_role = 'player'
        self._waiting = False
        self._cleanup_errors = []

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if self.result is None:
            if kind is KeyboardInterrupt:
                self._finish('user_interrupt', 130, error='KeyboardInterrupt during setup')
            elif kind is not None:
                self._finish('setup_failure' if not self._waiting else 'supervision_error', 1,
                             error=repr(value))
            else:
                self._finish('context_exit_without_wait', 1)
        return False

    def _require_open(self):
        if self.result is not None:
            raise RuntimeError('Pipeline is already closed')

    @staticmethod
    def _role(role):
        if not isinstance(role, str) or not role or len(role) > 64:
            raise ValueError('A nonempty role name of <=64 characters is required')

    def open_log(self, role, path):
        """Open a NEW binary log; register immediately for staged-failure cleanup."""
        self._require_open()
        try:
            self._role(role)
            if role in self.logs or len(self.logs) >= self.max_children:
                raise ValueError('Duplicate role log or log limit')
            handle = open(path, 'xb')
            self.logs[role] = handle
            return handle
        except KeyboardInterrupt:
            self._finish('user_interrupt', 130, error='KeyboardInterrupt opening log')
            raise
        except Exception as exc:
            self._finish('setup_failure', 1, error=repr(exc))
            raise

    def start(self, role, command, *, input_from=None, stdin=None, stdout=None,
              stderr=None, stop_signal=None):
        """Start one child. input_from transfers an upstream stdout pipe to it.

        After the downstream Popen succeeds, close that parent pipe handle.
        Passed external handles are borrowed; opened logs/Popen PIPEs are owned.
        """
        self._require_open()
        try:
            self._role(role)
            if role in self.children or len(self.children) >= self.max_children:
                raise ValueError('Duplicate child role or child limit')
            if isinstance(command, (str, bytes)) or not command:
                raise ValueError('command must be a nonempty argument sequence')
            borrowed = None
            if input_from is not None:
                if stdin is not None or input_from not in self.children:
                    raise ValueError('Invalid input_from or conflicting stdin')
                borrowed = self.children[input_from]['process'].stdout
                if borrowed is None or borrowed.closed:
                    raise ValueError('Upstream stdout is not an open PIPE')
                stdin = borrowed
            chosen_signal = stop_signal if stop_signal is not None else (signal.SIGINT if role == self.player_role else signal.SIGTERM)
            if chosen_signal not in (signal.SIGINT, signal.SIGTERM):
                raise ValueError('stop_signal must be SIGINT or SIGTERM')
            child = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
            self.children[role] = {'process': child, 'stop_signal': chosen_signal,
                                   'natural_returncode': None, 'signals_sent': [],
                                   'leader_signals_sent': [], 'kill_escalated': False}
            if borrowed is not None:
                borrowed.close()
            return child
        except KeyboardInterrupt:
            self._finish('user_interrupt', 130, error='KeyboardInterrupt starting child')
            raise
        except Exception as exc:
            self._finish('setup_failure', 1, error=repr(exc))
            raise

    def wait(self, player_role='player'):
        """Poll every role, so an upstream failure cannot hide behind player0.

        natural_eof means all registered children naturally returned0; it is
        not proof that an opaque player consumed every byte. player_exit means
        player0 while upstream is still running, intentionally stopped here.
        A nonzero observed before our stop signals is always an independent
        child failure. duration_watchdog uses a monotonic wall deadline.
        """
        self._require_open()
        self._waiting = True
        self.player_role = player_role
        if player_role not in self.children:
            return self._finish('setup_failure', 1, error='Missing player role')
        self.children[player_role]['stop_signal'] = signal.SIGINT
        try:
            while True:
                codes = self._poll()
                upstream_failure = next((role for role, code in codes.items()
                                         if role != player_role and code not in (None, 0)), None)
                if upstream_failure is not None:
                    return self._finish('upstream_failure', 1, failed_role=upstream_failure)
                player_code = codes[player_role]
                if player_code is not None:
                    if player_code:
                        return self._finish('player_failure', player_code if player_code > 0 else 1,
                                            failed_role=player_role)
                    reason = 'natural_eof' if all(code == 0 for code in codes.values()) else 'player_exit'
                    return self._finish(reason, 0)
                if time.monotonic() - self.started >= self.duration_seconds:
                    return self._finish('duration_watchdog', 124)
                time.sleep(self.poll_seconds)
        except KeyboardInterrupt:
            return self._finish('user_interrupt', 130)
        except Exception as exc:
            self._finish('supervision_error', 1, error=repr(exc))
            raise

    def _poll(self):
        codes = {}
        for role, record in self.children.items():
            code = record['process'].poll()
            codes[role] = code
            if code is not None and not record['leader_signals_sent']:
                record['natural_returncode'] = code
        return codes

    def _close_owned_handles(self):
        handles = list(self.logs.values())
        for record in self.children.values():
            child = record['process']
            handles.extend(handle for handle in (child.stdin, child.stdout, child.stderr) if handle is not None)
        for handle in handles:
            if not handle.closed:
                try:
                    handle.close()
                except Exception as exc:
                    self._cleanup_errors.append('close: ' + repr(exc))
        return all(handle.closed for handle in handles)

    @staticmethod
    def _group_alive(record):
        try:
            os.killpg(record['process'].pid, 0)
            return True
        except ProcessLookupError:
            return False

    def _signal(self, record, number):
        child = record['process']
        leader_running = child.poll() is None
        try:
            # Popen created exactly this new session/group. Include owned
            # player descendants such as aplay; never target a service group.
            os.killpg(child.pid, number)
            record['signals_sent'].append(int(number))
            if leader_running:
                record['leader_signals_sent'].append(int(number))
        except ProcessLookupError:
            child.poll()
        except Exception as exc:
            self._cleanup_errors.append('signal: ' + repr(exc))

    def _finish(self, reason, code, *, failed_role=None, error=None):
        # A second Ctrl+C must not interrupt registered-child reaping.
        previous = None
        if threading.current_thread() is threading.main_thread():
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            return self._finish_impl(reason, code, failed_role=failed_role, error=error)
        finally:
            if previous is not None:
                signal.signal(signal.SIGINT, previous)

    def _finish_impl(self, reason, code, *, failed_role=None, error=None):
        if self.result is not None:
            return self.result
        initial_codes = self._poll()
        # Catch independent exits at the cleanup boundary before attributing
        # later signal/BrokenPipe exits to our deliberate teardown.
        if reason in ('natural_eof', 'player_exit'):
            independent = next((role for role, rc in initial_codes.items()
                                if role != self.player_role and rc not in (None, 0)), None)
            if independent is not None:
                reason, code, failed_role = 'upstream_failure', 1, independent
        order = list(reversed(list(self.children)))
        if self.player_role in order:
            order.remove(self.player_role); order.insert(0, self.player_role)
        for role in order:
            self._signal(self.children[role], self.children[role]['stop_signal'])
        # A shared deadline bounds shutdown for all roles, not N*grace.
        deadline = time.monotonic() + self.shutdown_grace_seconds
        for role in order:
            child = self.children[role]['process']
            try:
                child.wait(timeout=max(0.001, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                self.children[role]['kill_escalated'] = True
                self._signal(self.children[role], signal.SIGKILL)
            except Exception as exc:
                self._cleanup_errors.append('wait: ' + repr(exc))
        # A leader can exit while one of its descendants retains a pipe.
        # Give the entire owned group the same grace, then kill only that group.
        while time.monotonic() < deadline and any(self._group_alive(record) for record in self.children.values()):
            time.sleep(min(self.poll_seconds, max(0.001, deadline-time.monotonic())))
        for record in self.children.values():
            if self._group_alive(record):
                record['kill_escalated'] = True
                self._signal(record, signal.SIGKILL)
        deadline = time.monotonic() + self.kill_grace_seconds
        for role in order:
            child = self.children[role]['process']
            if child.poll() is None:
                try:
                    child.wait(timeout=max(0.001, deadline-time.monotonic()))
                except Exception as exc:
                    self._cleanup_errors.append('final_reap: ' + repr(exc))
        while time.monotonic() < deadline and any(self._group_alive(record) for record in self.children.values()):
            time.sleep(min(self.poll_seconds, max(0.001, deadline-time.monotonic())))
        groups_exited = all(not self._group_alive(record) for record in self.children.values())
        handles_closed = self._close_owned_handles()
        rows = {}
        for role, record in self.children.items():
            child = record['process']; rc = child.poll()
            natural = record['natural_returncode']
            outcome = ('supervisor_stopped' if record['leader_signals_sent'] else
                       'natural_success' if natural == 0 else
                       'natural_failure' if natural is not None else 'reaping_incomplete')
            rows[role] = {'pid': child.pid, 'returncode': rc, 'natural_returncode': natural,
                          'outcome': outcome, 'signals_sent': record['signals_sent'],
                          'leader_signals_sent': record['leader_signals_sent'],
                          'kill_escalated': record['kill_escalated'],
                          'owned_process_group_exited': not self._group_alive(record)}
        reaped = all(row['returncode'] is not None for row in rows.values())
        if not reaped or not groups_exited or not handles_closed or self._cleanup_errors:
            reason, code = 'cleanup_failure', 1
        self.result = {'schema': 'garmin-host-pipeline-result/v1', 'returncode': code,
                       'stop_reason': reason, 'failed_role': failed_role, 'error': error,
                       'player_role': self.player_role, 'player_returncode': rows.get(self.player_role, {}).get('returncode'),
                       'children': rows, 'all_children_reaped': reaped,
                       'all_owned_process_groups_exited': groups_exited,
                       'all_owned_handles_closed': handles_closed, 'cleanup_errors': self._cleanup_errors,
                       'elapsed_seconds': time.monotonic()-self.started,
                       'opaque_child_content_or_call_state_verified': False,
                       'player_force_killed': rows.get(self.player_role, {}).get('kill_escalated', False),
                       'CIND_restoration_verified': False}
        return self.result
