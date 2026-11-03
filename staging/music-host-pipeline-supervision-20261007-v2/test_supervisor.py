#!/usr/bin/env python3
"""Real short inert Python child pipelines; no audio or device operations."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from garmin_host_audio_pipeline import PipelineSupervisor
ROWS=[]


def command(code):return [sys.executable,'-B','-u','-c',code]


def gone(pid):
    try:os.kill(pid,0);return False
    except ProcessLookupError:return True


class Tests(unittest.TestCase):
    def setUp(self):self.fd_before=len(list(Path('/proc/self/fd').iterdir()))
    def tearDown(self):self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),self.fd_before,'Parent FD leak')

    def supervisor(self,duration=1):
        return PipelineSupervisor(duration_seconds=duration,shutdown_grace_seconds=.15,kill_grace_seconds=.4,poll_seconds=.005)

    def verified(self,name,supervisor,result,extra=None):
        self.assertTrue(result['all_children_reaped'],result)
        self.assertTrue(result['all_owned_process_groups_exited'],result)
        self.assertTrue(result['all_owned_handles_closed'],result)
        self.assertFalse(result['CIND_restoration_verified'])
        pids=[record['pid'] for record in result['children'].values()]
        self.assertTrue(all(gone(pid) for pid in pids),'Leftover registered PID')
        ROWS.append({'case':name,'result':result,'all_registered_PIDs_gone':True,'parent_fd_count_before':self.fd_before,
                     'parent_fd_count_after':len(list(Path('/proc/self/fd').iterdir())),'extra':extra})

    def test01_natural_EOF_and_consumed_bytes(self):
        with tempfile.TemporaryDirectory(prefix='pipeline-normal-') as name:
            with self.supervisor() as sup:
                sink=sup.open_log('player',Path(name)/'sink.log')
                sup.start('capture',command("import sys;sys.stdout.buffer.write(b'abc'*100);sys.stdout.buffer.flush()"),stdout=subprocess.PIPE)
                sup.start('convert',command("import sys;raw=sys.stdin.buffer.read();sys.stdout.buffer.write(raw.upper());sys.stdout.buffer.flush()"),input_from='capture',stdout=subprocess.PIPE)
                sup.start('player',command("import sys;raw=sys.stdin.buffer.read();print(len(raw));sys.exit(0 if raw==b'ABC'*100 else 9)"),input_from='convert',stdout=sink)
                result=sup.wait()
            self.assertEqual((result['stop_reason'],result['returncode']),('natural_eof',0))
            self.assertEqual((Path(name)/'sink.log').read_text().strip(),'300')
            self.verified('all_zero_natural_EOF',sup,result,{'fixture_payload_bytes':300,'sink_consumed_all_expected':True})

    def test02_capture_failure_not_hidden_by_player_zero(self):
        with self.supervisor() as sup:
            sup.start('capture',command('import sys;sys.exit(7)'),stdout=subprocess.PIPE)
            sup.start('convert',command('import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'),input_from='capture',stdout=subprocess.PIPE)
            sup.start('player',command('import sys;sys.stdin.buffer.read();sys.exit(0)'),input_from='convert')
            result=sup.wait()
        self.assertEqual((result['stop_reason'],result['returncode'],result['failed_role']),('upstream_failure',1,'capture'))
        self.assertEqual(result['children']['capture']['natural_returncode'],7)
        self.verified('capture_nonzero_not_player_success',sup,result)

    def test03_conversion_failure_not_hidden_by_player_zero(self):
        with self.supervisor() as sup:
            sup.start('capture',command('import time;time.sleep(1.5)'),stdout=subprocess.PIPE)
            sup.start('convert',command('import sys;sys.exit(9)'),input_from='capture',stdout=subprocess.PIPE)
            sup.start('player',command('import sys;sys.stdin.buffer.read();sys.exit(0)'),input_from='convert')
            result=sup.wait()
        self.assertEqual((result['stop_reason'],result['failed_role']),('upstream_failure','convert'))
        self.assertEqual(result['children']['convert']['natural_returncode'],9)
        self.verified('conversion_nonzero_terminates_pipeline',sup,result)

    def test04_player_normal_early_exit_is_not_natural_EOF(self):
        with self.supervisor() as sup:
            sup.start('capture',command('import time;time.sleep(1.5)'),stdout=subprocess.PIPE)
            sup.start('convert',command('import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'),input_from='capture',stdout=subprocess.PIPE)
            sup.start('player',command('import sys;sys.exit(0)'),input_from='convert')
            result=sup.wait()
        self.assertEqual((result['stop_reason'],result['returncode']),('player_exit',0))
        self.assertEqual(result['children']['capture']['outcome'],'supervisor_stopped')
        self.verified('early_player_zero_intentional_upstream_stop',sup,result)

    def test05_no_read_backpressure_watchdog(self):
        with self.supervisor(.15) as sup:
            sup.start('capture',command("import os,time;time.sleep(.03);os.write(1,b'x'*524288);time.sleep(1.5)"),stdout=subprocess.PIPE)
            sup.start('convert',command('import time;time.sleep(1.5)'),input_from='capture',stdout=subprocess.PIPE)
            sup.start('player',command('import time;time.sleep(1.5)'),input_from='convert')
            result=sup.wait()
        self.assertEqual((result['stop_reason'],result['returncode']),('duration_watchdog',124))
        self.assertLess(result['elapsed_seconds'],1.2)
        self.verified('blocked_pipe_bounded_watchdog',sup,result,{'max_attempted_fixture_payload_bytes':524288,'persistent_payload_bytes':0})

    def test06_actual_SIGINT_with_cleanup_shield(self):
        with self.supervisor() as sup:
            sup.start('capture',command('import time;time.sleep(1.5)'),stdout=subprocess.PIPE)
            sup.start('player',command('import time;time.sleep(1.5)'),input_from='capture')
            timer=threading.Timer(.08,lambda:os.kill(os.getpid(),signal.SIGINT));timer.start()
            try:result=sup.wait()
            finally:timer.join()
        self.assertEqual((result['stop_reason'],result['returncode']),('user_interrupt',130))
        self.assertIn(signal.SIGINT,result['children']['player']['signals_sent'])
        self.assertIn(signal.SIGTERM,result['children']['capture']['signals_sent'])
        self.verified('parent_user_SIGINT_cleanup',sup,result)

    def test07_second_log_open_failure_reaps_started_child(self):
        with tempfile.TemporaryDirectory(prefix='pipeline-log-failure-') as name:
            sup=self.supervisor();log=sup.open_log('capture',Path(name)/'first.log')
            sup.start('capture',command('import time;time.sleep(1.5)'),stdout=subprocess.PIPE,stderr=log)
            with self.assertRaises(FileNotFoundError):sup.open_log('convert',Path(name)/'missing-parent'/'second.log')
            self.assertTrue(log.closed);self.assertEqual(sup.result['stop_reason'],'setup_failure')
            self.verified('staged_second_log_open_failure',sup,sup.result)

    def test08_downstream_Popen_failure_closes_all_owned_pipes_logs(self):
        with tempfile.TemporaryDirectory(prefix='pipeline-start-failure-') as name:
            sup=self.supervisor();log=sup.open_log('capture',Path(name)/'first.log')
            sup.start('capture',command('import time;time.sleep(1.5)'),stdout=subprocess.PIPE,stderr=log)
            with self.assertRaises(FileNotFoundError):sup.start('convert',['/nonexistent/inert-test-command'],input_from='capture',stdout=subprocess.PIPE)
            self.assertEqual(sup.result['stop_reason'],'setup_failure')
            self.verified('staged_Popen_failure',sup,sup.result)

    def test09_unresponsive_child_escalates_KILL(self):
        with tempfile.TemporaryDirectory(prefix='pipeline-kill-') as name:
            ready=Path(name)/'ready'
            with self.supervisor(.18) as sup:
                code="import signal,time;from pathlib import Path;signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN);Path("+repr(str(ready))+").write_text('ready');time.sleep(1.5)"
                sup.start('player',command(code))
                result=sup.wait()
            self.assertTrue(ready.exists());self.assertTrue(result['children']['player']['kill_escalated'])
            self.assertIn(signal.SIGKILL,result['children']['player']['signals_sent'])
            self.assertTrue(result['player_force_killed']);self.assertFalse(result['CIND_restoration_verified'])
            self.verified('unresponsive_registered_child_KILL',sup,result)

    def test10_owned_player_descendant_pipe_is_stopped_and_reaped(self):
        with tempfile.TemporaryDirectory(prefix='pipeline-descendant-') as name:
            pidfile=Path(name)/'child-pid';done=Path(name)/'reaped'
            childcode='import time;time.sleep(1.5)'
            parentcode="""import signal,subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,'-B','-u','-c',CHILD])
Path(PIDFILE).write_text(str(child.pid))
def stop(number,frame):
 child.wait(timeout=.5)
 Path(DONE).write_text('reaped')
 sys.exit(0)
signal.signal(signal.SIGINT,stop)
time.sleep(1.5)
child.wait()
""".replace('CHILD',repr(childcode)).replace('PIDFILE',repr(str(pidfile))).replace('DONE',repr(str(done)))
            with self.supervisor(.18) as sup:
                sup.start('player',command(parentcode),stdout=subprocess.PIPE)
                result=sup.wait()
            self.assertTrue(pidfile.exists());pid=int(pidfile.read_text());self.assertTrue(done.exists());self.assertTrue(gone(pid))
            self.assertFalse(result['player_force_killed'])
            self.verified('own_session_SIGINT_includes_descendant',sup,result,{'descendant_pid':pid,'descendant_PID_gone':True,'parent_reaped_descendant':True})

    def test11_input_pipe_consumed_exactly_once(self):
        with self.supervisor() as sup:
            capture=sup.start('capture',command('import time;time.sleep(1.5)'),stdout=subprocess.PIPE)
            sup.start('convert',command('import sys;sys.stdin.buffer.read()'),input_from='capture',stdout=subprocess.PIPE)
            self.assertTrue(capture.stdout.closed)
            with self.assertRaisesRegex(ValueError,'not an open PIPE'):sup.start('second_convert',command('pass'),input_from='capture')
        self.assertEqual(sup.result['stop_reason'],'setup_failure')
        self.verified('input_from_parent_handle_single_transfer',sup,sup.result)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    raw=(ROOT/'scripts/garmin_host_audio_pipeline.py').read_bytes()
    proof={'schema':'music-host-pipeline-supervision-actual-tests/v2','all_assigned_checks_passed':result.wasSuccessful(),
           'methods':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
           'failure_details':[str(x) for x in result.failures+result.errors],'cases':ROWS,
           'source_bytes':len(raw),'source_sha256':hashlib.sha256(raw).hexdigest(),
           'max_child_fixture_seconds':1.5,'actual_audio_DBus_PCM_BlueZ_services_devices_maps':False,
           'native_guest_firmware_or_audio_admission':False,'persistent_pipe_fixture_bytes':0}
    (HERE/'host-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    sys.exit(0 if result.wasSuccessful() else 1)
