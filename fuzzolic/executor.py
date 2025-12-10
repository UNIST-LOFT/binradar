#!/usr/bin/python3

import os
import sys
import json
import glob
import filecmp
import subprocess
import time
import signal
import configparser
import re
import shutil
import functools
import tempfile
import random
import ctypes
import resource
import errno
import struct
import select
import threading

import minimizer_qsym
import minimizer
import logger

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SOLVER_SMT_BIN = SCRIPT_DIR + '/../solver/build/solver-smt'
SOLVER_FUZZY_BIN = SCRIPT_DIR + '/../solver/build/solver-fuzzy'
TRACER_BIN = SCRIPT_DIR + '/../tracer/build/x86_64-linux-user/qemu-x86_64'

if 'AFL_PATH' not in os.environ:
    AFL_PATH = SCRIPT_DIR + '/../../AFLplusplus/'
else:
    AFL_PATH = os.environ['AFL_PATH']

SOLVER_WAIT_TIME_AT_STARTUP = 0.0010
SOLVER_TIMEOUT = 1000
SHUTDOWN = False

RUNNING_PROCESSES = []
MAX_VIRTUAL_MEMORY = 16 * 1024 * 1024 * 1024 # 16 GB

def setlimits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, MAX_VIRTUAL_MEMORY))

class ForkserverRunResult:
    returncode: int
    status: int
    duration: float
    child_pid: int
    timed_out: bool = False
    def __init__(self, returncode: int, status: int, duration: float, child_pid: int, timed_out: bool):
        self.returncode = returncode
        self.status = status
        self.duration = duration
        self.child_pid = child_pid
        self.timed_out = timed_out


class ForkserverTracerError(RuntimeError):
    pass

class ForkserverTracerTimeout(ForkserverTracerError):
    pass

class ForkserverTracer:
    _HANDSHAKE_EXPECTED = 0x41464C00
    _CTRL_FD = 198

    def __init__(self, args, env, cwd, debug, testcase_from_stdin, logger, session_log):
        if debug == 'gdb_tracer':
            raise ForkserverTracerError(
                'Forkserver mode does not support --debug gdb_tracer.')
        if testcase_from_stdin:
            raise ForkserverTracerError(
                'Forkserver mode requires a file-based testcase (@@).')

        self._cmd = args # self._build_cmd(tracer_bin, binary, binary_args, debug)
        self._env = env
        self._cwd = cwd
        self._logger = logger
        self.proc = None
        self._ctl_w = None
        self._status_r = None
        self._stderr_thread = None
        self._session_log = session_log
        self._run_log = None
        self._log_lock = threading.Lock()
        self._last_run_was_killed = False
        self._timeout = 20
        self._handshake_timeout = 30

    def start(self):
        ctl_r, ctl_w = os.pipe()
        st_r, st_w = os.pipe()
        ctrl_fd = self._CTRL_FD
        status_fd = self._CTRL_FD + 1
        os.dup2(ctl_r, ctrl_fd)
        os.dup2(st_w, status_fd)
        os.close(ctl_r)
        os.close(st_w)
        os.set_inheritable(ctrl_fd, True)
        os.set_inheritable(status_fd, True)

        self.proc = subprocess.Popen(
            self._cmd,
            stdout=None,
            stderr=self._session_log,
            stdin=None,
            cwd=self._cwd,
            env=self._env,
            pass_fds=(ctrl_fd, status_fd),
            preexec_fn=setlimits)

        os.close(ctrl_fd)
        os.close(status_fd)
        self._ctl_w = ctl_w
        self._status_r = st_r

        # self._stderr_thread = threading.Thread(
        #     target=self._pump_stderr, daemon=True)
        # self._stderr_thread.start()

        self._logger.info('[forkserver] waiting for handshake')
        banner = self._read_u32(self._handshake_timeout)
        if banner != self._HANDSHAKE_EXPECTED:
            raise ForkserverTracerError(
                f'Unexpected forkserver banner {hex(banner)}')

        self._write_u32(self._HANDSHAKE_EXPECTED ^ 0xFFFFFFFF)
        ack = self._read_u32(self._handshake_timeout)
        if ack != self._HANDSHAKE_EXPECTED:
            raise ForkserverTracerError('Forkserver handshake failed')
        self._logger.info('[forkserver] handshake complete')

    def run_testcase(self, run_dir):
        run_log = open(os.path.join(run_dir, 'tracer.log'), 'wb', buffering=0)
        start = time.time()
        with self._log_lock:
            self._run_log = run_log

        was_killed = 1 if self._last_run_was_killed else 0
        self._last_run_was_killed = False
        self._write_u32(was_killed)

        child_pid = self._read_u32(self._timeout)
        timed_out = False
        try:
            status = self._read_u32(self._timeout)
        except ForkserverTracerTimeout:
            timed_out = True
            self._logger.warning(
                '[forkserver] child %d timed out, sending SIGKILL', child_pid)
            try:
                os.kill(child_pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            time.sleep(0.5)
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._last_run_was_killed = True
            status = self._read_u32(5)

        duration = time.time() - start
        result = ForkserverRunResult(
            returncode=self._decode_status(status),
            status=status,
            duration=duration,
            child_pid=child_pid,
            timed_out=timed_out,
        )

        with self._log_lock:
            run_log.flush()
            run_log.close()
            self._run_log = None

        return result

    def stop(self):
        if self._ctl_w is not None:
            os.close(self._ctl_w)
            self._ctl_w = None
        if self._status_r is not None:
            os.close(self._status_r)
            self._status_r = None
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        # if self._stderr_thread:
        #     self._stderr_thread.join(timeout=2)
        if self._session_log:
            self._session_log.close()
            self._session_log = None

    def _build_cmd(self, tracer_bin, binary, binary_args, debug):
        cmd = [tracer_bin]
        cmd.append(binary)
        if binary_args:
            cmd.extend(binary_args)
        return cmd

    def _pump_stderr(self):
        try:
            while True:
                data = self.proc.stderr.read(4096)
                if not data:
                    break
                
                if self._session_log:
                    self._session_log.write(data)
                
                with self._log_lock:
                    if self._run_log:
                        self._run_log.write(data)
        except (ValueError, OSError) as e:
            if self._logger:
                self._logger.debug(f"Stderr pump stopped: {e}")
        except Exception as e:
            if self._logger:
                self._logger.error(f"Stderr pump error: {e}")

    def _write_u32(self, val: int):
        try:
            data = struct.pack('<I', val)
            os.write(self._ctl_w, data)
        except BrokenPipeError:
            raise ForkserverTracerError("Forkserver pipe broken (write)")

    def _read_u32(self, timeout: float) -> int:
        rlist, _, _ = select.select([self._status_r], [], [], timeout)
        if not rlist:
            raise ForkserverTracerTimeout("Read timed out")
        
        data = self._read_exact(4)
        return struct.unpack('<I', data)[0]

    def _read_exact(self, length: int) -> bytes:
        data = b''
        while len(data) < length:
            try:
                chunk = os.read(self._status_r, length - len(data))
                if not chunk:
                    raise ForkserverTracerError("Forkserver pipe closed unexpectedly (EOF)")
                data += chunk
            except BlockingIOError:
                continue
        return data

    def _decode_status(self, status: int) -> int:
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            return -os.WTERMSIG(status)
        return 0


class Executor(object):

    def __init__(self, binary, input, output_dir, binary_args,
                 debug=None, afl=None, timeout=0, fuzzy=False,
                 optimistic_solving=False,
                 memory_slice_reasoning=False,
                 address_reasoning=False,
                 fuzz_expr=False,
                 input_fixed_name=None,
                 use_smt_if_empty=False,
                 use_symbolic_models=False,
                 keep_run_dirs=False,
                 single_path=False,
                 check_input=False,
                 binradar_entrypoint=""):

        if not os.path.exists(binary):
            sys.exit('ERROR: invalid binary')
        self.binary = os.path.abspath(binary)

        self.binary_args = binary_args
        self.testcase_from_stdin = '@@' not in self.binary_args
        
        self.binradar_entrypoint = binradar_entrypoint
        self._forkserver = None
        self._forkserver_session_log = None

        if not os.path.exists(output_dir):
            sys.exit('ERROR: invalid working directory')
        self.output_dir = os.path.abspath(output_dir)
        logger.set_file(os.path.join(self.output_dir, 'fuzzolic.log'))        

        if not os.path.exists(input):
            sys.exit('ERROR: invalid input')
        self.input = os.path.abspath(input)

        self.global_bitmap = self.__get_root_dir() + '/branch_bitmap'
        if False and os.path.exists(self.__get_root_dir() + '/../branch_bitmap'):
            os.system("cp " + self.__get_root_dir() + '/../branch_bitmap'  + " "+ self.global_bitmap)
            # os.system("cp " + self.__get_root_dir() + '/../context_bitmap'  + " " + self.__get_root_dir() + '/context_bitmap')
            logger.info("Importing from parent")
        else:
            os.system("touch " + self.global_bitmap)

        if afl:
            if not os.path.exists(afl):
                sys.exit('ERROR: invalid AFL workdir')
            self.afl = os.path.abspath(afl)
            self.minimizer = minimizer_qsym.TestcaseMinimizer(
                [binary] + binary_args, AFL_PATH, output_dir, True, input_fixed_name)
            #  self.minimizer = minimizer.TestcaseMinimizer([binary] + binary_args, self.global_bitmap)
        else:
            self.afl = None
            if minimizer_qsym.is_afl_showmap_available():
                self.minimizer = minimizer_qsym.TestcaseMinimizer(
                    [binary] + binary_args, AFL_PATH, output_dir, True, input_fixed_name)
            else:
                self.minimizer = minimizer.TestcaseMinimizer([binary] + binary_args, self.global_bitmap)

        self.afl_processed_testcases = set()
        self.afl_alt_processed_testcases = set()
        self.timeout_testcases = set()

        self.debug = debug
        self.tick_count = 0
        self.timeout = timeout
        self.fuzzy = fuzzy
        self.optimistic_solving = optimistic_solving
        self.memory_slice_reasoning = memory_slice_reasoning
        self.address_reasoning = address_reasoning
        self.fuzz_expr = fuzz_expr
        self.input_fixed_name = input_fixed_name
        self.keep_run_dirs = keep_run_dirs
        self.single_path = single_path
        self.check_input = check_input

        self.__load_config()
        self.__warning_log = set()

        self.libc = ctypes.CDLL("libc.so.6")

        self.use_smt_if_empty = False
        if self.fuzzy and use_smt_if_empty:
            self.use_smt_if_empty = True
            self.global_alt_bitmap = self.__get_root_dir() + '/branch_alt_bitmap'
            os.system("touch " + self.global_alt_bitmap)
        else:
            self.global_alt_bitmap = None

        if use_symbolic_models:
            plt_info_file = self.__get_root_dir() + "/plt_info.txt"
            p = subprocess.Popen(
                                [
                                    SCRIPT_DIR + "/find_models_addrs.py",
                                    "-o", plt_info_file,
                                    binary
                                ],
                                # stderr=subprocess.DEVNULL,
                                # stdin=subprocess.DEVNULL,
                                )
            p.wait()
            self.plt_info = plt_info_file
        else:
            self.plt_info = None

    def __load_config(self):
        config = {}
        if not os.path.exists(self.binary + '.fuzzolic'):
            logger.info(
                'Configuration file for %s is missing. Using default configuration.' % self.binary)
            config['SYMBOLIC_INJECT_INPUT_MODE'] = "FROM_FILE"
        else:
            with open(self.binary + '.fuzzolic', 'r') as cfgfile:
                for line in cfgfile:
                    line = line.rstrip('\n').strip()
                    if line.startswith('#') or '=' not in line:
                        continue
                    pivot = line.index('=')
                    key = line[:pivot]
                    value = line[pivot + 1:]
                    config[key] = value
        self.config = config

    def __get_root_dir(self):
        if not os.path.exists(self.output_dir):
            os.system('mkdir ' + self.output_dir)
        return self.output_dir

    def __get_queue_dir(self):
        queue_dir = self.__get_root_dir() + '/queue'
        if not os.path.exists(queue_dir):
            os.system('mkdir ' + queue_dir)
        return queue_dir

    def __get_testcases_dir(self):
        testcases_dir = self.__get_root_dir() + '/tests'
        if not os.path.exists(testcases_dir):
            os.system('mkdir ' + testcases_dir)
        return testcases_dir

    def __get_timeout_dir(self):
        testcases_dir = self.__get_root_dir() + '/timeout'
        if not os.path.exists(testcases_dir):
            os.system('mkdir ' + testcases_dir)
        return testcases_dir

    def __get_run_dir(self):
        root_dir = self.__get_root_dir()

        # status file
        status_file = root_dir + '/status'
        if not os.path.exists(status_file):
            os.system('echo 0 > ' + status_file)

        # get id for next run
        with open(status_file, 'r') as sf:
            run_id = sf.read()
            run_id = int(run_id)
            assert(run_id >= 0)

        # run dir
        run_dir = root_dir + '/fuzzolic-%05d' % run_id
        os.system('mkdir ' + run_dir)

        # increment id for the next run
        with open(status_file, 'w') as sf:
            sf.write(str(run_id + 1))

        return run_dir, run_id

    def get_solver_bin(self, force_smt=False):
        if self.fuzzy and not force_smt:
            logger.info("Using Fuzzy-SAT solver")
            return SOLVER_FUZZY_BIN
        else:
            logger.info("Using SMT solver")
            return SOLVER_SMT_BIN

    def fuzz_one(self, testcase, target, force_smt=False):

        global RUNNING_PROCESSES
        self.__check_shutdown_flag()

        run_dir, run_id = self.__get_run_dir()

        os.system("cp " + testcase + " " + run_dir)
        #testcase = run_dir + "/" + os.path.basename(testcase)

        logger.info('\nRunning directory: %s' % run_dir)

        env = os.environ.copy()
        for c in self.config:
            env[c] = self.config[c]
        if self.testcase_from_stdin:
            env['SYMBOLIC_INJECT_INPUT_MODE'] = 'READ_FD_0'
        else:
            env['SYMBOLIC_TESTCASE_NAME'] = testcase
            logger.info(f"SYMBOLIC_TESTCASE_NAME: {testcase}")
        if self.debug == 'coverage':
            env['COVERAGE_TRACER'] = self.output_dir + '/fuzzolic-bitmap'
            env['COVERAGE_TRACER_LOG'] = self.output_dir + \
                '/fuzzolic-coverage.out'

        # generate random shm keys
        env['EXPR_POOL_SHM_KEY'] = hex(random.getrandbits(32))
        env['QUERY_SHM_KEY'] = hex(random.getrandbits(32))
        env['BITMAP_SHM_KEY'] = hex(random.getrandbits(32))
        if self.timeout > 0:
            # logger.info("Setting solving timeout: %s" % self.timeout)
            env['SOLVER_TIMEOUT'] = str(self.timeout)

        if self.fuzz_expr:
            env['DEBUG_FUZZ_EXPR'] = "1"
            assert('DEBUG_FUZZ_EXPR_IDX' in env)
            assert('DEBUG_FUZZ_EXPR_VALUE' in env)

        self.__check_shutdown_flag()

        _, global_bitmap_pre_run = tempfile.mkstemp()
        os.system("cp " + self.global_bitmap + " " + global_bitmap_pre_run)

        p_solver_log_name = run_dir + '/solver.log'
        p_solver_log = open(p_solver_log_name, 'w')

        # launch solver
        if self.debug != 'no_solver' and self.debug != 'coverage':
            p_solver_args = []
            p_solver_args += ['stdbuf', '-o0']  # No buffering on stdout
            p_solver_args += [self.get_solver_bin(force_smt)]
            p_solver_args += ['-i', testcase]
            p_solver_args += ['-t', self.__get_testcases_dir()]
            p_solver_args += ['-o', run_dir]

            if not force_smt:
                p_solver_args += ['-b', self.global_bitmap]
                if self.use_smt_if_empty:
                    env['BITMAP_ALT'] = str(self.global_alt_bitmap)
            else:
                p_solver_args += ['-b', self.global_alt_bitmap]
                if self.use_smt_if_empty:
                    env['BITMAP_ALT'] = str(self.global_bitmap)

            p_solver_args += ['-c', self.__get_root_dir() + '/context_bitmap']
            p_solver_args += ['-m', self.__get_root_dir() + '/memory_bitmap']

            #p_solver_args += ['-b', os.path.join(self.output_dir, '/afl-bitmap')]

            if self.optimistic_solving:
                p_solver_args += [ '-p' ]
            if self.memory_slice_reasoning:
                p_solver_args += [ '-s' ]
            if self.address_reasoning:
                p_solver_args += [ '-a' ]
            
            logger.info(f"[FUZZOLIC] Starting solver with args: {' '.join(p_solver_args)}")

            if self.debug == 'gdb_solver':
                p_solver = subprocess.Popen(['gdb'] + p_solver_args[0:1],
                                            stdout=p_solver_log if not self.debug else None,
                                            stderr=subprocess.STDOUT if not self.debug else None,
                                            stdin=subprocess.PIPE,
                                            cwd=run_dir,
                                            bufsize=0,
                                            env=env)

                RUNNING_PROCESSES.append(p_solver)

                gdb_cmd = 'run ' + ' '.join(p_solver_args[1:])
                gdb_cmd += "\n"
                try:
                    p_solver.wait(5)
                except:
                    pass
                logger.info("GDB command: %s" % gdb_cmd)
                p_solver.stdin.write("break exit\n".encode())
                p_solver.stdin.write(gdb_cmd.encode())
                # p_solver.stdin.close()
                time.sleep(2)
            else:
                p_solver = subprocess.Popen(p_solver_args,
                                            stdout=p_solver_log if not self.debug else None,
                                            stderr=subprocess.STDOUT if not self.debug else None,
                                            cwd=run_dir,
                                            preexec_fn=setlimits,
                                            env=env)
                RUNNING_PROCESSES.append(p_solver)

            # wait a few moments to let the solver setup setup shared memories
            time.sleep(SOLVER_WAIT_TIME_AT_STARTUP)

        # launch tracer
        p_tracer_log_name = run_dir + '/tracer.log'
        p_tracer = None
        forkserver_mode = bool(self.binradar_entrypoint)
        forkserver_result = None

        p_tracer_args = []
        if self.debug == 'gdb_tracer':
            p_tracer_args += ['gdb']

        p_tracer_args += [TRACER_BIN]

        if self.debug != 'gdb_tracer':
            p_tracer_args += ['-symbolic']
            if (self.debug == 'trace'):
                p_tracer_args += ['-d']
                p_tracer_args += ['in_asm,op,op_opt,out_asm']

        args = self.binary_args
        if not self.testcase_from_stdin:
            for k in range(len(args)):
                if args[k] == '@@':
                    args[k] = testcase

        if self.debug != 'gdb_tracer':
            p_tracer_args += [self.binary]
            p_tracer_args += args

        if self.plt_info:
            env["PLT_INFO_FILE"] = self.plt_info
        logger.info(f"[FUZZOLIC] Starting tracer for {self.binary} with args: {' '.join(p_tracer_args)}")
        start_time = time.time()
        tracer_returncode = 0
        if forkserver_mode:
            env["BINRADAR_ENTRYPOINT"] = self.binradar_entrypoint
            if not self._forkserver:
                if not self._forkserver_session_log:
                    session_log_path = os.path.join(self.output_dir, 'tracer-forkserver.log')
                    self._forkserver_session_log = open(session_log_path, 'ab', buffering=0)
                self._forkserver = ForkserverTracer(
                    p_tracer_args, env, self.output_dir, self.debug,
                    self.testcase_from_stdin, logger, self._forkserver_session_log)
                self._forkserver.start()
                RUNNING_PROCESSES.append(self._forkserver.proc)
            forkserver_result = self._forkserver.run_testcase(run_dir)
            print(f"Run 1: {forkserver_result}")
            forkserver_result2 = self._forkserver.run_testcase(run_dir)
            print(f"Run 2: {forkserver_result2}")
            forkserver_result3 = self._forkserver.run_testcase(run_dir)
            print(f"Run 3: {forkserver_result3}")
            tracer_returncode = forkserver_result.returncode
            logger.info(f"[tracer] [pid {forkserver_result.child_pid}] [time {round(forkserver_result.duration, 3)} secs]")
        else:
            p_tracer_log = open(p_tracer_log_name, 'w')
            p_tracer = subprocess.Popen(p_tracer_args,
                                        stdout=subprocess.DEVNULL if not self.debug and not self.fuzz_expr else None,
                                        stderr=p_tracer_log if not self.debug and not self.fuzz_expr else None,
                                        stdin=subprocess.PIPE if self.testcase_from_stdin or self.debug == 'gdb_tracer' else None,
                                        cwd=run_dir,
                                        env=env,
                                        preexec_fn=setlimits,
                                        bufsize=0 if self.debug == 'gdb_tracer' else -1)

            RUNNING_PROCESSES.append(p_tracer)
            if self.debug != 'gdb_tracer':
                if self.testcase_from_stdin:
                    with open(testcase, "rb") as f:
                        p_tracer.stdin.write(f.read())
                        p_tracer.stdin.close()
            else:
                gdb_cmd = 'run -d in_asm,op_opt,out_asm -symbolic ' + self.binary + ' ' + ' '.join(args)
                if self.testcase_from_stdin:
                    gdb_cmd += ' < ' + testcase
                gdb_cmd += "\n"
                logger.info("GDB command: %s" % gdb_cmd)
                p_tracer.stdin.write(gdb_cmd.encode())
                for line in sys.stdin:
                    p_tracer.stdin.write(line.encode())
                    if 'quit' in line or line.startswith('q'):
                        logger.info("Closing stdin in gdb")
                        break
                p_tracer.stdin.close()

            try:
                p_tracer.wait(20)
            except subprocess.TimeoutExpired:
                logger.info('[FUZZOLIC] Sending SIGINT to tracer.')
                p_tracer.send_signal(signal.SIGINT)
                try:
                    p_tracer.wait(1)
                except subprocess.TimeoutExpired:
                    logger.info('[FUZZOLIC] Sending SIGKILL to tracer.')
                    p_tracer.send_signal(signal.SIGKILL)
                    p_tracer.wait()

            if p_tracer in RUNNING_PROCESSES:
                RUNNING_PROCESSES.remove(p_tracer)
            logger.info(f"[tracer] [time {round(time.time() - start_time, 3)} secs]")
            p_tracer_log.close()
            tracer_returncode = p_tracer.returncode

        if self.debug == 'gdb_solver':
            for line in sys.stdin:
                p_solver.stdin.write(line.encode())
                if 'quit' in line or line.startswith('q'):
                    logger.info("Closing stdin in gdb")
                    break
            p_solver.stdin.close()

        if tracer_returncode != 0:
            returncode_str = "(SIGSEGV)" if tracer_returncode == -11 else ""
            logger.warning("ERROR: tracer has returned code %d %s" %
                  (tracer_returncode, returncode_str))

        if self.debug != 'no_solver' and self.debug != 'coverage':
            p_solver.send_signal(signal.SIGUSR1)

        if self.fuzz_expr:
            p_solver.send_signal(signal.SIGINT)
            time.sleep(1)
            p_solver.send_signal(signal.SIGKILL)
            sys.exit(tracer_returncode)

        if self.debug != 'no_solver' and self.debug != 'coverage':
            elapsed = 0
            timeout = False
            while not SHUTDOWN:
                try:
                    p_solver.wait(SOLVER_TIMEOUT / 1000)
                    break
                except subprocess.TimeoutExpired:
                    # logger.info("Elapsed %s secs (timeout: %s, elapsed: %s)"  % ((SOLVER_TIMEOUT / 1000), self.timeout, elapsed)) 
                    pass
                elapsed += SOLVER_TIMEOUT
                if self.timeout > 0 and elapsed > (self.timeout + 10000):
                    timeout = True
                    break

            if SHUTDOWN or timeout:
                logger.info('[FUZZOLIC] Solver is taking too long. Let us stop it.')
                p_solver.send_signal(signal.SIGUSR2)
                try:
                    p_solver.wait(SOLVER_TIMEOUT)
                except subprocess.TimeoutExpired:
                    logger.info('[FUZZOLIC] Solver will be killed.')
                    p_solver.send_signal(signal.SIGKILL)
                    p_solver.wait()

        if self.debug != 'no_solver' and self.debug != 'coverage':
            if p_solver in RUNNING_PROCESSES:
                RUNNING_PROCESSES.remove(p_solver)

        p_solver_log.close()

        # delete shared memory (solver may have crashed)
        IPC_RMID = 0
        shm_keys = [
            int(env['EXPR_POOL_SHM_KEY'], 16),
            int(env['QUERY_SHM_KEY'], 16),
            int(env['BITMAP_SHM_KEY'], 16),
        ]
        for shm_key in shm_keys:
            shm_id = self.libc.shmget(ctypes.c_int(
                shm_key), ctypes.c_int(1), ctypes.c_int(0))
            if shm_id > 0:
                r = self.libc.shmctl(ctypes.c_int(
                    shm_id), ctypes.c_int(IPC_RMID), ctypes.c_int(0))
                logger.info("Shared memory detach on (%s, %s): %s" %
                      (shm_key, shm_id, r))

        # parse tracer logs for known errors/warnings
        input_timeout = False
        if not self.debug:
            """
            with open(p_tracer_log_name, 'r', encoding="utf8", errors='ignore') as log:
                for line in log:
                    # if re.search('Helper', line):
                    if 'Unhandled TCG instruction' in line or 'Helper ' in line:
                        if line not in self.__warning_log:
                            self.__warning_log.add(
                                "[tracer warning]: %s" % line)
            """
            with open(p_solver_log_name, 'r', encoding="utf8", errors='ignore') as log:
                for line in log:
                    """
                    if 'PROGRAM ABORT' in line:
                        if line not in self.__warning_log:
                            self.__warning_log.add(
                                "[solver warning]: %s" % line)
                    """
                    if "Solving time exceded budget" in line:
                        input_timeout = True

        if input_timeout:
            os.system("cp " + testcase + " " + self.__get_timeout_dir() + "/" + target)

        # check new test cases
        if 'USE_DUPLICATE_TESTCASE_CHECKER' in env and not self.afl:
            files = list(filter(os.path.isfile, glob.glob(
                run_dir + "/test_case_*.dat")))
            files.sort(key=lambda x: os.path.getmtime(x))
            k = 0
            for t in files:
                good = self.__check_testcase_duplicate(t, run_id, k, target)
                if good:
                    self.__import_test_case(run_dir + '/' + t, 'test_case_%03d_%03d_.dat' % (run_id, k))
                    k += 1
        else:
            file_extension = None
            if self.input_fixed_name:
                _, file_extension = os.path.splitext(self.input_fixed_name)
                file_extension = file_extension[1:]
                # logger.info("File extensions: %s" % file_extension)
            r = self.minimizer.check_testcases(run_dir, global_bitmap_pre_run, f_ext=file_extension)
            k = 0
            for t in r:
                good = r[t]
                if good:
                    if self.afl:
                        target = os.path.basename(target)[:len("id:......")]
                        name = "id:%06d,src:%s" % (self.tick(), target)
                        self.__import_test_case(run_dir + '/' + t, name)
                    else:
                        self.__import_test_case(run_dir + '/' + t, 'test_case_%03d_%03d.dat' % (run_id, k))
                    k += 1
                else:
                    if self.afl:
                        os.unlink(run_dir + '/' + t)

        if not self.keep_run_dirs:
            shutil.rmtree(run_dir)

        os.unlink(global_bitmap_pre_run)

        if tracer_returncode == -11:
            with open(p_tracer_log_name, "r") as f:
                log_lines = f.readlines()
                qemu_segfault = True
                for line in log_lines:
                    if "qemu: uncaught target signal 11 (Segmentation fault)" in line:
                        logger.info("[FUZZOLIC] [info] Target program crashed with SIGSEGV.")
                        qemu_segfault = False
                        break
                if qemu_segfault:
                    logger.info("[FUZZOLIC] [error] QEMU tracer crashed with SIGSEGV.")
                    sys.exit(-11)
        if self.debug != 'no_solver' and self.debug != 'coverage' and p_solver.returncode == -6:
            sys.exit(-11)

    def __check_testcase(self, t, run_id, k, target, global_bitmap_pre_run):
        if self.minimizer.check_testcase(t, global_bitmap_pre_run):
            self.__import_test_case(
                t, 'test_case_' + str(run_id) + '_' + str(k) + '.dat')
            return True
        else:
            return False

    def __check_testcase_duplicate(self, t, run_id, k, target):
        # check whether this a duplicate test case
        discard = False
        known_tests = glob.glob(
            self.__get_testcases_dir() + "/*.dat")
        for kt in known_tests:
            if filecmp.cmp(kt, t, shallow=False):
                logger.info('Discarding %s since it is a duplicate (%s)' % (t, kt))
                discard = True
                break

        if not discard:
            logger.info("Importing %s with id=%s_%s" % (t, run_id, k))
            self.__import_test_case(
                t, 'test_case_' + str(run_id) + '_' + str(k) + '.dat')

        return not discard

    def tick(self):
        self.tick_count += 1
        return self.tick_count - 1

    def __check_testcase_afl(self, t, run_id, k, target, global_bitmap_pre_run=None):
        if self.minimizer.check_testcase(t, global_bitmap_pre_run):
            # logger.info("Importing %s" % t)
            target = os.path.basename(target)[:len("id:......")]
            name = "id:%06d,src:%s" % (self.tick(), target)
            self.__import_test_case(t, name)
            return True
        else:
            # logger.info('Discarding %s since it is not interesting.' % t)
            return False

    def __import_test_case(self, testcase, name):
        os.system('cp ' + testcase + ' ' + self.__get_queue_dir() + '/' + name)
        os.system('cp ' + testcase + ' ' +
                  self.__get_testcases_dir() + '/' + name)
        return self.__get_queue_dir() + '/' + name

    @property
    def cur_input(self):
        if self.input_fixed_name:
            return self.__get_root_dir() + '/' + self.input_fixed_name
        else:
            return self.__get_root_dir() + '/.cur_input'

    def __pick_testcase(self, initial_run=False, force_smt=False):

        if self.afl:
            queued_inputs = self.__import_from_afl(force_smt)
            if len(queued_inputs) == 0 and self.use_smt_if_empty and not force_smt and self.fuzzy:
                return self.__pick_testcase(initial_run, force_smt=True)

            if len(queued_inputs) == 0 and not initial_run:
                timeout_testcases = os.listdir(self.__get_timeout_dir())
                timeout_testcases = set(timeout_testcases) - self.timeout_testcases
                if len(timeout_testcases) > 0:
                    testcase = list(timeout_testcases)[0]
                    self.timeout_testcases.add(testcase)
                    queued_inputs = [ self.__get_timeout_dir() + "/" + testcase ]

            waiting_rounds = 0
            reported_waiting_rounds = 0
            while len(queued_inputs) == 0:
                waiting_rounds += 1
                if waiting_rounds > 0 and waiting_rounds % 300 == 0:
                    logger.info("Waiting for a new input from AFL (%s secs)\n" %
                          ((waiting_rounds - reported_waiting_rounds) * 0.1))
                    reported_waiting_rounds = waiting_rounds
                time.sleep(0.1)
                queued_inputs = self.__import_from_afl()

            if waiting_rounds > 0:
                logger.info("\nWaited %s seconds for a new input from AFL\n" %
                      ((waiting_rounds - reported_waiting_rounds) * 0.1))

            while not os.path.exists(queued_inputs[0]):
                # afl has rename the input, skip it
                queued_inputs = queued_inputs[1:]

            if len(queued_inputs) == 0:
                return self.__pick_testcase(initial_run, force_smt)

            if force_smt:
                self.afl_alt_processed_testcases.add(queued_inputs[0])
            shutil.copy2(queued_inputs[0], self.cur_input)
            self.afl_processed_testcases.add(queued_inputs[0])

            # if initial_run:
            # update bitmap
            self.minimizer.check_testcase(
                self.cur_input, self.global_bitmap, True)

            return self.cur_input, os.path.basename(queued_inputs[0]), force_smt

        else:
            queued_inputs = list(
                filter(os.path.isfile, glob.glob(self.__get_queue_dir() + "/*")))

            if len(queued_inputs) == 0 and not initial_run:
                timeout_testcases = os.listdir(self.__get_timeout_dir())
                timeout_testcases = set(timeout_testcases) - self.timeout_testcases
                if len(timeout_testcases) > 0:
                    testcase = list(timeout_testcases)[0]
                    self.timeout_testcases.add(testcase)
                    queued_inputs = [ self.__get_timeout_dir() + "/" + testcase ]

            if len(queued_inputs) == 0:
                if not initial_run:
                    return None, None, False

                # copy the initial seed(s) in the queue
                if not os.path.isdir(self.input):
                    test_case_path = self.__import_test_case(
                        self.input, 'seed.dat')
                    queued_inputs.append(test_case_path)
                else:
                    for t in glob.glob(self.input + '/*'):
                        test_case_path = self.__import_test_case(
                            t, os.path.basename(t))
                        queued_inputs.append(test_case_path)

                self.minimizer.check_testcase(
                    queued_inputs[0], self.global_bitmap, True)

            elif len(queued_inputs) > 1:
                # sort the queue
                queued_inputs.sort(key=lambda x: os.path.getmtime(x))
            
            logger.info(f"[FUZZOLIC] Picked testcase {queued_inputs[0]} from queue. {queued_inputs}")
            shutil.copy2(queued_inputs[0], self.cur_input)

            # remove from the queue
            os.unlink(queued_inputs[0])

            return self.cur_input, os.path.basename(queued_inputs[0]), False

    def __check_shutdown_flag(self):
        if SHUTDOWN:
            sys.exit("Forcefully terminating...")

    def __import_from_afl(self, force_smt=False):
        if not self.afl:
            return []

        afl_queue = self.afl + '/queue/'
        files = []
        for name in os.listdir(afl_queue):
            path = os.path.join(afl_queue, name)
            if os.path.isfile(path):
                files.append(path)

        if force_smt:
            files = list(set(files) - self.afl_alt_processed_testcases)
        else:
            files = list(set(files) - self.afl_processed_testcases)
        files = sorted(files)
        return sorted(files,
                      key=functools.cmp_to_key(
                          minimizer_qsym.testcase_compare),
                      reverse=True)

    def run(self):

        self.__check_shutdown_flag()
        testcase, target, force_smt = self.__pick_testcase(True)
        while testcase:
            start = time.time()
            self.fuzz_one(testcase, target)
            end = time.time()
            logger.info("Run took %s secs" % round(end-start, 1))
            # if self.debug or self.fuzz_expr or self.single_path:
            #     return
            self.__check_shutdown_flag()
            testcase, target, force_smt = self.__pick_testcase()
            self.__check_shutdown_flag()
            logger.info(f"[FUZZOLIC] testcase: {testcase}")

        logger.info("[FUZZOLIC] no more testcase. Finishing.\n")

        if self._forkserver:
            if self._forkserver.proc in RUNNING_PROCESSES:
                RUNNING_PROCESSES.remove(self._forkserver.proc)
            self._forkserver.stop()
            self._forkserver = None
        if self._forkserver_session_log:
            self._forkserver_session_log.close()
            self._forkserver_session_log = None

        if len(self.__warning_log):
            logger.info()
        for w in self.__warning_log:
            logger.info(w)
