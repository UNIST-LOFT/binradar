import subprocess
import os
import signal
import shlex
from typing import List, Set, Tuple, Dict, Optional, Any

import sbsv

import logger

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_STACKTRACE_RELEASE = os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_stacktrace", "target", "release", "qemu_stacktrace")

def execute_async(command: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None, timeout: float = 60.0) -> subprocess.Popen:
    """
    Executes a command and returns the exit code, stdout, and stderr.
    """
    logger.info(f"Executing command: {' '.join(command)} at {cwd if cwd else os.getcwd()}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    return process

class ExecutionResult:
    def __init__(self, success: bool, exit_code: int, stdout: str, stderr: str):
        self.success = success
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
    
    def decode_status(self) -> int:
        if os.WIFEXITED(self.exit_code):
            return os.WEXITSTATUS(self.exit_code)
        elif os.WIFSIGNALED(self.exit_code):
            return -os.WTERMSIG(self.exit_code)
        return 0

def execute_await(process: subprocess.Popen, timeout: float = 60.0) -> ExecutionResult:
    
    def decode_output(data) -> str:
        if data is None:
            return ""
        if isinstance(data, bytes):
            return data.decode(errors="ignore")
        return str(data)
    
    logger.debug(f"Awaiting process with PID {process.pid} for up to {timeout} seconds")
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return ExecutionResult(
            success=True,
            exit_code=process.returncode,
            stdout=decode_output(stdout),
            stderr=decode_output(stderr))
    except Exception as e:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        stdout, stderr = process.communicate()
        logger.debug(f"Command failed: Error: {str(e)}")
        return ExecutionResult(
            success=False,
            exit_code=process.returncode,
            stdout=decode_output(stdout),
            stderr=decode_output(stderr))

def execute(command: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None, timeout: float = 60.0) -> ExecutionResult:
    process = execute_async(command, env=env, cwd=cwd, timeout=timeout)
    return execute_await(process, timeout=timeout)

def load_env(file: str) -> Dict[str, str]:
    """
    Loads environment variables from a .env file and returns them as a dictionary.
    """
    env = dict()
    with open(file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    return env

def save_env(env: Dict[str, str], file: str):
    """
    Saves environment variables from a dictionary to a .env file.
    """
    with open(file, "w") as f:
        for key, value in env.items():
            f.write(f"{key}=\"{value}\"\n")

class BinRadarVerifier:
    dir: str
    binary: str
    poc_input: str
    test_cmd: str
    target_function_entry: str
    patch_loc: str
    run_results: Optional[ExecutionResult]
    def __init__(self, dir: str, binary: str, poc_input: str, test_cmd: str, target_function_entry: str, patch_loc: str):
        self.dir = dir
        self.binary = binary
        self.poc_input = poc_input
        self.test_cmd = test_cmd
        self.target_function_entry = target_function_entry
        self.patch_loc = patch_loc
        self.run_results = None
    
    @staticmethod
    def init(dir: str) -> "BinRadarVerifier":
        env = load_env(os.path.join(dir, "config.env"))
        return BinRadarVerifier.init_from_env(dir, env)
    
    @staticmethod
    def init_from_env(dir: str, env: Dict[str, str]) -> "BinRadarVerifier":
        return BinRadarVerifier(
            dir=dir,
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            target_function_entry=env["TARGET_FUNCTION_ENTRY"],
            patch_loc=env["PATCH_LOC"]
        )
    
    def original_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.orig")

    def get_qemu_stacktrace_command(self, binary: str, input_file: str) -> List[str]:
        return [QEMU_STACKTRACE_RELEASE, "--input", input_file, "--patch-loc", self.patch_loc, binary, "--"] + shlex.split(self.test_cmd)

    def test_with_original(self):
        command = self.get_qemu_stacktrace_command(self.original_binary(), self.poc_input)
        self.run_results = execute(command, cwd=self.dir)
        parsed = self.parse_results(self.run_results.stderr)
    
    def parse_results(self, log: str) -> Dict[str, Any]:
        if self.run_results is None:
            raise ValueError("No results to parse. Please run the test first.")
        if not self.run_results.success:
            logger.error("Failed to execute the command.")
            return {}
        print(f"Success: {self.run_results.success}")
        print(f"Exit code: {self.run_results.exit_code}")
        print(f"Stdout: {self.run_results.stdout}")
        print(f"Stderr: {self.run_results.stderr}")
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[patch-info] [set: bool] [location: hex]")
        parser.add_schema("[exit] [result: str]")
        parser.add_schema("[stacktrace] [idx: int] [addr: hex] [symbol: str]")
        parser.add_schema("[patch-cov] [location: hex] [covered: bool] [hits: int]")
        parser.add_schema("[patch-func] [location: hex] [entry-cnt: int] [entry: str] [hits: int]")
        result = parser.loads(log)
        return result


