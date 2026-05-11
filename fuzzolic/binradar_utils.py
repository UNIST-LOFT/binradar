import subprocess
import os
import signal
from typing import List, Set, Tuple, Dict, Optional, Any

import logger

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

def execute_async(command: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None, timeout: float = 60.0, verbose: bool = True) -> subprocess.Popen:
    """
    Executes a command and returns the exit code, stdout, and stderr.
    """
    if verbose:
        logger.info(f"Executing command: {' '.join(command)} at {cwd if cwd else os.getcwd()}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    return process

def execute_await(process: subprocess.Popen, timeout: float = 60.0, verbose: bool = False) -> ExecutionResult:
    
    def decode_output(data) -> str:
        if data is None:
            return ""
        if isinstance(data, bytes):
            return data.decode(errors="ignore")
        return str(data)
    
    if verbose:
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

def execute(command: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None, timeout: float = 60.0, verbose: bool = True) -> ExecutionResult:
    process = execute_async(command, env=env, cwd=cwd, timeout=timeout, verbose=verbose)
    return execute_await(process, timeout=timeout, verbose=verbose)

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