import subprocess
import os
import signal
import threading
from typing import List, Set, Tuple, Dict, Optional, Any

import logger

# E9 runtime metadata keys in binradar.env, prefixed per artifact so a
# future .brcache can never borrow .brpatched layout values.  All current
# artifacts are built with the same e9patch invocation, so the values are
# shared; selection is by prefix at load time.
E9_METADATA_PREFIXES = {
    "brpatched": "BRPATCHED",
    "prefilter": "PREFILTER",
    "brcached": "BRCACHED",
}


def e9_metadata_keys(prefix: str) -> Tuple[str, str]:
    """Return (exclude-ranges key, relocated-calls key) for an artifact.

    `prefix` is the artifact name ("brpatched", "prefilter", "brcached");
    the stored keys carry the uppercase prefix.
    """
    upper = E9_METADATA_PREFIXES[prefix]
    return (f"{upper}_E9_EXCLUDE_RANGES",
            f"{upper}_E9_RELOCATED_CALL_JUMPS")


def set_e9_metadata(env: Dict[str, str], prefix: str,
                    exclude_ranges: str, relocated_calls: str) -> None:
    """Write one artifact's E9 metadata into an env dict under its prefix."""
    ranges_key, calls_key = e9_metadata_keys(prefix)
    env[ranges_key] = exclude_ranges
    env[calls_key] = relocated_calls


def get_e9_metadata(env: Dict[str, str], prefix: str) -> Tuple[str, str]:
    """Read one artifact's E9 metadata; missing keys yield empty strings."""
    ranges_key, calls_key = e9_metadata_keys(prefix)
    return env.get(ranges_key, ""), env.get(calls_key, "")

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
        logger.info(f"Executing command: cd {cwd if cwd else os.getcwd()} && {' '.join(command)}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    return process

def decode_output(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="ignore")
    return str(data)

def pipe_reader(rfd: int, chunks: List[bytes], verbose: bool = False):
    try:
        while True:
            chunk = os.read(rfd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
    except Exception as e:
        if verbose:
            logger.debug(f"Pipe reader thread encountered an error: {str(e)}")
    finally:
        os.close(rfd)

def create_pipe_reader_thread(rfd: int, verbose: bool = False) -> Tuple[threading.Thread, List[bytes]]:
    patch_chunks = list()
    thread = threading.Thread(target=pipe_reader, args=(rfd, patch_chunks, verbose), daemon=False)
    thread.start()
    return thread, patch_chunks

def execute_await(process: subprocess.Popen, timeout: float = 60.0, verbose: bool = False) -> ExecutionResult:

    if verbose:
        logger.debug(f"Awaiting process with PID {process.pid} for up to {timeout} seconds")
    
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return ExecutionResult(
            success=True,
            exit_code=process.returncode,
            stdout=decode_output(stdout),
            stderr=decode_output(stderr))
    
    except subprocess.TimeoutExpired as e:
        if verbose:
            logger.debug(f"Process with PID {process.pid} timed out after {timeout} seconds")
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
        return ExecutionResult(
            success=False,
            exit_code=process.returncode,
            stdout=decode_output(stdout),
            stderr=decode_output(stderr))
    
    except Exception as e:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
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