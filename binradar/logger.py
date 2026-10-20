import logging

logger = logging.getLogger("binradar")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s - %(message)s")
ch.setFormatter(fmt)
logger.addHandler(ch)

def set_file(file_name: str):
    fh = logging.FileHandler(file_name)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

def error(msg):
    logger.error(msg)

def warning(msg):
    logger.warning(msg)

def info(msg):
    logger.info(msg)

def debug(msg):
    logger.debug(msg)
