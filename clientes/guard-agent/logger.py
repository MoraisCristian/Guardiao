import logging
import os
import sys
import traceback
from datetime import datetime

# Ensure log directory exists
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configure logging
log_file = os.path.join(log_dir, f'guard_agent_{datetime.now().strftime("%Y%m%d")}.log')

# Create logger
logger = logging.getLogger('guard_agent')
logger.setLevel(logging.DEBUG)

# Create file handler
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# Create console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def log_info(message):
    """Log info level message"""
    logger.info(message)

def log_warning(message):
    """Log warning level message"""
    logger.warning(message)

def log_error(message, exc_info=None):
    """Log error level message with optional exception info"""
    if exc_info:
        error_details = ''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))
        logger.error(f"{message}\nException details: {error_details}")
    else:
        logger.error(message)

def log_debug(message):
    """Log debug level message"""
    logger.debug(message)

def log_critical(message, exc_info=None):
    """Log critical level message with optional exception info"""
    if exc_info:
        error_details = ''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))
        logger.critical(f"{message}\nException details: {error_details}")
    else:
        logger.critical(message)

def log_exception(message="An exception occurred"):
    """Log exception with full traceback"""
    logger.exception(message)