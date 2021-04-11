import logging.handlers
import os


logger = logging.getLogger('dragoneye')
INITIALIZED = False
if not INITIALIZED:
    logger.setLevel(logging.INFO)
    logger_file = os.path.join(os.getcwd(), 'dragoneye.log')
    rotate_file = os.path.isfile(logger_file)
    file_handler = logging.handlers.RotatingFileHandler(logger_file, maxBytes=10000000, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
    if rotate_file:  # keeping log file per execution
        file_handler.doRollover()
    logger.addHandler(file_handler)
    logger.addHandler(logging.StreamHandler())

    INITIALIZED = True
