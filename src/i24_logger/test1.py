
import log_writer
log_writer.connect_automatically(user_settings = {"log_name":"new name"})
logger = log_writer.logger
# for x in range(1000):
#     logger.critical("Hello Zi")

logger.debug("Test")