import logging
import socket
from logging.handlers import SysLogHandler
from logstash_async.handler import AsynchronousLogstashHandler
from logstash_async.formatter import LogstashFormatter
import ecs_logging
import sys
import os
import traceback

from typing import Union, Mapping

levels = {'CRITICAL': logging.CRITICAL, 'ERROR': logging.ERROR, 'WARNING': logging.WARNING,
          'INFO': logging.INFO, 'DEBUG': logging.DEBUG, None: None}

global logger


class MaxLevelFilter(object):
    """
    Filter for keeping log records of a given level or LOWER (as opposed to the normal 'or higher' functionality).
    Does not inherit from logging.Filter, since we need our own __init__ to keep track of the max level.
    Inspired from: https://pythonexamples.org/python-logging-info
    """
    def __init__(self, level):
        """
        Establish the filter with maximum log level to keep.
        :param level: maximum logging level (e.g., logging.INFO) to allow through the filter
        """
        self.__max_level = level

    def __call__(self, log_record: logging.LogRecord) -> bool:
        """
        Filter function, implemented as the direct call of this object.
        :param log_record: logging.LogRecord that contains all the relevant fields and functionality.
        :return:
        """
        return log_record.levelno <= self.__max_level


class ExtraLogger(logging.Logger):
    """
    Subclass of logging.Logger that adds "extra" log record information passed as a dictionary as 1) unpacked individual
        LogRecord attributes (default behavior) and 2) as a single attribute that contains the entire dictionary. This
        feature is needed in order to unify the logging interface between different code modules that will want to
        include different "extra" fields depending on context.
    Inspired from: https://devdreamz.com/question/710484-python-logging-logger-overriding-makerecord
    """
    def makeRecord(self, name: str, level: int, fn: str, lno: int, msg: object, args, exc_info,
                   func: Union[str, None] = None,  extra: Union[Mapping[str, object], None] = None,
                   sinfo: Union[str, None] = None) -> logging.LogRecord:
        """
        Overrides `makeRecord` in logging.Logger in order to add a single feature: add the attribute 'extra' to each
            LogRecord that is created and set its value as the entire "extra" dictionary that is passed to the log
            function that initiated the record creation. The "extra" dictionary still gets unpacked and added as
            individual attributes through the call to super.makeRecord(...).
        :param name: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param level: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param fn: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param lno: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param msg: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param args: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param exc_info: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param func: passed straight to the LogRecord factory, which by default is the LogRecord class
        :param extra: a dictionary of extra log information that is contextual to the code module logging call
        :param sinfo: passed straight to the LogRecord factory, which by default is the LogRecord class
        :return: LogRecord with the desired 'extra' attribute and unpacked "extra" values
        """
        # Make the call to the normal `makeRecord` function, which will do the default behavior
        # DEREK: brutish fix, use logging.Logger.makeRecord as a static method
        rv = logging.Logger.makeRecord(None,name=name, level=level, fn=fn, lno=lno, msg=msg, args=args,
                                                 exc_info=exc_info, func=func, extra=extra, sinfo=sinfo)
        # Also add the complete "extra" dictionary as an attribute
        rv.__dict__['extra'] = extra
        return rv


class I24Logger:
    """
    This unified interface is used to abstract log setup from other code modules,
        which we want to have consistent behavior.
    """

    # Python 3.8 compatibility mode...add other typehints if minimum version changes.
    def __init__(self, log_name: str = None, processing_environment: str = None,
                 connect_logstash: bool = False, connect_file: bool = False,
                 connect_syslog: bool = False, connect_console: bool = False,
                 logstash_address=None, file_path: str = None, syslog_location=None,
                 all_log_level: str = 'DEBUG', logstash_log_level=None, file_log_level=None,
                 syslog_log_level=None, console_log_level=None):
        """
        Constructor of the persistent logging interface. It establishes a custom multi-destination logger with the
            option to log different levels to different destinations.
        :param log_name:
        :param processing_environment:
        :param connect_logstash: True/False to connect to Logstash via asynchronous handler.
        :param connect_file: True/False to connect a simple log file (non-rotating) to this logger. If multiple loggers
            are instantiated, multiple files will be produced and need to be differentiated by `file_path`.
        :param connect_syslog: True/False to connect to the host computer's syslog via TCP Socket Stream.
        :param connect_console: True/False to connect to the STDOUT and STDERR available via `sys` package.
        :param logstash_address: (host, port) tuple for Logstash connection.
        :param file_path: Path (absolute or relative) and file name of the log file to write; directories not created.
        :param all_log_level: Available to set a global log level across all handlers; overridden by handler-specific.
        :param logstash_log_level: Logstash log level as string; overrides `all_log_level`.
        :param file_log_level: File log level as string; overrides `all_log_level`.
        :param syslog_log_level: Syslog log level as string; overrides `all_log_level`.
        :param console_log_level: Console log level as string; overrides `all_log_level`.
        """
        # There are multiple default LogRecord attributes that are populated automatically, so we don't need to
        #   duplicate this functionality unless it's not working for us.
        #       - LogRecord.process: process ID (if available, acquired from `os.getpid()`)
        #       - LogRecord.processName: process name (default='MainProcess', acquired from `mp.current_process().name`)
        #       - LogRecord.thread: thread ID (default=None, acquired from `threading.get_ident()`)
        #       - LogRecord.threadName: thread name (default=None, acquired from `threading.current_thread().name`)
        #       - LogRecord.filename/pathname: file/path of source file (where this comes from is complicated)
        #       - LogRecord.module: filename without extension

        # We have to give the logger a name, but the actual process name is populated in LogRecords automatically.
        self._name = log_name

        self._hostname = socket.gethostname()
        self._environment = processing_environment if processing_environment is not None else 'DEF_ENV'
        
        self._logstash_addr = logstash_address
        self._logfile_path = file_path if file_path is not None else '{}_{}.log'.format(self._name, os.getpid())
        self._syslog_location = syslog_location

        # No need to put in owner process name/ID or parent, since this information will be in the logger name or
        #   the LogRecord attributes.
        self._default_logger_extra = {'host': self._hostname, 'env': self._environment}

        if not all([ll in levels.keys() for ll in
                    (logstash_log_level, file_log_level, syslog_log_level, console_log_level)]):
            raise ValueError("Invalid log level specified. Use: 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', None.")
        self._log_levels = {'logstash': (levels[logstash_log_level] if logstash_log_level is not None
                                         else levels[all_log_level]),
                            'file': (levels[file_log_level] if file_log_level is not None
                                     else levels[all_log_level]),
                            'syslog': (levels[syslog_log_level] if syslog_log_level is not None
                                       else levels[all_log_level]),
                            'console': (levels[console_log_level] if console_log_level is not None
                                        else levels[all_log_level]),
                            }
        self._connect = {'logstash': connect_logstash, 'file': connect_file,
                         'syslog': connect_syslog, 'console': connect_console}

        if self._connect['logstash'] is True and self._log_levels['logstash'] is None:
            raise ValueError("Logstash logging activated, but no log level specified during construction.")
        if self._connect['file'] is True and self._log_levels['file'] is None:
            raise ValueError("File logging activated, but no log level specified during construction.")
        if self._connect['syslog'] is True and self._log_levels['syslog'] is None:
            raise ValueError("Syslog logging activated, but no log level specified during construction.")
        if self._connect['console'] is True and self._log_levels['console'] is None:
            raise ValueError("Console logging activated, but no log level specified during construction.")

        if self._connect['logstash'] is True and self._logstash_addr is None:
            raise ValueError("Logstash logging activated, but no connection information given (host and port).")
        if self._connect['file'] is True and (self._logfile_path is None or self._logfile_path == ''):
            raise ValueError("File logging activated, but no file path given.")
        if self._connect['syslog'] is True and syslog_location is None:
            raise ValueError("Syslog logging activated, but no location (path or host/port tuple) given.")

        logging.setLoggerClass(ExtraLogger)
        self._logger = logging.getLogger(self._name)

        self._logger.propagate = False
        # Set overall logger level at the minimum of the specified levels (no need to set it any lower).
        self._logger.setLevel(min(self._log_levels.values()))

        if self._connect['logstash'] is True:
            self._setup_logstash()
        if self._connect['file'] is True:
            self._setup_file()
        if self._connect['syslog'] is True:
            self._setup_syslog()
        if self._connect['console'] is True:
            self._setup_console()

    def connect_logstash(self, logstash_address, logstash_log_level=None):
        """
        External-access function for setting up Logstash AFTER construction of I24Logger.
        :param logstash_address: Since Logstash was not set up at construction, need to pass in (host, port).
        :param logstash_log_level: Logstash log level as string; overrides any level specified in constructor for LS.
        :return: None
        """
        if self._connect['logstash'] is True:
            self.warning("Logstash logging is already connected!")
            return
        self._connect['logstash'] = True
        self._logstash_addr = logstash_address
        if logstash_log_level is not None:
            self._log_levels['logstash'] = levels[logstash_log_level]
        self._setup_logstash()

    def connect_syslog(self, syslog_location, syslog_log_level=None):
        """
        External-access function for setting up syslog AFTER construction of I24Logger.
        :param syslog_location: Since syslog was not set up at construction, need to pass in its location.
        :param syslog_log_level: Syslog log level as string; overrides any level specified in constructor for syslog.
        :return: None
        """
        if self._connect['syslog'] is True:
            self.warning("Syslog logging is already connected!")
            return
        self._connect['syslog'] = True
        self._syslog_location = syslog_location
        if syslog_log_level is not None:
            self._log_levels['syslog'] = levels[syslog_log_level]
        self._setup_syslog()

    def connect_file(self, file_path, file_log_level=None):
        """
        External-access function for setting up Logstash AFTER construction of I24Logger.
        :param file_path: Since file log was not set up at construction, need to pass in a path for it.
        :param file_log_level: File log level as string; overrides any level specified in constructor for file.
        :return: None
        """
        if self._connect['file'] is True:
            self.warning("File logging is already connected!")
            return
        self._connect['file'] = True
        self._logfile_path = file_path
        if file_log_level is not None:
            self._log_levels['file'] = levels[file_log_level]
        self._setup_file()

    def connect_console(self, console_log_level=None):
        """
        External-access function for setting up console AFTER construction of I24Logger.
        :param console_log_level: Console log level as string; overrides any level specified in constructor for console.
        :return: None
        """
        if self._connect['console'] is True:
            self.warning("Console logging is already connected!")
            return
        self._connect['console'] = True
        if console_log_level is not None:
            self._log_levels['console'] = levels[console_log_level]
        self._setup_console()

    def _setup_logstash(self):
        """
        Attaches a Logstash asynchronous handler, which executes transactions without blocking primary code. Uses
            connection information given in the I24Logger constructor. Log level is also set in the constructor.
            Formatter is currently the LogstashFormatter with only `message_type='python-logstash'`, which appears
             to be purely cosmetic and not a behavior change.
        :return: None
        """
        # Set database_path to None to use in-memory caching.
        logstash_host, logstash_port = self._logstash_addr
        lsth = AsynchronousLogstashHandler(logstash_host, logstash_port, database_path=None)
        lsth.setLevel(self._log_levels['logstash'])
        # Not using the "extra" feature of the LogstashFormatter, since we already have the desired merge behavior
        #   in our own logger object.
        lstf = LogstashFormatter(message_type='python-logstash', extra_prefix=None)
        lsth.setFormatter(lstf)
        self._logger.addHandler(lsth)

    def _setup_syslog(self, elastic_format: bool = False):
        """
        Attaches a syslog handler for this machine. The path of the syslog is needed in the I24Logger constructor, since
            platforms have different destinations (e.g., Mac appears to be '/var/run/syslog' and Linux is usually
            '/var/log/syslog'). There are two formatting options: ECS, which makes logs easily importable into Elastic,
            and a default time/level/name/message/extra line format.
        :param elastic_format: True/False to use Elastic-compatible formatting.
        :return: None
        """
        sysh = SysLogHandler(address=self._syslog_location, socktype=socket.SOCK_STREAM)
        sysh.setLevel(self._log_levels['syslog'])
        if elastic_format is True:
            ecsfmt = ecs_logging.StdlibFormatter()
            sysh.setFormatter(ecsfmt)
        else:
            # Other fields may include: %(module)s, %(processName)s, %(thread)d, %(threadName)s
            fmtstr = '%(asctime)s | %(levelname)s | %(name)s | %(process)d | %(message)s | %(extra)s'
            exfmt = logging.Formatter(fmtstr)
            sysh.setFormatter(exfmt)
        self._logger.addHandler(sysh)

    def _setup_file(self, elastic_format: bool = False):
        """
        Attaches a non-rotating file handler. The file path is given during I24Logger construction. Formatting is by
            default a simple line of information that is easily readble, but can also be made compatible with Elastic.
        :param elastic_format: True/False to use Elastic-compatible formatting.
        :return: None
        """
        flh = logging.FileHandler(filename=self._logfile_path)
        flh.setLevel(self._log_levels['file'])
        if elastic_format is True:
            ecsfmt = ecs_logging.StdlibFormatter()
            flh.setFormatter(ecsfmt)
        else:
            # Other fields may include: %(module)s, %(processName)s, %(thread)d, %(threadName)s
            # Process ID (%(process)d) was not included, since the files are separated already by process.
            fmtstr = '%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(extra)s'
            exfmt = logging.Formatter(fmtstr)
            flh.setFormatter(exfmt)
        self._logger.addHandler(flh)

    def _setup_console(self, stdout_max_level=logging.INFO):
        """
        Attaches a STDOUT/STDERR handler. Messages at INFO/DEBUG level are handled through STDOUT and WARNING and higher
            are handled through STDERR in order to take advantage of typically built-in formatting (e.g., red text).
            That filtering is accomplished through the custom MaxLevelFilter, which can be set with `stdout_max_level`.
        :param stdout_max_level: Option to set STDOUT max log level, everything higher goes to STDERR. *Not currently
            configurable/implemented in constructor.*
        :return: None
        """
        if stdout_max_level not in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL):
            raise ValueError("Must provide valid logging level for maximum log level to STDOUT.")
        fmtstr = '%(levelname)s | %(name)s | %(process)d | %(message)s | %(extra)s'
        csfmt = logging.Formatter(fmtstr)
        if self._log_levels['console'] <= logging.INFO:
            outh = logging.StreamHandler(stream=sys.stdout)
            outh.setLevel(self._log_levels['console'])
            outh.addFilter(filter=MaxLevelFilter(level=stdout_max_level))
            outh.setFormatter(csfmt)
            self._logger.addHandler(outh)
        errh = logging.StreamHandler(stream=sys.stderr)
        errh.setLevel(max(self._log_levels['console'], logging.WARNING))
        errh.setFormatter(csfmt)
        self._logger.addHandler(errh)

    def debug(self, message: Union[str, BaseException], extra: Union[dict, None] = None, exc_info: bool = False):
        """
        Logs a message at the DEBUG level, which is the lowest order of precedence.
        Anything given in `extra` is merged with the values in the I24Logger constructor. This is the location in
            which contextual information should be passed. This allows, particularly in LogStash, this information
            to be separated automatically from the log message and to maintain its type. For example, one might include
            information about processing rate (e.g., frames per second, trajectories per minute) or status of monitored
            assets (e.g., cameras).
        In order to log an exception traceback, pass the exception or a message as `message`, and set `exc_info`=True;
            or write a message and pass the exception object as `exc_info`. Support is available for just setting
            `exc_info`=True and letting `logging` automatically gather the traceback, but it is recommended to be
            explicit about including the exception.
        ```
        try:
            raise ValueError("Parameter invalid.")
        except ValueError as e:
            my_logger.warning(e, exc_info=True)                     # Option 1
            my_logger.warning("Got an exception!", exc_info=e)      # Option 2
        ```
        :param message: Either a log message as a string, or an exception.
        :param extra: Dictionary of extra contextual information about the log message.
        :param exc_info: True/False to automatically include exception info, or the exception itself (recommended).
        :return: None
        """
        extra = extra if extra is not None else {}
        self._logger.debug(message, extra={**self._default_logger_extra, **extra}, exc_info=exc_info)

    def info(self, message: Union[str, BaseException], extra: Union[dict, None] = None, exc_info: bool = False):
        """
        Logs a message at the INFO level. See .debug(...) for more information.
        """
        extra = extra if extra is not None else {}
        self._logger.info(message, extra={**self._default_logger_extra, **extra}, exc_info=exc_info)

    def warning(self, message: Union[str, BaseException], extra: Union[dict, None] = None, exc_info: bool = False):
        """
        Logs a message at the WARNING level. See .debug(...) for more information.
        """
        extra = extra if extra is not None else {}
        self._logger.warning(message, extra={**self._default_logger_extra, **extra}, exc_info=exc_info)

    def error(self, message: Union[str, BaseException], extra: Union[dict, None] = None, exc_info: bool = False):
        """
        Logs a message at the ERROR level. See .debug(...) for more information.
        """
        extra = extra if extra is not None else {}
        self._logger.error(message, extra={**self._default_logger_extra, **extra}, exc_info=exc_info)

    def critical(self, message: Union[str, BaseException], extra: Union[dict, None] = None, exc_info: bool = False):
        """
        Logs a message at the CRITICAL level. See .debug(...) for more information.
        """
        extra = extra if extra is not None else {}
        self._logger.critical(message, extra={**self._default_logger_extra, **extra}, exc_info=exc_info)

    def log(self, level: str, message: Union[str, BaseException],
            extra: Union[dict, None] = None, exc_info: bool = False):
        """
        Logs a message at the level specified in `level` (as a string). Otherwise, behavior is the same as .debug(...).
        """
        level_upper = level.upper()
        if level_upper == 'DEBUG':
            self.debug(message=message, extra=extra, exc_info=exc_info)
        elif level_upper == 'INFO':
            self.info(message=message, extra=extra, exc_info=exc_info)
        elif level_upper == 'WARNING':
            self.warning(message=message, extra=extra, exc_info=exc_info)
        elif level_upper == 'ERROR':
            self.error(message=message, extra=extra, exc_info=exc_info)
        elif level_upper == 'CRITICAL':
            self.critical(message=message, extra=extra, exc_info=exc_info)

    def set_name(self,name):
        self._logger.name = name

        
    def __del__(self):
        for h in reversed(self._logger.handlers):
            h.close()
            logging._removeHandlerRef(h)
            del h 
        self._logger.handlers.clear()
        self._logger.handlers = []
        del self._logger

def connect_automatically(user_settings = {}):
    """
    Function for automatically connecting a logger upon import of this module. In the future, this could check for
    some system or environment variable or configuration, but fall back to the default console logger.
    :param user_settings (dict) overrides for default settings listed in `params`
    """   
    
    params = {"log_name":"defaultlog",
              "processing_environment":None,
              "connect_logstash":False,
              "logstash_address":('10.2.218.61',5000),
              "connect_syslog":False,
              "connect_file":False,
              "connect_console":True, 
              "console_log_level":'DEBUG'
              }
    
    # override defaults as specified
    for key in params.keys():
        if key in user_settings.keys():
            params[key] = user_settings[key]
        
    global logger
    logger =  I24Logger(**params)

def catch_critical(errors=(Exception, ), default_value=''):

    def decorator(func):

        def new_func(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except errors as e:
                stacktrace = traceback.format_exc()
                logger.critical(e,extra={"stacktrace":stacktrace})
                print()
                return default_value

        return new_func

    return decorator

connect_automatically(user_settings = {"connect_logstash":True})


@critical(errors = (Exception))
def test_function():
    raise Exception("Test Exception using catch_critical")