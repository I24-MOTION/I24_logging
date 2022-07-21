import logging
import socket
from logging.handlers import SysLogHandler
from logstash_async.handler import AsynchronousLogstashHandler
from logstash_async.formatter import LogstashFormatter
import ecs_logging
import sys
import os
import struct
import traceback
import configparser
import warnings
import datetime as dt

from typing import Union, Mapping
Address = tuple[str, int]

levels = {'CRITICAL': logging.CRITICAL, 'ERROR': logging.ERROR, 'WARNING': logging.WARNING,
          'INFO': logging.INFO, 'DEBUG': logging.DEBUG, None: None}
# Conversion from Python logging numbers (equivalent to strings) to SwRI StatusLogger defined levels.
sl_levelno_mapping = {0: 4, 10: 3, 20: 2, 30: 1, 40: 0, 50: 0}

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
        rv = logging.Logger.makeRecord(None, name=name, level=level, fn=fn, lno=lno, msg=msg, args=args,
                                       exc_info=exc_info, func=func, extra=extra, sinfo=sinfo)
        # Also add the complete "extra" dictionary as an attribute
        rv.__dict__['extra'] = extra
        return rv


class StatusLoggerHandler(logging.handlers.SocketHandler):
    """
    Send log messages as the defined StatusLogger format, defined below.

    StatusLogger format: [ version (4 bytes UINT) -- OLE timestamp (8 bytes DOUBLE) -- log level (4 bytes UINT) --
        log classification (4 bytes UINT) -- error code (4 bytes INT) -- app name (0-18 bytes MFC string) --
        user name (0-6 bytes MFC string) -- event ID (variable bytes MFC string) -- event descr. (var. bytes MFC string)
        -- message (var. bytes MFC string) ]
    """

    # def __init__(self, *args, **kwargs):
    #    super(StatusLoggerHandler, self).__init__(*args, **kwargs)

    @staticmethod
    def mfc_string(string):
        """
        Format a string in MFC standard byte format.

            For len < 255: single byte length value + string bytes
            For len < 65534: 0xFF + 2-byte length value + string bytes
            Else: 0xFF 0xFF 0xFF + 4-byte length value + string bytes
        :param string: the string to format
        :return: bytes of length indicators and string
        """
        if len(string) < 255:
            return struct.pack('B', len(string)) + bytes(string, 'utf-8')
        elif len(string) < 65534:
            return b'\xff' + struct.pack('H', len(string)) + bytes(string, 'utf-8')
        else:
            return b'\xff\xff\xff' + struct.pack('I', len(string)) + bytes(string, 'utf-8')

    @staticmethod
    def ole_timestamp(timestamp):
        """
        Convert a datetime object into an OLE timestamp.

        OLE timestamp has integer number of days since epoch, plus decimal portion of the seconds elapsed in the day.
        :param timestamp: datetime.datetime object
        :return: float for OLE timestamp
        """
        old_datum = dt.datetime(1899, 12, 30)
        delta = timestamp - old_datum
        return float(delta.days) + (float(delta.seconds) / 86400)

    def makePickle(self, record: logging.LogRecord):
        """
        Make a bytes representation of the message to send to StatusLogger through a custom implementation.

        :param record: a LogRecord object, assumed to be constructed using the ExtraLogger factory implemented here
        :return: buffer of bytes
        """
        ts = self.ole_timestamp(dt.datetime.fromtimestamp(record.created))
        # Start with the version, timestamp as OLE date, log level number, log classification, error code
        buf = struct.pack('<IdIII', 1, ts, sl_levelno_mapping[record.levelno], 0, 0)
        # Add app name, user name, and host name
        buf += self.mfc_string('AI-DSS') + self.mfc_string('Vanderbilt') + self.mfc_string('wbarbour')
        # Add event ID, event description
        # TODO: Test the lookup of these parameters from the "extra" field of the log record...make sure record factory is working correct.
        buf += self.mfc_string('event ID') + self.mfc_string('event description')
        # buf += self.mfc_string(record.extra.get('eventID', 'None'))
        # buf += self.mfc_string(record.extra.get('eventDesc', 'None'))
        buf += self.mfc_string(record.msg)
        buf = bytearray(buf)
        return buf


class I24Logger:
    """
    This unified interface is used to abstract log setup from other code modules,
        which we want to have consistent behavior.
    """

    # Python 3.8 compatibility mode...add other typehints if minimum version changes.
    def __init__(self, log_name: str = None, processing_environment: str = None,
                 connect_logstash: bool = False, connect_file: bool = False,
                 connect_syslog: bool = False, connect_console: bool = False, connect_sl: bool = False,
                 logstash_address: Address = None, sl_address: Address = None,
                 file_path: str = None, syslog_location: str = None,
                 all_log_level: str = 'DEBUG', logstash_log_level=None, file_log_level=None,
                 syslog_log_level=None, console_log_level=None, sl_log_level=None):
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
        :param connect_sl: True/False to connect to SwRI StatusLogger.
        :param logstash_address: (host, port) tuple for Logstash connection.
        :param sl_address: (host, port) tuple for StatusLogger connection.
        :param file_path: Path (absolute or relative) and file name of the log file to write; directories not created.
        :param syslog_location: Path to syslog.
        :param all_log_level: Available to set a global log level across all handlers; overridden by handler-specific.
        :param logstash_log_level: Logstash log level as string; overrides `all_log_level`.
        :param file_log_level: File log level as string; overrides `all_log_level`.
        :param syslog_log_level: Syslog log level as string; overrides `all_log_level`.
        :param console_log_level: Console log level as string; overrides `all_log_level`.
        :param sl_log_level: StatusLogger log level as string (Python convention); overrides `all_log_level`.
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
        self._statuslogger_addr = sl_address
        self._logfile_path = file_path if file_path is not None else '{}_{}.log'.format(self._name, os.getpid())
        self._syslog_location = syslog_location

        # No need to put in owner process name/ID or parent, since this information will be in the logger name or
        #   the LogRecord attributes.
        self._default_logger_extra = {'host': self._hostname, 'env': self._environment}

        if not all([ll in levels.keys() for ll in
                    (logstash_log_level, file_log_level, syslog_log_level, console_log_level, sl_log_level)]):
            raise ValueError("Invalid log level specified. Use: 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', None.")
        self._log_levels = {'logstash': (levels[logstash_log_level] if logstash_log_level is not None
                                         else levels[all_log_level]),
                            'file': (levels[file_log_level] if file_log_level is not None
                                     else levels[all_log_level]),
                            'syslog': (levels[syslog_log_level] if syslog_log_level is not None
                                       else levels[all_log_level]),
                            'console': (levels[console_log_level] if console_log_level is not None
                                        else levels[all_log_level]),
                            'statuslogger': (levels[sl_log_level] if sl_log_level is not None
                                             else levels[all_log_level]),
                            }
        self._connect = {'logstash': connect_logstash, 'file': connect_file, 'syslog': connect_syslog,
                         'console': connect_console, 'statuslogger': connect_sl}

        if self._connect['logstash'] is True and self._log_levels['logstash'] is None:
            raise ValueError("Logstash logging activated, but no log level specified during construction.")
        if self._connect['file'] is True and self._log_levels['file'] is None:
            raise ValueError("File logging activated, but no log level specified during construction.")
        if self._connect['syslog'] is True and self._log_levels['syslog'] is None:
            raise ValueError("Syslog logging activated, but no log level specified during construction.")
        if self._connect['console'] is True and self._log_levels['console'] is None:
            raise ValueError("Console logging activated, but no log level specified during construction.")
        if self._connect['statuslogger'] is True and self._log_levels['statuslogger'] is None:
            raise ValueError("StatusLogger logging activated, but no log level specified during construction.")

        if self._connect['logstash'] is True and self._logstash_addr is None:
            raise ValueError("Logstash logging activated, but no connection address given (host, port).")
        if self._connect['file'] is True and (self._logfile_path is None or self._logfile_path == ''):
            raise ValueError("File logging activated, but no file path given.")
        if self._connect['syslog'] is True and self._syslog_location is None:
            raise ValueError("Syslog logging activated, but no location (path or host/port tuple) given.")
        if self._connect['statuslogger'] is True and self._statuslogger_addr is None:
            raise ValueError("StatusLogger logging activated, but no connection address given (host, port).")

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
        if self._connect['statuslogger'] is True:
            self._setup_statuslogger()

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

    def connect_statuslogger(self, sl_address: Address, sl_log_level=None):
        """
        External-access function for setting up StatusLogger AFTER construction of I24Logger.
        :param sl_address: Since StatusLogger was not setup during construction, need (host, port) address.
        :param  sl_log_level: StatusLogger log level as string (Python convention); overrides any level specified in
            constructor for StatusLogger.
        :return: None
        """
        if self._connect['statuslogger'] is True:
            self.warning("StatusLogger logging is already connected!")
            return
        self._connect['statuslogger'] = True
        self._statuslogger_addr = sl_address
        if sl_log_level is not None:
            self._log_levels['statuslogger'] = levels[sl_log_level]
        self._setup_statuslogger()

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
        fmtstr = '%(levelname)s | %(name)s | %(process)d | %(message)s '#|  %(extra)s'
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

    def _setup_statuslogger(self):
        """
        Create an instance of the custom StatusLoggerHandler class, which is a subclass of SocketHandler. Uses
            connection information given in the I24Logger constructor. Log level is also set in the constructor.
            Formatter is implicit in `makePickle` function, which packs log messages in bytes representation for
            transmittal to StatusLogger.
        :return: None
        """
        sl_host, sl_port = self._statuslogger_addr
        slh = StatusLoggerHandler(host=sl_host, port=sl_port)
        slh.setLevel(self._log_levels['statuslogger'])
        self._logger.addHandler(slh)

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

    def set_name(self, name):
        self._logger.name = name

    def __del__(self):
        for h in reversed(self._logger.handlers):
            h.close()
            try:
                logging._removeHandlerRef(h)
            except:
                pass
            del h 
        self._logger.handlers.clear()
        self._logger.handlers = []
        del self._logger


def connect_automatically(user_settings={}):
    """
    Function for automatically connecting a logger upon import of this module. In the future, this could check for
    some system or environment variable or configuration, but fall back to the default console logger.
    :param user_settings (dict) overrides for default settings listed in `params`
    """   
    
    params = {"log_name": "defaultlog",
              "processing_environment": None,
              "connect_logstash": False,
              "logstash_address": ('10.2.218.61', 5000),
              "connect_syslog": False,
              "connect_file": False,
              "connect_console": True,
              "connect_sl": False,
              "console_log_level": 'DEBUG'
              }

    if len(user_settings.keys()) == 0:
        try:
            config_file = os.path.join(os.environ["USER_CONFIG_DIRECTORY"],"logger.config")
            
            try:
                SECTION = os.environ["USER_CONFIG_SECTION"]
            except:
                SECTION = "DEFAULT"
            
            # load config here
            config = configparser.ConfigParser()
            config.read(config_file)
            user_settings = dict(config["DEFAULT"])
            
            user_settings["processing_environment"] = SECTION
            user_settings["connect_logstash"] = True if user_settings["connect_logstash"] == "True" else False
            user_settings["connect_syslog"] = True if user_settings["connect_syslog"] == "True" else False
            user_settings["connect_file"] = True if user_settings["connect_file"] == "True" else False
            user_settings["connect_console"] = True if user_settings["connect_console"] == "True" else False
            lsa = user_settings["logstash_address"]  
            user_settings["logstash_address"] = (lsa.split(",")[0], int(lsa.split(",")[1]))
        except:
            pass
        
    # override defaults as specified
    for key in params.keys():
        if key in user_settings.keys():
            params[key] = user_settings[key]

    global logger
    logger = I24Logger(**params)
        
    return logger


# %% decorators
def catch_critical(errors=(Exception, )):

    def decorator(func):

        def new_func(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except errors as e:
                stacktrace = traceback.format_exc()
                logger.critical("Knock knock. Who's there? {}".format(type(e).__name__),
                                extra={"stacktrace": stacktrace})
                
                # raise the original error
                raise e

        return new_func

    return decorator


def log_errors(errors=(Exception,), default_value=None):
    def decorator(func):

        def new_func(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except errors as e:
                stacktrace = traceback.format_exc()
                logger.error(e, extra={"stacktrace": stacktrace})
                return default_value
        return new_func

    return decorator


def log_warnings():
    def decorator(func):
        
        def new_func(*args, **kwargs):
            with warnings.catch_warnings(record=True) as w:
                
                out = func(*args, **kwargs)

                if len(w) > 0:
                    for item in w:
                        logger.warning("{} raised.".format(item.category),extra = {"warn_category":item.category,"warn_message":item.message,"stacktrace":traceback.format_exc()})
                return out

        return new_func

    return decorator


connect_automatically()


# %% decorator tests
@catch_critical(errors=(Exception))
def test_function():
    raise Exception("Test Exception using catch_critical")
    
    
@log_warnings()
def test_function2():
    warnings.warn("Test Warning using log_warnings")
    print("Function continued execution after warning")
    return -1

@log_errors(errors=(ValueError))
def test_function3():
    raise ValueError("Test ValueError using log_errors")
