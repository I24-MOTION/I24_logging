# Custom I-24 Logging package
#### Version: 1.1
#### Date revised: 05/05/2022

### Installation
With the desired python venv / conda env activated, use the following command in shell:

`pip install git+https://github.com/Lab-Work/I24_logging/@<tag>`

where `<tag>` is either a branch name (e.g. `master`) or a tag name (e.g. `v1.1`)
    
Then, using in your python code anywhere is as simple as:

```
from i24_logger.log_writer import logger
logger.debug("Hello World")
```

```
Output: >>> DEBUG | defaultlog | 10382 | Hello World! | {'host': 'lambda-quad4x6000', 'env': 'DEF_ENV'}
```

### Built to accommodate a few custom functional modes within the broader I-24 MOTION software stack

- Asynchronous log messaging to Logstash (Elastic stack) 
- Extra parameter handling and control for Elastic integration
- Maximum level filtering for debugging on console with STDERR
- Development, test, and production environments with pre-configured 

## Logger principles
The typical strategy is to use this logger as it is constructed automatically upon import of the package. The reason
behind this strategy is the avoidance of a verbose construction phase each time a logger is used. The syntax for log
messages remains the same within the codebase.

Upon `import log_writer`, the module-level function `construct_automatically()` is called, which sets the global
instance named `logger`. In this manner, after import, one can call `log_writer.logger.info("A message")`. As a syntax
shortcut, add a pointer/alias to the global instance after your import statement: `l = log_writer.logger`.

This automatic construction is not the only chance to perform logger configuration. One can call the post-construction
`connect_...` functions of the logger (e.g., `log_writer.logger.connect_file('test.log')`). While this begins to
defeat the purpose of the simple logger import syntax, it does, however, allow for logger configuration in the `main`
file and zero configuration in any imported libraries or functions (since they share the same context as `main`).

### In future versions
More work needs to be done on automatic construction of the logger. Currently, the automatic construction is always a
default (log to console, only) and any additional log handlers need to be added with `log_writer.logger.connect_...`.
Possible methods for automatic construction include system or environment variables, config strings, config files, etc.

Additional future enhancements include: 
- The introduction of log schema elements. These would be logged into the `extra`
field of log messages, either in context of the log message (e.g., trajectory IDs) or in the class-level extra
information (which is currently just hostname and environment).
- Better customization attribute setting for the logger. This could go as deep as we want, but at the very least we 
need a good way to set the 'environment' and 'name'. This might end up being unnecessary depending on what is done with
the automatic configuration.

## Usage examples

### Use case 1: Logging within functions imported from another file

The following code demonstrates the use of the I24Logger from within a code `main` and from within functions imported
into that code. For example, consider a separate file of utility or support functions that would also like to integrate
logging capabilities. The log messages retain the context of the `main` process, i.e., reflecting its PID.

```python
import time, os
import log_writer
logger = log_writer.logger

print("My PID is {}.".format(os.getpid()))
logger.debug("First debug message.")
time.sleep(0.5)
logger.info("INFORMATION")
time.sleep(0.5)
import utility_functions
import datetime as dt
utility_functions.to_ole(dt.datetime.now())
time.sleep(0.5)
logger.warning("A WARNING!")
logger.debug("Second debug message.")
```

```python
# file: utility_functions.py
import datetime as dt
import log_writer

def to_ole(timestamp):
    delta = timestamp - dt.datetime(1899, 12, 30)
    ole = float(delta.days) + (float(delta.seconds) / 86400)
    log_writer.logger.info("Converted {} to {}.".format(timestamp, ole), extra={'ole': ole})
    return ole
```

The console log output of the code is the following. Notice the PID in the `extra` field of each message remains the same, even for the imported function.
```
My PID is 98852.
DEBUG | defaultlog | 98852 | First debug message. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV'}
INFO | defaultlog | 98852 | INFORMATION | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV'}
INFO | defaultlog | 98852 | Converted 2022-05-05 13:06:23.878450 to 44686.54609953704. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 'ole': 44686.54609953704}
WARNING | defaultlog | 98852 | A WARNING! | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV'}
DEBUG | defaultlog | 98852 | Second debug message. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV'}
```


### Use case 2: Multiprocess logging

The following conde and log output demonstrates the use of the I24Logger from multiple processes that are forked from a 
manager or existing process. Even if this code lives all within a single file, the logging package is imported/forked 
into each child process with separate context. It exhibits the behavior of two separate instances with distinct PIDs.

```python
import time, os, sys, random
import multiprocessing as mp
import log_writer
logger = log_writer.logger

def child_process():
    while True:
        try:
            wait_time = random.randint(0, 500) / 100
            if wait_time < 0.2:
                raise ValueError("Wait time less than 0.2!")
            time.sleep(wait_time)
            level = random.choice(['INFO', 'DEBUG'])
            logger.log(level=level, message="Finished waiting {} seconds.".format(wait_time), extra={'t': wait_time})
        except ValueError as e:
            logger.warning(e, extra={}, exc_info=True)

def main_process():
    logger.info("Main process logger connected.")
    num_workers = 2
    worker_processes = []
    logger.info("Starting worker processes.", extra={'n': num_workers})
    for i in range(num_workers):
        wp = mp.Process(target=child_process, args=('worker-{}'.format(i),), daemon=True)
        wp.start()
        logger.debug("'{}' started; PID={}.".format(wp.name, wp.pid), extra={'PID': wp.pid})
        worker_processes.append(wp)
    try:
        while True:
            time.sleep(5)
            status = [wp.is_alive() for wp in worker_processes]
            logger.info("Status of worker processes: {}".format(status), extra={})
    except KeyboardInterrupt as e:
        logger.info("Got exit signal via CTRL-C. Exiting.")
        sys.exit()

if __name__ == '__main__':
    main_process()
```

This results in the following output (blank lines and ellipses added for clarity):
```
INFO | defaultlog | 98883 | Main process logger connected. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 'myfield': 'EXTRA WORKS!'}
INFO | defaultlog | 98883 | Starting worker processes. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 'n': 4}
DEBUG | defaultlog | 98883 | 'worker-0' started; PID=98885. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 'PID': 98885}
DEBUG | defaultlog | 98883 | 'worker-1' started; PID=98886. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 'PID': 98886}

DEBUG | defaultlog | 98885 | Finished waiting 1.26 seconds. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 't': 1.26}
INFO | defaultlog | 98886 | Finished waiting 3.81 seconds. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 't': 3.81}

ERROR | defaultlog | 98885 | Wait time less than 0.2! | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV'}
Traceback (most recent call last):
  File "/Users/wbarbour/PycharmProjects/I24_logging/log_test.py", line 28, in test_worker
    raise ValueError("Wait time less than 0.2!")
ValueError: Wait time less than 0.2!

DEBUG | defaultlog | 98886 | Finished waiting 3.91 seconds. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 't': 3.91}
INFO | defaultlog | 98885 | Finished waiting 0.88 seconds. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 't': 0.88}
INFO | defaultlog | 98885 | Finished waiting 2.56 seconds. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV', 't': 2.56}

Process worker-0:
Traceback (most recent call last):
  ...
KeyboardInterrupt

Process worker-1:
Traceback (most recent call last):
  ...
KeyboardInterrupt

INFO | defaultlog | 98883 | Got exit signal via CTRL-C. Exiting. | {'host': 'Wills-MacBook-Pro-2.local', 'env': 'DEF_ENV'}
Process finished with exit code 0
```
