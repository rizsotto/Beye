# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
""" This module is a collection of methods commonly used in this project. """
import collections
import functools
import json
import logging
import os
import os.path
import re
import shlex
import subprocess
import sys
import pprint

from typing import List, Any, Dict, Callable  # noqa: ignore=F401

ENVIRONMENT_KEY = 'INTERCEPT_BUILD'

Execution = collections.namedtuple('Execution', ['pid', 'cwd', 'cmd'])


def shell_split(string):
    # type: (str) -> List[str]
    """ Takes a command string and returns as a list. """

    def unescape(arg):
        # type: (str) -> str
        """ Gets rid of the escaping characters. """

        if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] == '"':
            return re.sub(r'\\(["\\])', r'\1', arg[1:-1])
        return re.sub(r'\\([\\ $%&\(\)\[\]\{\}\*|<>@?!])', r'\1', arg)

    return [unescape(token) for token in shlex.split(string)]


def run_build(command, *args, **kwargs):
    # type: (...) -> int
    """ Run and report build command execution

    :param command: list of tokens
    :return: exit code of the process
    """
    environment = kwargs.get('env', os.environ)
    logging.debug('run build %s, in environment:\n%s',
                  command,
                  pprint.pformat(environment, indent=1, width=79))
    exit_code = subprocess.call(command, *args, **kwargs)
    logging.debug('build finished with exit code: %d', exit_code)
    return exit_code


def run_command(command, cwd=None):
    # type: (List[str], str) -> List[str]
    """ Run a given command and report the execution.

    :param command: array of tokens
    :param cwd: the working directory where the command will be executed
    :return: output of the command
    """
    def decode_when_needed(result):
        # type: (Any) -> str
        """ check_output returns bytes or string depend on python version """
        if not isinstance(result, str):
            return result.decode('utf-8')
        return result

    try:
        directory = os.path.abspath(cwd) if cwd else os.getcwd()
        logging.debug('exec command %s in %s', command, directory)
        output = subprocess.check_output(command,
                                         cwd=directory,
                                         stderr=subprocess.STDOUT)
        return decode_when_needed(output).splitlines()
    except subprocess.CalledProcessError as ex:
        ex.output = decode_when_needed(ex.output).splitlines()
        raise ex


def reconfigure_logging(verbose_level):
    """ Reconfigure logging level and format based on the verbose flag.

    :param verbose_level: number of `-v` flags received by the command
    :return: no return value
    """
    # exit when nothing to do
    if verbose_level == 0:
        return

    root = logging.getLogger()
    # tune level
    if verbose_level == -1:
        level = logging.ERROR
    else:
        level = logging.WARNING - min(logging.WARNING, (10 * verbose_level))
    root.setLevel(level)
    # be verbose with messages
    if verbose_level <= 3:
        fmt_string = '%(name)s: %(levelname)s: %(message)s'
    else:
        fmt_string = '%(name)s: %(levelname)s: %(funcName)s: %(message)s'
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt=fmt_string))
    root.handlers = [handler]


def command_entry_point(function):
    # type: (Callable[[], int]) -> Callable[[], int]
    """ Decorator for command entry methods.

    The decorator initialize/shutdown logging and guard on programming
    errors (catch exceptions).

    The decorated method can have arbitrary parameters, the return value will
    be the exit code of the process. """

    @functools.wraps(function)
    def wrapper():
        # type: () -> int
        """ Do housekeeping tasks and execute the wrapped method. """

        try:
            logging.basicConfig(format='%(name)s: %(message)s',
                                level=logging.WARNING,
                                stream=sys.stdout)
            # this hack to get the executable name as %(name)
            logging.getLogger().name = os.path.basename(sys.argv[0])
            return function()
        except KeyboardInterrupt:
            logging.warning('Keyboard interrupt')
            return 130  # signal received exit code for bash
        except (OSError, subprocess.CalledProcessError):
            logging.exception('Internal error.')
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.error("Please report this bug and attach the output "
                              "to the bug report")
            else:
                logging.error("Please run this command again and turn on "
                              "verbose mode (add '-vvvv' as argument).")
            return 64  # some non used exit code for internal errors
        finally:
            logging.shutdown()

    return wrapper


def wrapper_entry_point(function):
    # type: (Callable[[int, Execution], None]) -> Callable[[], int]
    """ Implements compiler wrapper base functionality.

    A compiler wrapper executes the real compiler, then implement some
    functionality, then returns with the real compiler exit code.

    :param function: the extra functionality what the wrapper want to
    do on top of the compiler call. If it throws exception, it will be
    caught and logged.
    :return: the exit code of the real compiler.

    The :param function: will receive the following arguments:

    :result:       the exit code of the compilation.
    :execution:    the command executed by the wrapper. """

    def is_cxx_wrapper():
        # type: () -> bool
        """ Find out was it a C++ compiler call. Compiler wrapper names
        contain the compiler type. C++ compiler wrappers ends with `c++`,
        but might have `.exe` extension on windows. """

        wrapper_command = os.path.basename(sys.argv[0])
        return True if re.match(r'(.+)c\+\+(.*)', wrapper_command) else False

    def run_compiler(executable):
        # type: (List[str]) -> int
        """ Execute compilation with the real compiler. """

        command = executable + sys.argv[1:]
        logging.debug('compilation: %s', command)
        result = subprocess.call(command)
        logging.debug('compilation exit code: %d', result)
        return result

    @functools.wraps(function)
    def wrapper():
        # type: () -> int
        """ It executes the compilation and calls the wrapped method. """

        # get relevant parameters from environment
        parameters = json.loads(os.environ[ENVIRONMENT_KEY])
        reconfigure_logging(parameters['verbose'])
        # execute the requested compilation and crash if anything goes wrong
        cxx = is_cxx_wrapper()
        compiler = parameters['cxx'] if cxx else parameters['cc']
        result = run_compiler(compiler)
        # call the wrapped method and ignore it's return value
        try:
            call = Execution(
                pid=os.getpid(),
                cwd=os.getcwd(),
                cmd=['c++' if cxx else 'cc'] + sys.argv[1:])
            function(result, call)
        except (OSError, subprocess.CalledProcessError):
            logging.exception('Compiler wrapper failed complete.')
        # always return the real compiler exit code
        return result

    return wrapper


def wrapper_environment(args):
    # type: (...) -> Dict[str, str]
    """ Set up environment for interpose compiler wrapper."""

    return {
        ENVIRONMENT_KEY: json.dumps({
            'verbose': args.verbose,
            'cc': shell_split(args.cc),
            'cxx': shell_split(args.cxx)
        })
    }
