# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
""" This module is responsible to capture the compiler invocation of any
build process. The result of that should be a compilation database.

This implementation is using the LD_PRELOAD or DYLD_INSERT_LIBRARIES
mechanisms provided by the dynamic linker. The related library is implemented
in C language and can be found under 'libear' directory.

The 'libear' library is capturing all child process creation and logging the
relevant information about it into separate files in a specified directory.
The parameter of this process is the output directory name, where the report
files shall be placed. This parameter is passed as an environment variable.

The module also implements compiler wrappers to intercept the compiler calls.

The module implements the build command execution and the post-processing of
the output files, which will condensates into a compilation database. """

import itertools
import json
import logging
import os
import os.path
import re
import sys
import uuid
import subprocess
import argparse  # noqa: ignore=F401
from typing import Iterable, Dict, Tuple, List  # noqa: ignore=F401

from libear import build_libear, temporary_directory
from libscanbuild import command_entry_point, wrapper_entry_point, \
    wrapper_environment, run_build, run_command, Execution, shell_split
from libscanbuild.arguments import parse_args_for_intercept_build
from libscanbuild.compilation import Compilation, CompilationDatabase

__all__ = ['capture', 'intercept_build', 'intercept_compiler_wrapper']

COMPILER_WRAPPER_CC = 'intercept-cc'
COMPILER_WRAPPER_CXX = 'intercept-c++'
TRACE_FILE_PREFIX = 'execution.'  # same as in ear.c
WRAPPER_ONLY_PLATFORMS = ('win32', 'cygwin')


@command_entry_point
def intercept_build():
    # type: () -> int
    """ Entry point for 'intercept-build' command. """

    args = parse_args_for_intercept_build()
    exit_code, current = capture(args)

    # To support incremental builds, it is desired to read elements from
    # an existing compilation database from a previous run.
    if args.append and os.path.isfile(args.cdb):
        previous = CompilationDatabase.load(args.cdb)
        entries = iter(set(itertools.chain(previous, current)))
        CompilationDatabase.save(args.cdb, entries)
    else:
        CompilationDatabase.save(args.cdb, current)

    return exit_code


def capture(args):
    # type: (argparse.Namespace) -> Tuple[int, Iterable[Compilation]]
    """ Implementation of compilation database generation.

    :param args:    the parsed and validated command line arguments
    :return:        the exit status of build process. """

    with temporary_directory(prefix='intercept-') as tmp_dir:
        # run the build command
        environment = setup_environment(args, tmp_dir)
        exit_code = run_build(args.build, env=environment)
        # read the intercepted exec calls
        calls = (parse_exec_trace(file) for file in exec_trace_files(tmp_dir))
        current = compilations(calls, args.cc, args.cxx)

        return exit_code, iter(set(current))


def compilations(exec_calls, cc, cxx):
    # type: (Iterable[Execution], str, str) -> Iterable[Compilation]
    """ Needs to filter out commands which are not compiler calls. And those
    compiler calls shall be compilation (not pre-processing or linking) calls.
    Plus needs to find the source file name from the arguments.

    :param exec_calls:  iterator of executions
    :param cc:          user specified C compiler name
    :param cxx:         user specified C++ compiler name
    :return: stream of formatted compilation database entries """

    for call in exec_calls:
        for compilation in Compilation.iter_from_execution(call, cc, cxx):
            yield compilation


def setup_environment(args, destination):
    # type: (argparse.Namespace, str) -> Dict[str, str]
    """ Sets up the environment for the build command.

    In order to capture the sub-commands (executed by the build process),
    it needs to prepare the environment. It's either the compiler wrappers
    shall be announce as compiler or the intercepting library shall be
    announced for the dynamic linker.

    :param args:        command line arguments
    :param destination: directory path for the execution trace files
    :return: a prepared set of environment variables. """

    use_wrapper = args.override_compiler or is_preload_disabled(sys.platform)

    environment = dict(os.environ)
    environment.update({'INTERCEPT_BUILD_TARGET_DIR': destination})

    if use_wrapper:
        environment.update(wrapper_environment(args))
        environment.update({
            'CC': COMPILER_WRAPPER_CC,
            'CXX': COMPILER_WRAPPER_CXX,
        })
    else:
        libear_cc = args.libear_cc if 'libear_cc' in args else args.cc
        intercept_library = build_libear(libear_cc, destination)
        if sys.platform == 'darwin':
            environment.update({
                'DYLD_INSERT_LIBRARIES': intercept_library,
                'DYLD_FORCE_FLAT_NAMESPACE': '1'
            })
        else:
            environment.update({'LD_PRELOAD': intercept_library})

    return environment


@command_entry_point
@wrapper_entry_point
def intercept_compiler_wrapper(_, execution):
    # type: (int, Execution) -> None
    """ Entry point for `intercept-cc` and `intercept-c++` compiler wrappers.

    It does generate execution report into target directory.
    The target directory name is from environment variables. """

    message_prefix = 'execution report might be incomplete: %s'

    target_dir = os.getenv('INTERCEPT_BUILD_TARGET_DIR')
    if not target_dir:
        logging.warning(message_prefix, 'missing target directory')
        return
    # write current execution info to the pid file
    try:
        target_file_name = TRACE_FILE_PREFIX + str(uuid.uuid4())
        target_file = os.path.join(target_dir, target_file_name)
        logging.debug('writing execution report to: %s', target_file)
        write_exec_trace(target_file, execution)
    except IOError:
        logging.warning(message_prefix, 'io problem')


def expand_cmd_with_response_files(cmd):
    # type: (List[str]) -> List[str]
    """ Expand's response file parameters into actual parameters

    MSVC's cl and clang-cl has functionality to prevent too long command lines
    by reading options from so called temporary "response" files. These files
    are ascii encoded and can contain compiler and linker flags and/or
    compilation units.

    For example, QT's qmake generates nmake based makefiles where the response
    file contains all compilation units. """

    def is_response_file(param):
        # type: (str) -> bool
        """ Checks if the given command line argument is response file. """
        return param[0] == '@' and os.path.isfile(param[1:])

    def from_response_file(filename):
        # type: (str) -> List[str]
        """ Read and return command line argument list from response file.

        Might throw IOException when file operations fails. """
        with open(filename[1:], 'r') as file_handle:
            return [arg.strip() for arg in shell_split(file_handle.read())]

    def update_if_needed(arg):
        # type: (str) -> List[str]
        """ Returns [n,] thats either read from response or has single arg """
        return from_response_file(arg) if is_response_file(arg) else [arg]

    return [n for row in [update_if_needed(arg) for arg in cmd] for n in row]


def write_exec_trace(filename, entry):
    # type: (str, Execution) -> None
    """ Write execution report file.

    This method shall be sync with the execution report writer in interception
    library. The entry in the file is a JSON objects.

    :param filename:    path to the output execution trace file,
    :param entry:       the Execution object to append to that file. """

    call = {'pid': entry.pid, 'cwd': entry.cwd,
            'cmd': expand_cmd_with_response_files(entry.cmd)}
    with open(filename, 'w') as handler:
        json.dump(call, handler)


def parse_exec_trace(filename):
    # type: (str) -> Execution
    """ Parse execution report file.

    Given filename points to a file which contains the basic report
    generated by the interception library or compiler wrapper.

    :param filename: path to an execution trace file to read from,
    :return: an Execution object. """

    logging.debug('parse exec trace file: %s', filename)
    with open(filename, 'r') as handler:
        entry = json.load(handler)
        return Execution(
            pid=entry['pid'],
            cwd=entry['cwd'],
            cmd=entry['cmd'])


def exec_trace_files(directory):
    # type: (str) -> Iterable[str]
    """ Generates exec trace file names.

    :param directory:   path to directory which contains the trace files.
    :return:            a generator of file names (absolute path). """

    for root, _, files in os.walk(directory):
        for candidate in files:
            if candidate.startswith(TRACE_FILE_PREFIX):
                yield os.path.join(root, candidate)


def is_preload_disabled(platform):
    # type: (str) -> bool
    """ Library-based interposition will fail silently if SIP is enabled,
    so this should be detected. You can detect whether SIP is enabled on
    Darwin by checking whether (1) there is a binary called 'csrutil' in
    the path and, if so, (2) whether the output of executing 'csrutil status'
    contains 'System Integrity Protection status: enabled'.

    :param platform: name of the platform (returned by sys.platform),
    :return: True if library preload will fail by the dynamic linker. """

    if platform in WRAPPER_ONLY_PLATFORMS:
        return True
    elif platform == 'darwin':
        command = ['csrutil', 'status']
        pattern = re.compile(r'System Integrity Protection status:\s+enabled')
        try:
            return any(pattern.match(line) for line in run_command(command))
        except (OSError, subprocess.CalledProcessError):
            return False
    else:
        return False
