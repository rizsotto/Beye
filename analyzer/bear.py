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
The input of the library is therefore the output directory which is passed
as an environment variable.

This module implements the build command execution with the 'libear' library
and the post-processing of the output files, which will condensates into a
(might be empty) compilation database. """


import logging
import subprocess
import argparse
import json
import sys
import os
import os.path
import re
import glob
import shlex
import pkg_resources
import itertools
from analyzer import create_parser
from analyzer.decorators import to_logging_level, trace, entry
from analyzer.command import parse
from analyzer.command import Action

if 3 != sys.version_info[0]:
    filter = itertools.ifilter
    map = itertools.imap

if 'darwin' == sys.platform:
    ENVIRONMENTS = [("ENV_OUTPUT", "BEAR_OUTPUT"),
                    ("ENV_PRELOAD", "DYLD_INSERT_LIBRARIES"),
                    ("ENV_FLAT", "DYLD_FORCE_FLAT_NAMESPACE")]
else:
    ENVIRONMENTS = [("ENV_OUTPUT", "BEAR_OUTPUT"),
                    ("ENV_PRELOAD", "LD_PRELOAD")]


@entry
def bear():
    """ Entry point for 'bear'.

        This part initializes some parts and forwards to the main method. """

    parser = initialize_command_line(create_parser())
    advanced = parser.add_argument_group('advanced options')
    advanced.add_argument(
        '--append',
        action='store_true',
        help="""Append new entries to existing compilation database.""")
    advanced.add_argument(
        '--disable-filter', '-n',
        dest='raw_entries',
        action='store_true',
        help="""Disable filter, unformated output.""")

    args = parser.parse_args()

    logging.getLogger().setLevel(to_logging_level(args.verbose))
    logging.debug(args)

    if args.help or 0 == len(args.build):
        parser.print_help()
        return 0

    return main(args)


def main(args):
    """ The reusable entry point of 'bear'.

        The 'scan-build' and 'bear' are the two entry points of this code.
        Both provide the parsed argument object as input for this job. """

    def post_processing(entries):
        if 'raw_entries' not in args or not args.raw_entries:
            # create entries from the current run
            current = itertools.chain.from_iterable(
                map(format_entry,
                    # filter out non compiler calls from intercepted execs
                    filter(compiler_call, entries)))
            # read entries from previous run
            if 'append' in args and args.append and os.path.exists(args.cdb):
                with open(args.cdb) as handle:
                    previous = iter(json.load(handle))
            else:
                previous = iter([])
            # filter out duplicate entries from both
            return filter(not_duplicate(), itertools.chain(current, previous))
        return entries

    with TemporaryDirectory(prefix='bear-') as tmpdir:
        # run the build command
        exit_code = run_build(args.build, tmpdir)
        # read the intercepted exec calls
        commands = map(parse_exec_trace,
                       glob.iglob(os.path.join(tmpdir, 'cmd.*')))
        # do post processing when it required
        entries = post_processing(commands)
        # dump the compilation database
        with open(args.cdb, 'w+') as handle:
            json.dump(list(entries), handle, sort_keys=True, indent=4)
        return exit_code


@trace
def initialize_command_line(parser):
    """ Add task related argument to the command line parser. """
    parser.add_argument(
        dest='build',
        nargs=argparse.REMAINDER,
        help="""Command to run.""")

    return parser


@trace
def run_build(command, destination):
    """ Runs the original build command.

    It sets the required environment variables and execute the given command.
    The exec calls will be logged by the 'libear' preloaded library. """

    def get_ear_so_file():
        lib_name = 'libear.dylib' if 'darwin' == sys.platform else 'libear.so'
        return pkg_resources.resource_filename('analyzer', lib_name)

    environment = dict(os.environ)
    for alias, key in ENVIRONMENTS:
        value = '1'
        if alias == 'ENV_PRELOAD':
            value = get_ear_so_file()
        elif alias == 'ENV_OUTPUT':
            value = destination
        environment.update({key: value})

    return subprocess.call(command, env=environment)


@trace
def parse_exec_trace(filename):
    """ Parse the file generated by the 'libear' preloaded library. """
    RS = chr(0x1e)
    US = chr(0x1f)
    with open(filename, 'r') as handler:
        content = handler.read()
        records = content.split(RS)
        return {'pid': records[0],
                'ppid': records[1],
                'function': records[2],
                'directory': records[3],
                'command': records[4].split(US)[:-1]}


@trace
def format_entry(entry):
    """ Generate the desired fields for compilation database entries. """
    def join_command(args):
        """ Create a single string from list.

        The major challenge, which is not solved yet, to deal with white
        spaces. Which are used by the shell as separator.
        (Eg.: -D_KEY="Value with spaces") """
        return ' '.join(args)

    atoms = parse({'command': entry['command']}, lambda x: x)
    if atoms['action'] == Action.Compile:
        for filename in atoms['files']:
            yield {'directory': entry['directory'],
                   'command': join_command(entry['command']),
                   'file': os.path.abspath(filename)}


@trace
def compiler_call(entry):
    """ A predicate to decide the entry is a compiler call or not. """
    def known_compiler(command):
        patterns = [
            re.compile(r'^([^/]*/)*c(c|\+\+)$'),
            re.compile(r'^([^/]*/)*([^-]*-)*g(cc|\+\+)(-[2345].[0-9])?$'),
            re.compile(r'^([^/]*/)*([^-]*-)*clang(\+\+)?(-[23].[0-9])?$'),
            re.compile(r'^([^/]*/)*llvm-g(cc|\+\+)$'),
        ]
        executable = command[0]
        for pattern in patterns:
            if pattern.match(executable):
                return True
        return False

    def cancel_parameter(command):
        patterns = [
            re.compile(r'^-cc1$')
        ]
        for pattern in patterns:
            for arg in command[1:]:
                if pattern.match(arg):
                    return True
        return False

    command = entry['command']
    return known_compiler(command) and not cancel_parameter(command)


def not_duplicate():
    """ Predicate to detect duplicated entries.

    Entries are represented as dictionary, which has no default hash
    method. This method implement one and store it in the given state
    if that was not already stored. """
    def predicate(entry):
        if os.path.exists(entry['file']):
            # On OS X the 'cc' and 'c++' compilers are wrappers for
            # 'clang' therefore both call would be logged. To avoid
            # this the hash does not contain the first word of the
            # command.
            command = ' '.join(shlex.split(entry['command'])[1:])
            # For faster lookup in set filename is reverted
            filename = entry['file'][::-1]
            # For faster lookup in set directory is reverted
            directory = entry['directory'][::-1]

            entry_hash = '<>'.join([filename, directory, command])
            if entry_hash not in predicate.state:
                predicate.state.add(entry_hash)
                return True
        return False

    predicate.state = set()
    return predicate


if sys.version_info.major >= 3 and sys.version_info.minor >= 2:
    from tempfile import TemporaryDirectory
else:
    class TemporaryDirectory(object):
        """ This function creates a temporary directory using mkdtemp() (the
        supplied arguments are passed directly to the underlying function).
        The resulting object can be used as a context manager. On completion
        of the context or destruction of the temporary directory object the
        newly created temporary directory and all its contents are removed
        from the filesystem. """
        def __init__(self, **kwargs):
            from tempfile import mkdtemp
            self.name = mkdtemp(*kwargs)

        def __enter__(self):
            return self.name

        def __exit__(self, _type, _value, _traceback):
            self.cleanup()

        def cleanup(self):
            from shutil import rmtree
            if self.name is not None:
                rmtree(self.name)
