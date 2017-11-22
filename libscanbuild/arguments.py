# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
""" This module parses and validates arguments for command-line interfaces.

It uses argparse module to create the command line parser. (This library is
in the standard python library since 3.2 and backported to 2.7, but not
earlier.)

It also implements basic validation methods, related to the command.
Validations are mostly calling specific help methods, or mangling values.
"""

import os
import sys
import argparse
import logging
import tempfile
from typing import Tuple, Dict  # noqa: ignore=F401

from libscanbuild import reconfigure_logging
from libscanbuild.clang import get_checkers


__all__ = ['parse_args_for_analyze_build']


def parse_args_for_analyze_build():
    # type: () -> argparse.Namespace
    """ Parse and validate command-line arguments for analyze-build. """

    parser = create_analyze_parser()
    args = parser.parse_args()

    reconfigure_logging(args.verbose)
    logging.debug('Raw arguments %s', sys.argv)

    normalize_args_for_analyze(args)
    validate_args_for_analyze(parser, args)
    logging.debug('Parsed arguments: %s', args)
    return args


def normalize_args_for_analyze(args):
    # type: (argparse.Namespace) -> None
    """ Normalize parsed arguments for analyze-build and scan-build.

    :param args: Parsed argument object. (Will be mutated.) """

    # make plugins always a list. (it might be None when not specified.)
    if args.plugins is None:
        args.plugins = []

    # make exclude directory list unique and absolute.
    uniq_excludes = set(os.path.abspath(entry) for entry in args.excludes)
    args.excludes = list(uniq_excludes)


def validate_args_for_analyze(parser, args):
    # type: (argparse.ArgumentParser, argparse.Namespace) -> None
    """ Command line parsing is done by the argparse module, but semantic
    validation still needs to be done. This method is doing it for
    analyze-build and scan-build commands.

    :param parser: The command line parser object.
    :param args: Parsed argument object.
    :return: No return value, but this call might throw when validation
    fails. """

    if args.help_checkers_verbose:
        print_checkers(get_checkers(args.clang, args.plugins))
        parser.exit(status=0)
    elif args.help_checkers:
        print_active_checkers(get_checkers(args.clang, args.plugins))
        parser.exit(status=0)
    elif not os.path.exists(args.cdb):
        parser.error(message='compilation database is missing')


def create_analyze_parser():
    # type: () -> argparse.ArgumentParser
    """ Creates a parser for command-line arguments to 'analyze'. """

    parser = create_default_parser()

    parser.add_argument(
        '--cdb',
        metavar='<file>',
        default="compile_commands.json",
        help="""The JSON compilation database.""")

    parser.add_argument(
        '--status-bugs',
        action='store_true',
        help="""The exit status of '%(prog)s' is the same as the executed
        build command. This option ignores the build exit status and sets to
        be non zero if it found potential bugs or zero otherwise.""")
    parser.add_argument(
        '--exclude',
        metavar='<directory>',
        dest='excludes',
        action='append',
        default=[],
        help="""Do not run static analyzer against files found in this
        directory. (You can specify this option multiple times.)
        Could be useful when project contains 3rd party libraries.""")

    output = parser.add_argument_group('output control options')
    output.add_argument(
        '--output',
        '-o',
        metavar='<path>',
        default=tempfile.gettempdir(),
        help="""Specifies the output directory for analyzer reports.
        Subdirectory will be created if default directory is targeted.""")
    output.add_argument(
        '--keep-empty',
        action='store_true',
        help="""Don't remove the build results directory even if no issues
        were reported.""")
    output.add_argument(
        '--html-title',
        metavar='<title>',
        help="""Specify the title used on generated HTML pages.
        If not specified, a default title will be used.""")
    format_group = output.add_mutually_exclusive_group()
    format_group.add_argument(
        '--plist',
        '-plist',
        dest='output_format',
        const='plist',
        default='html',
        action='store_const',
        help="""Cause the results as a set of .plist files.""")
    format_group.add_argument(
        '--plist-html',
        '-plist-html',
        dest='output_format',
        const='plist-html',
        default='html',
        action='store_const',
        help="""Cause the results as a set of .html and .plist files.""")
    format_group.add_argument(
        '--plist-multi-file',
        '-plist-multi-file',
        dest='output_format',
        const='plist-multi-file',
        default='html',
        action='store_const',
        help="""Cause the results as a set of .plist files with extra
        information on related files.""")
    # TODO: implement '-view '

    advanced = parser.add_argument_group('advanced options')
    advanced.add_argument(
        '--use-analyzer',
        metavar='<path>',
        dest='clang',
        default='clang',
        help="""'%(prog)s' uses the 'clang' executable relative to itself for
        static analysis. One can override this behavior with this option by
        using the 'clang' packaged with Xcode (on OS X) or from the PATH.""")
    advanced.add_argument(
        '--no-failure-reports',
        '-no-failure-reports',
        dest='output_failures',
        action='store_false',
        help="""Do not create a 'failures' subdirectory that includes analyzer
        crash reports and preprocessed source files.""")
    parser.add_argument(
        '--analyze-headers',
        action='store_true',
        help="""Also analyze functions in #included files. By default, such
        functions are skipped unless they are called by functions within the
        main source file.""")
    advanced.add_argument(
        '--stats',
        '-stats',
        action='store_true',
        help="""Generates visitation statistics for the project.""")
    advanced.add_argument(
        '--internal-stats',
        action='store_true',
        help="""Generate internal analyzer statistics.""")
    advanced.add_argument(
        '--maxloop',
        '-maxloop',
        metavar='<loop count>',
        type=int,
        help="""Specifiy the number of times a block can be visited before
        giving up. Increase for more comprehensive coverage at a cost of
        speed.""")
    advanced.add_argument(
        '--store',
        '-store',
        metavar='<model>',
        dest='store_model',
        choices=['region', 'basic'],
        help="""Specify the store model used by the analyzer. 'region'
        specifies a field- sensitive store model. 'basic' which is far less
        precise but can more quickly analyze code. 'basic' was the default
        store model for checker-0.221 and earlier.""")
    advanced.add_argument(
        '--constraints',
        '-constraints',
        metavar='<model>',
        dest='constraints_model',
        choices=['range', 'basic'],
        help="""Specify the constraint engine used by the analyzer. Specifying
        'basic' uses a simpler, less powerful constraint model used by
        checker-0.160 and earlier.""")
    advanced.add_argument(
        '--analyzer-config',
        '-analyzer-config',
        metavar='<options>',
        help="""Provide options to pass through to the analyzer's
        -analyzer-config flag. Several options are separated with comma:
        'key1=val1,key2=val2'

        Available options:
            stable-report-filename=true or false (default)

        Switch the page naming to:
        report-<filename>-<function/method name>-<id>.html
        instead of report-XXXXXX.html""")
    advanced.add_argument(
        '--force-analyze-debug-code',
        dest='force_debug',
        action='store_true',
        help="""Tells analyzer to enable assertions in code even if they were
        disabled during compilation, enabling more precise results.""")

    plugins = parser.add_argument_group('checker options')
    plugins.add_argument(
        '--load-plugin',
        '-load-plugin',
        metavar='<plugin library>',
        dest='plugins',
        action='append',
        help="""Loading external checkers using the clang plugin interface.""")
    plugins.add_argument(
        '--enable-checker',
        '-enable-checker',
        metavar='<checker name>',
        action=AppendCommaSeparated,
        help="""Enable specific checker.""")
    plugins.add_argument(
        '--disable-checker',
        '-disable-checker',
        metavar='<checker name>',
        action=AppendCommaSeparated,
        help="""Disable specific checker.""")
    plugins.add_argument(
        '--help-checkers',
        action='store_true',
        help="""A default group of checkers is run unless explicitly disabled.
        Exactly which checkers constitute the default group is a function of
        the operating system in use. These can be printed with this flag.""")
    plugins.add_argument(
        '--help-checkers-verbose',
        action='store_true',
        help="""Print all available checkers and mark the enabled ones.""")
    return parser


def create_default_parser():
    # type: () -> argparse.ArgumentParser
    """ Creates command line parser for all build wrapper commands. """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=0,
        help="""Enable verbose output from '%(prog)s'. A second, third and
        fourth flags increases verbosity.""")
    return parser


class AppendCommaSeparated(argparse.Action):
    """ argparse Action class to support multiple comma separated lists. """

    def __call__(self, __parser, namespace, values, __option_string=None):
        # getattr(obj, attr, default) does not really returns default but none
        if getattr(namespace, self.dest, None) is None:
            setattr(namespace, self.dest, [])
        # once it's fixed we can use as expected
        actual = getattr(namespace, self.dest)
        actual.extend(values.split(','))
        setattr(namespace, self.dest, actual)


def print_active_checkers(checkers):
    # type: (Dict[str, Tuple[str, bool]]) -> None
    """ Print active checkers to stdout. """

    for name in sorted(name for name, (_, active) in checkers.items()
                       if active):
        print(name)


def print_checkers(checkers):
    # type: (Dict[str, Tuple[str, bool]]) -> None
    """ Print verbose checker help to stdout. """

    print('')
    print('available checkers:')
    print('')
    for name in sorted(checkers.keys()):
        description, active = checkers[name]
        prefix = '+' if active else ' '
        if len(name) > 30:
            print(' {0} {1}'.format(prefix, name))
            print(' ' * 35 + description)
        else:
            print(' {0} {1: <30}  {2}'.format(prefix, name, description))
    print('')
    print('NOTE: "+" indicates that an analysis is enabled by default.')
    print('')
