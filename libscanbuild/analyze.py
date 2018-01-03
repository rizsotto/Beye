# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
""" This module implements the 'scan-build' command API.

To run the static analyzer against a build is done in multiple steps:

 -- Intercept: capture the compilation command during the build,
 -- Analyze:   run the analyzer against the captured commands,
 -- Report:    create a cover report from the analyzer outputs.  """

import re
import os
import os.path
import logging
import multiprocessing
import tempfile
import json
import functools
import subprocess
import platform
import contextlib
import datetime
import argparse  # noqa: ignore=F401
from typing import Any, Dict, List, Iterable, Generator  # noqa: ignore=F401
from typing import Optional  # noqa: ignore=F401

from libscanbuild import shell_split, command_entry_point, run_command
from libscanbuild.arguments import parse_args_for_analyze_build
from libscanbuild.report import document
from libscanbuild.clang import get_version, get_arguments

# Keyword constants
COMMAND = 'command'
ARGUMENTS = 'arguments'
DIRECTORY = 'directory'
SOURCE = 'file'
FLAGS = 'flags'
EXCLUDES = 'excludes'


@command_entry_point
def analyze_build():
    # type: () -> int
    """ Entry point for analyze-build command. """

    args = parse_args_for_analyze_build()
    # will re-assign the report directory as new output
    with report_directory(args.output, args.keep_empty) as args.output:
        # run the analyzer against a compilation db
        compilations = load_compilation_database(args.cdb)
        run_analyzer_parallel(compilations, args)
        # cover report generation and bug counting
        number_of_bugs = document(args)
        # set exit status as it was requested
        return number_of_bugs if args.status_bugs else 0


def load_compilation_database(filename):
    # type: (str) -> Iterable[Dict[str, Any]]
    """ Load compilations from file.

    :param filename: the file to read from
    :returns: iterator of Compilation objects. """

    with open(filename, 'r') as handle:
        for entry in json.load(handle):
            yield entry


def analyze_parameters(args):
    # type: (argparse.Namespace) -> Dict[str, Any]
    """ Mapping between the command line parameters and the analyzer run
    method. The run method works with a plain dictionary, while the command
    line parameters are in a named tuple.
    The keys are very similar, and some values are preprocessed. """

    def prefix_with(constant, pieces):
        # type: (Any, List[Any]) -> List[Any]
        """ From a sequence create another sequence where every second element
        is from the original sequence and the odd elements are the prefix.

        eg.: prefix_with(0, [1,2,3]) creates [0, 1, 0, 2, 0, 3] """

        return [elem for piece in pieces for elem in [constant, piece]]

    def direct_args(args):
        # type: (argparse.Namespace) -> List[str]
        """ A group of command line arguments can mapped to command
        line arguments of the analyzer. """

        result = []

        if args.store_model:
            result.append('-analyzer-store={0}'.format(args.store_model))
        if args.constraints_model:
            result.append('-analyzer-constraints={0}'.format(
                args.constraints_model))
        if args.internal_stats:
            result.append('-analyzer-stats')
        if args.analyze_headers:
            result.append('-analyzer-opt-analyze-headers')
        if args.stats:
            result.append('-analyzer-checker=debug.Stats')
        if args.maxloop:
            result.extend(['-analyzer-max-loop', str(args.maxloop)])
        if args.output_format:
            result.append('-analyzer-output={0}'.format(args.output_format))
        if args.analyzer_config:
            result.extend(['-analyzer-config', args.analyzer_config])
        if args.verbose >= 4:
            result.append('-analyzer-display-progress')
        if args.plugins:
            result.extend(prefix_with('-load', args.plugins))
        if args.enable_checker:
            checkers = ','.join(args.enable_checker)
            result.extend(['-analyzer-checker', checkers])
        if args.disable_checker:
            checkers = ','.join(args.disable_checker)
            result.extend(['-analyzer-disable-checker', checkers])
        if os.getenv('UBIVIZ'):
            result.append('-analyzer-viz-egraph-ubigraph')

        return prefix_with('-Xclang', result)

    return {
        'clang': args.clang,
        'output_dir': args.output,
        'output_format': args.output_format,
        'output_failures': args.output_failures,
        'direct_args': direct_args(args),
        'force_debug': args.force_debug,
        EXCLUDES: args.excludes
    }


def run_analyzer_parallel(compilations, args):
    # type: (Iterable[Dict[str, Any]], argparse.Namespace) -> None
    """ Runs the analyzer against the given compilations. """

    def logging_analyzer_output(current):
        # type: (Dict[str, Any]) -> None
        """ Display error message from analyzer. """
        if current and 'error_output' in current:
            for line in current['error_output']:
                logging.info(line)

    logging.debug('run analyzer against compilation database')
    consts = analyze_parameters(args)
    parameters = (dict(compilation, **consts) for compilation in compilations)
    # when verbose output requested execute sequentially
    pool = multiprocessing.Pool(1 if args.verbose > 2 else None)
    for current in pool.imap_unordered(run, parameters):
        logging_analyzer_output(current)
    pool.close()
    pool.join()


@contextlib.contextmanager
def report_directory(hint, keep):
    # type: (str, bool) -> Generator[str, None, None]
    """ Responsible for the report directory.

    hint -- could specify the parent directory of the output directory.
    keep -- a boolean value to keep or delete the empty report directory. """

    stamp_format = 'scan-build-%Y-%m-%d-%H-%M-%S-%f-'
    stamp = datetime.datetime.now().strftime(stamp_format)
    parent_dir = os.path.abspath(hint)
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)
    name = tempfile.mkdtemp(prefix=stamp, dir=parent_dir)

    logging.info('Report directory created: %s', name)

    try:
        yield name
    finally:
        if os.listdir(name):
            msg = "Run 'scan-view %s' to examine bug reports."
            keep = True
        else:
            if keep:
                msg = "Report directory '%s' contains no report, but kept."
            else:
                msg = "Removing directory '%s' because it contains no report."
        logging.warning(msg, name)

        if not keep:
            os.rmdir(name)


def require(required):
    """ Decorator for checking the required values in state.

    It checks the required attributes in the passed state and stop when
    any of those is missing. """

    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            for key in required:
                assert key in args[0], '{} is missing'.format(key)

            return method(*args, **kwargs)

        return wrapper

    return decorator


@require([SOURCE])
def run(opts):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """ Entry point to run (or not) static analyzer against a single entry
    of the compilation database.

    This complex task is decomposed into smaller methods which are calling
    each other in chain. If the analysis is not possible the given method
    just return and break the chain.

    The passed parameter is a python dictionary. Each method first check
    that the needed parameters received. (This is done by the 'require'
    decorator. It's like an 'assert' to check the contract between the
    caller and the called method.) """

    logging.debug("Run analyzer against '%s'", opts[SOURCE])
    return validate_db_entry(opts)


@require(['clang', 'directory', FLAGS, SOURCE, 'output_dir', 'language',
          'error_output', 'exit_code'])
def report_failure(opts):
    # type: (Dict[str, Any]) -> None
    """ Create report when analyzer failed.

    The major report is the preprocessor output. The output filename generated
    randomly. The compiler output also captured into '.stderr.txt' file.
    And some more execution context also saved into '.info.txt' file. """

    def extension():
        # type: () -> str
        """ Generate preprocessor file extension. """

        mapping = {'objective-c++': '.mii', 'objective-c': '.mi', 'c++': '.ii'}
        return mapping.get(opts['language'], '.i')

    def destination():
        # type: () -> str
        """ Creates failures directory if not exits yet. """

        failures_dir = os.path.join(opts['output_dir'], 'failures')
        if not os.path.isdir(failures_dir):
            os.makedirs(failures_dir)
        return failures_dir

    # Classify error type: when Clang terminated by a signal it's a 'Crash'.
    # (python subprocess Popen.returncode is negative when child terminated
    # by signal.) Everything else is 'Other Error'.
    error = 'crash' if opts['exit_code'] < 0 else 'other_error'
    # Create preprocessor output file name. (This is blindly following the
    # Perl implementation.)
    (fd, name) = tempfile.mkstemp(suffix=extension(),
                                  prefix='clang_' + error + '_',
                                  dir=destination())
    os.close(fd)
    # Execute Clang again, but run the syntax check only.
    try:
        cwd = opts['directory']
        cmd = get_arguments([opts['clang'], '-fsyntax-only', '-E'] +
                            opts[FLAGS] + [opts[SOURCE], '-o', name], cwd)
        run_command(cmd, cwd=cwd)
        # write general information about the crash
        with open(name + '.info.txt', 'w') as handle:
            handle.write(opts[SOURCE] + os.linesep)
            handle.write(error.title().replace('_', ' ') + os.linesep)
            handle.write(' '.join(cmd) + os.linesep)
            handle.write(' '.join(platform.uname()) + os.linesep)
            handle.write(get_version(opts['clang']))
            handle.close()
        # write the captured output too
        with open(name + '.stderr.txt', 'w') as handle:
            for line in opts['error_output']:
                handle.write(line)
            handle.close()
    except (OSError, subprocess.CalledProcessError):
        logging.warning('failed to report failure', exc_info=True)


@require(['clang', 'directory', FLAGS, 'direct_args', SOURCE, 'output_dir',
          'output_format'])
def run_analyzer(opts, continuation=report_failure):
    # type: (...) -> Dict[str, Any]
    """ It assembles the analysis command line and executes it. Capture the
    output of the analysis and returns with it. If failure reports are
    requested, it calls the continuation to generate it. """

    def target():
        # type: () -> str
        """ Creates output file name for reports. """
        if opts['output_format'].startswith('plist'):
            (handle, name) = tempfile.mkstemp(prefix='report-',
                                              suffix='.plist',
                                              dir=opts['output_dir'])
            os.close(handle)
            return name
        return opts['output_dir']

    try:
        cwd = opts['directory']
        cmd = get_arguments([opts['clang'], '--analyze'] +
                            opts['direct_args'] + opts[FLAGS] +
                            [opts[SOURCE], '-o', target()],
                            cwd)
        output = run_command(cmd, cwd=cwd)
        return {'error_output': output, 'exit_code': 0}
    except OSError:
        message = 'failed to execute "{0}"'.format(opts['clang'])
        return {'error_output': message, 'exit_code': 127}
    except subprocess.CalledProcessError as ex:
        logging.warning('analysis failed: %s', exc_info=True)
        result = {'error_output': ex.output, 'exit_code': ex.returncode}
        if opts.get('output_failures', False):
            opts.update(result)
            continuation(opts)
        return result


@require([FLAGS, 'force_debug'])
def filter_debug_flags(opts, continuation=run_analyzer):
    # type: (...) -> Dict[str, Any]
    """ Filter out nondebug macros when requested. """

    if opts.pop('force_debug'):
        # lazy implementation just append an undefine macro at the end
        opts.update({FLAGS: opts[FLAGS] + ['-UNDEBUG']})

    return continuation(opts)


@require(['language', 'compiler', SOURCE, FLAGS])
def language_check(opts, continuation=filter_debug_flags):
    # type: (...) -> Dict[str, Any]
    """ Find out the language from command line parameters or file name
    extension. The decision also influenced by the compiler invocation. """

    accepted = frozenset({
        'c', 'c++', 'objective-c', 'objective-c++', 'c-cpp-output',
        'c++-cpp-output', 'objective-c-cpp-output'
    })

    # language can be given as a parameter...
    language = opts.pop('language')
    compiler = opts.pop('compiler')
    # ... or find out from source file extension
    if language is None and compiler is not None:
        language = classify_source(opts[SOURCE], compiler == 'c')

    if language is None:
        logging.debug('skip analysis, language not known')
        return dict()
    elif language not in accepted:
        logging.debug('skip analysis, language not supported')
        return dict()

    logging.debug('analysis, language: %s', language)
    opts.update({'language': language,
                 FLAGS: ['-x', language] + opts[FLAGS]})
    return continuation(opts)


@require(['arch_list', FLAGS])
def arch_check(opts, continuation=language_check):
    # type: (...) -> Dict[str, Any]
    """ Do run analyzer through one of the given architectures. """

    disabled = frozenset({'ppc', 'ppc64'})

    received_list = opts.pop('arch_list')
    if received_list:
        # filter out disabled architectures and -arch switches
        filtered_list = [a for a in received_list if a not in disabled]
        if filtered_list:
            # There should be only one arch given (or the same multiple
            # times). If there are multiple arch are given and are not
            # the same, those should not change the pre-processing step.
            # But that's the only pass we have before run the analyzer.
            current = filtered_list.pop()
            logging.debug('analysis, on arch: %s', current)

            opts.update({FLAGS: ['-arch', current] + opts[FLAGS]})
            return continuation(opts)
        logging.debug('skip analysis, found not supported arch')
        return dict()
    logging.debug('analysis, on default arch')
    return continuation(opts)


# To have good results from static analyzer certain compiler options shall be
# omitted. The compiler flag filtering only affects the static analyzer run.
#
# Keys are the option name, value number of options to skip
IGNORED_FLAGS = {
    '-c': 0,  # compile option will be overwritten
    '-fsyntax-only': 0,  # static analyzer option will be overwritten
    '-o': 1,  # will set up own output file
    # flags below are inherited from the perl implementation.
    '-g': 0,
    '-save-temps': 0,
    '-install_name': 1,
    '-exported_symbols_list': 1,
    '-current_version': 1,
    '-compatibility_version': 1,
    '-init': 1,
    '-e': 1,
    '-seg1addr': 1,
    '-bundle_loader': 1,
    '-multiply_defined': 1,
    '-sectorder': 3,
    '--param': 1,
    '--serialize-diagnostics': 1
}  # type: Dict[str, int]


@require([FLAGS])
def classify_parameters(opts, continuation=arch_check):
    # type: (...) -> Dict[str, Any]
    """ Prepare compiler flags (filters some and add others) and take out
    language (-x) and architecture (-arch) flags for future processing. """

    # the result of the method
    result = {
        FLAGS: [],  # the filtered compiler flags
        'arch_list': [],  # list of architecture flags
        'language': None,  # compilation language, None, if not specified
    }  # type: Dict[str, Any]

    # iterate on the compile options
    args = iter(opts[FLAGS])
    for arg in args:
        # take arch flags into a separate basket
        if arg == '-arch':
            result['arch_list'].append(next(args))
        # take language
        elif arg == '-x':
            result['language'] = next(args)
        # ignore some flags
        elif arg in IGNORED_FLAGS:
            count = IGNORED_FLAGS[arg]
            for _ in range(count):
                next(args)
        # we don't care about extra warnings, but we should suppress ones
        # that we don't want to see.
        elif re.match(r'^-W.+', arg) and not re.match(r'^-Wno-.+', arg):
            pass
        # and consider everything else as compilation flag.
        else:
            result[FLAGS].append(arg)

    opts.update(result)
    return continuation(opts)


# Known C compiler executable name patterns.
COMPILERS_CC = (
    re.compile(r'^([^-]*-)*[mg]cc(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^([^-]*-)*clang(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^(i|)cc$'),
    re.compile(r'^(g|)xlc$'),
)


# Known C++ compiler executable name patterns.
COMPILERS_CXX = (
    re.compile(r'^(c\+\+|cxx|CC)$'),
    re.compile(r'^([^-]*-)*[mg]\+\+(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^([^-]*-)*clang\+\+(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^icpc$'),
    re.compile(r'^(g|)xl(C|c\+\+)$'),
)


@require([ARGUMENTS])
def compiler_name(opts, continuation=classify_parameters):
    # type: (...) -> Dict[str, Any]
    """ Guess the language from compiler name. """

    def is_c_compiler(cmd):
        # type: (str) -> bool
        return any(pattern.match(cmd) for pattern in COMPILERS_CC)

    def is_cxx_compiler(cmd):
        # type: (str) -> bool
        return any(pattern.match(cmd) for pattern in COMPILERS_CXX)

    def compiler_type(executable):
        # type: (str) -> Optional[str]
        cmd = os.path.basename(executable)
        if is_c_compiler(cmd):
            return 'c'
        elif is_cxx_compiler(cmd):
            return 'c++'
        else:
            return None

    arguments = opts.pop(ARGUMENTS)
    if len(arguments) < 2:
        logging.warning('Invalid entry (command length)')
        return dict()

    opts.update({
        FLAGS: arguments[1:],
        'compiler': compiler_type(arguments[0])
    })

    return continuation(opts)


@require([SOURCE, EXCLUDES])
def exclude(opts, continuation=compiler_name):
    # type: (...) -> Dict[str, Any]
    """ Analysis might be skipped, when one of the requested excluded
    directory contains the file. """

    def contains(directory, entry):
        # type: (str, str) -> bool
        """ Check is directory contains the given file. """

        # When a directory contains a file, then the relative path to the
        # file from that directory does not start with a parent dir prefix.
        relative = os.path.relpath(entry, directory).split(os.sep)
        return len(relative) > 0 and relative[0] != os.pardir

    if any(contains(dir, opts[SOURCE]) for dir in opts[EXCLUDES]):
        logging.debug('skip analysis, file requested to exclude')
        return dict()
    return continuation(opts)


@require([DIRECTORY, SOURCE])
def validate_db_entry(opts, continuation=exclude):
    # type: (...) -> Dict[str, Any]
    """ Validate compilation database input entry. """

    if COMMAND in opts:
        command = opts.pop(COMMAND)
        arguments = shell_split(command)
        opts.update({ARGUMENTS: arguments})
    elif ARGUMENTS in opts:
        pass
    else:
        logging.warning('Invalid entry (missing command)')
        return dict()

    opts.update({
        DIRECTORY: os.path.normpath(opts[DIRECTORY]),
        SOURCE: os.path.normpath(opts[SOURCE])
    })

    return continuation(opts)


def classify_source(filename, c_compiler=True):
    # type: (str, bool) -> str
    """ Classify source file names and returns the presumed language,
    based on the file name extension.

    :param filename:    the source file name
    :param c_compiler:  indicate that the compiler is a C compiler,
    :return: the language from file name extension. """

    mapping = {
        '.c': 'c' if c_compiler else 'c++',
        '.i': 'c-cpp-output' if c_compiler else 'c++-cpp-output',
        '.ii': 'c++-cpp-output',
        '.m': 'objective-c',
        '.mi': 'objective-c-cpp-output',
        '.mm': 'objective-c++',
        '.mii': 'objective-c++-cpp-output',
        '.C': 'c++',
        '.cc': 'c++',
        '.CC': 'c++',
        '.cp': 'c++',
        '.cpp': 'c++',
        '.cxx': 'c++',
        '.c++': 'c++',
        '.C++': 'c++',
        '.txx': 'c++'
    }

    __, extension = os.path.splitext(os.path.basename(filename))
    return mapping.get(extension)
