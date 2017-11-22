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
import functools
import subprocess
import platform
import contextlib
import datetime
import argparse  # noqa: ignore=F401
from typing import Any, Dict, List, Iterable, Generator  # noqa: ignore=F401
from libscanbuild.compilation import Compilation  # noqa: ignore=F401

from libscanbuild import command_entry_point, run_command
from libscanbuild.arguments import parse_args_for_analyze_build
from libscanbuild.report import document
from libscanbuild.compilation import classify_source, CompilationDatabase
from libscanbuild.clang import get_version, get_arguments

__all__ = ['analyze_build']


@command_entry_point
def analyze_build():
    # type: () -> int
    """ Entry point for analyze-build command. """

    args = parse_args_for_analyze_build()
    # will re-assign the report directory as new output
    with report_directory(args.output, args.keep_empty) as args.output:
        # run the analyzer against a compilation db
        compilations = CompilationDatabase.load(args.cdb)
        run_analyzer_parallel(compilations, args)
        # cover report generation and bug counting
        number_of_bugs = document(args)
        # set exit status as it was requested
        return number_of_bugs if args.status_bugs else 0


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
        'excludes': args.excludes
    }


def run_analyzer_parallel(compilations, args):
    # type: (Iterable[Compilation], argparse.Namespace) -> None
    """ Runs the analyzer against the given compilations. """

    logging.debug('run analyzer against compilation database')
    consts = analyze_parameters(args)
    parameters = (dict(compilation.as_dict(), **consts)
                  for compilation in compilations)
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


@require(['flags',  # entry from compilation
          'compiler',  # entry from compilation
          'directory',  # entry from compilation
          'source',  # entry from compilation
          'clang',  # clang executable name (and path)
          'direct_args',  # arguments from command line
          'excludes',  # list of directories
          'force_debug',  # kill non debug macros
          'output_dir',  # where generated report files shall go
          'output_format',  # it's 'plist', 'html', 'plist-html',
                            # 'text' or 'plist-multi-file'
          'output_failures'])  # generate crash reports or not
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

    command = [opts['compiler'], '-c'] + opts['flags'] + [opts['source']]
    logging.debug("Run analyzer against '%s'", command)
    return exclude(opts)


def logging_analyzer_output(opts):
    # type: (Dict[str, Any]) -> None
    """ Display error message from analyzer. """

    if opts and 'error_output' in opts:
        for line in opts['error_output']:
            logging.info(line)


@require(['clang', 'directory', 'flags', 'source', 'output_dir', 'language',
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
                            opts['flags'] + [opts['source'], '-o', name], cwd)
        run_command(cmd, cwd=cwd)
        # write general information about the crash
        with open(name + '.info.txt', 'w') as handle:
            handle.write(opts['source'] + os.linesep)
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


@require(['clang', 'directory', 'flags', 'direct_args', 'source', 'output_dir',
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
                            opts['direct_args'] + opts['flags'] +
                            [opts['source'], '-o', target()],
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


@require(['flags', 'force_debug'])
def filter_debug_flags(opts, continuation=run_analyzer):
    # type: (...) -> Dict[str, Any]
    """ Filter out nondebug macros when requested. """

    if opts.pop('force_debug'):
        # lazy implementation just append an undefine macro at the end
        opts.update({'flags': opts['flags'] + ['-UNDEBUG']})

    return continuation(opts)


@require(['language', 'compiler', 'source', 'flags'])
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
        language = classify_source(opts['source'], compiler == 'c')

    if language is None:
        logging.debug('skip analysis, language not known')
        return dict()
    elif language not in accepted:
        logging.debug('skip analysis, language not supported')
        return dict()

    logging.debug('analysis, language: %s', language)
    opts.update({'language': language,
                 'flags': ['-x', language] + opts['flags']})
    return continuation(opts)


@require(['arch_list', 'flags'])
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

            opts.update({'flags': ['-arch', current] + opts['flags']})
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


@require(['flags'])
def classify_parameters(opts, continuation=arch_check):
    # type: (...) -> Dict[str, Any]
    """ Prepare compiler flags (filters some and add others) and take out
    language (-x) and architecture (-arch) flags for future processing. """

    # the result of the method
    result = {
        'flags': [],  # the filtered compiler flags
        'arch_list': [],  # list of architecture flags
        'language': None,  # compilation language, None, if not specified
    }  # type: Dict[str, Any]

    # iterate on the compile options
    args = iter(opts['flags'])
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
            result['flags'].append(arg)

    opts.update(result)
    return continuation(opts)


@require(['source', 'excludes'])
def exclude(opts, continuation=classify_parameters):
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

    if any(contains(dir, opts['source']) for dir in opts['excludes']):
        logging.debug('skip analysis, file requested to exclude')
        return dict()
    return continuation(opts)
