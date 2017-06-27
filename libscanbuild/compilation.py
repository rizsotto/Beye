# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
""" This module is responsible to parse a compiler invocation. """

import re
import os
import collections
import logging
import json
from libscanbuild import Execution, shell_split

__all__ = ['classify_source', 'Compilation', 'CompilationDatabase']

# Ignored compiler options map for compilation database creation.
# The map is used in `_split_command` method. (Which does ignore and classify
# parameters.) Please note, that these are not the only parameters which
# might be ignored.
#
# Keys are the option name, value number of options to skip
IGNORED_FLAGS = {
    # compiling only flag, ignored because the creator of compilation
    # database will explicitly set it.
    '-c': 0,
    # preprocessor macros, ignored because would cause duplicate entries in
    # the output (the only difference would be these flags). this is actual
    # finding from users, who suffered longer execution time caused by the
    # duplicates.
    '-MD': 0,
    '-MMD': 0,
    '-MG': 0,
    '-MP': 0,
    '-MF': 1,
    '-MT': 1,
    '-MQ': 1,
    # linker options, ignored because for compilation database will contain
    # compilation commands only. so, the compiler would ignore these flags
    # anyway. the benefit to get rid of them is to make the output more
    # readable.
    '-static': 0,
    '-shared': 0,
    '-s': 0,
    '-rdynamic': 0,
    '-l': 1,
    '-L': 1,
    '-u': 1,
    '-z': 1,
    '-T': 1,
    '-Xlinker': 1
}

# Known C/C++ compiler wrapper name patterns
COMPILER_PATTERN_WRAPPER = re.compile(r'^(distcc|ccache)$')

# Known C compiler executable name patterns
COMPILER_PATTERNS_CC = frozenset([
    re.compile(r'^(|i|mpi)cc$'),
    re.compile(r'^([^-]*-)*[mg]cc(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^([^-]*-)*clang(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^(g|)xlc$'),
])

# Known C++ compiler executable name patterns
COMPILER_PATTERNS_CXX = frozenset([
    re.compile(r'^(c\+\+|cxx|CC)$'),
    re.compile(r'^([^-]*-)*[mg]\+\+(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^([^-]*-)*clang\+\+(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^(icpc|mpiCC|mpicxx|mpic\+\+)$'),
    re.compile(r'^(g|)xl(C|c\+\+)$'),
])

CompilationCommand = collections.namedtuple(
    'CompilationCommand', ['compiler', 'flags', 'files'])


class Compilation:
    """ Represents a compilation of a single module. """
    def __init__(self, compiler, flags, source, directory):
        """ Constructor for a single compilation.

        This method just normalize the paths and initialize values. """

        self.compiler = compiler
        self.flags = flags
        self.directory = os.path.normpath(directory)
        self.source = source if os.path.isabs(source) else \
            os.path.normpath(os.path.join(self.directory, source))

    def __hash__(self):
        return hash((self.compiler, self.source, self.directory,
                     ':'.join(self.flags)))

    def __eq__(self, other):
        return vars(self) == vars(other)

    def as_dict(self):
        """ This method dumps the object attributes into a dictionary. """

        return vars(self)

    def as_db_entry(self):
        """ This method creates a compilation database entry. """

        relative = os.path.relpath(self.source, self.directory)
        compiler = 'cc' if self.compiler == 'c' else 'c++'
        return {
            'file': relative,
            'arguments': [compiler, '-c'] + self.flags + [relative],
            'directory': self.directory
        }

    @staticmethod
    def from_db_entry(entry):
        """ Parser method for compilation entry.

        From compilation database entry it creates the compilation object.

        :param entry:   the compilation database entry
        :return: stream of CompilationDbEntry objects """

        command = shell_split(entry['command']) if 'command' in entry else \
            entry['arguments']
        execution = Execution(cmd=command, cwd=entry['directory'], pid=0)
        return Compilation.iter_from_execution(execution)

    @staticmethod
    def iter_from_execution(execution, cc='cc', cxx='c++'):
        """ Generator method for compilation entries.

        From a single compiler call it can generate zero or more entries.

        :param execution:   executed command and working directory
        :param cc:          user specified C compiler name
        :param cxx:         user specified C++ compiler name
        :return: stream of CompilationDbEntry objects """

        candidate = Compilation._split_command(execution.cmd, cc, cxx)
        for source in candidate.files if candidate else []:
            result = Compilation(directory=execution.cwd,
                                 source=source,
                                 compiler=candidate.compiler,
                                 flags=candidate.flags)
            if os.path.isfile(result.source):
                yield result

    @staticmethod
    def _split_compiler(command, cc, cxx):
        """ A predicate to decide the command is a compiler call or not.

        :param command:     the command to classify
        :param cc:          user specified C compiler name
        :param cxx:         user specified C++ compiler name
        :return: None if the command is not a compilation, or a tuple
                (compiler_language, rest of the command) otherwise """

        def is_wrapper(cmd):
            return True if COMPILER_PATTERN_WRAPPER.match(cmd) else False

        def is_c_compiler(cmd):
            return os.path.basename(cc) == cmd or \
                any(pattern.match(cmd) for pattern in COMPILER_PATTERNS_CC)

        def is_cxx_compiler(cmd):
            return os.path.basename(cxx) == cmd or \
                any(pattern.match(cmd) for pattern in COMPILER_PATTERNS_CXX)

        if command:  # not empty list will allow to index '0' and '1:'
            executable = os.path.basename(command[0])
            parameters = command[1:]
            # 'wrapper' 'parameters' and
            # 'wrapper' 'compiler' 'parameters' are valid.
            # plus, a wrapper can wrap wrapper too.
            if is_wrapper(executable):
                result = Compilation._split_compiler(parameters, cc, cxx)
                return ('c', parameters) if result is None else result
            # and 'compiler' 'parameters' is valid.
            elif is_c_compiler(executable):
                return 'c', parameters
            elif is_cxx_compiler(executable):
                return 'c++', parameters
        return None

    @staticmethod
    def _split_command(command, cc, cxx):
        """ Returns a value when the command is a compilation, None otherwise.

        :param command:     the command to classify
        :param cc:          user specified C compiler name
        :param cxx:         user specified C++ compiler name
        :return: stream of CompilationCommand objects """

        logging.debug('input was: %s', command)
        # quit right now, if the program was not a C/C++ compiler
        compiler_and_arguments = Compilation._split_compiler(command, cc, cxx)
        if compiler_and_arguments is None:
            return None

        # the result of this method
        result = CompilationCommand(compiler=compiler_and_arguments[0],
                                    flags=[],
                                    files=[])
        # iterate on the compile options
        args = iter(compiler_and_arguments[1])
        for arg in args:
            # quit when compilation pass is not involved
            if arg in {'-E', '-S', '-cc1', '-M', '-MM', '-###'}:
                return None
            # ignore some flags
            elif arg in IGNORED_FLAGS:
                count = IGNORED_FLAGS[arg]
                for _ in range(count):
                    next(args)
            elif re.match(r'^-(l|L|Wl,).+', arg):
                pass
            # some parameters could look like filename, take as compile option
            elif arg in {'-D', '-I'}:
                result.flags.extend([arg, next(args)])
            # parameter which looks source file is taken...
            elif re.match(r'^[^-].+', arg) and classify_source(arg):
                result.files.append(arg)
            # and consider everything else as compile option.
            else:
                result.flags.append(arg)
        logging.debug('output is: %s', result)
        # do extra check on number of source files
        return result if result.files else None


class CompilationDatabase:
    """ Compilation Database persistence methods. """

    @staticmethod
    def save(filename, iterator):
        """ Saves compilations to given file.

        :param filename: the destination file name
        :param iterator: iterator of Compilation objects. """

        entries = [entry.as_db_entry() for entry in iterator]
        with open(filename, 'w+') as handle:
            json.dump(entries, handle, sort_keys=True, indent=4)

    @staticmethod
    def load(filename):
        """ Load compilations from file.

        :param filename: the file to read from
        :returns: iterator of Compilation objects. """

        with open(filename, 'r') as handle:
            for entry in json.load(handle):
                for compilation in Compilation.from_db_entry(entry):
                    yield compilation


def classify_source(filename, c_compiler=True):
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
