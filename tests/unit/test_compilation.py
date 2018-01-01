# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.

import libscanbuild.compilation as sut
import unittest


class CompilerTest(unittest.TestCase):

    def assert_c_compiler(self, command, cc='nope', cxx='nope++'):
        value = sut.Compilation._split_compiler(command, cc, cxx)
        self.assertIsNotNone(value)
        self.assertEqual(value[0], 'c')

    def assert_cxx_compiler(self, command, cc='nope', cxx='nope++'):
        value = sut.Compilation._split_compiler(command, cc, cxx)
        self.assertIsNotNone(value)
        self.assertEqual(value[0], 'c++')

    def assert_not_compiler(self, command):
        value = sut.Compilation._split_compiler(command, 'nope', 'nope')
        self.assertIsNone(value)

    def test_compiler_call(self):
        self.assert_c_compiler(['cc'])
        self.assert_cxx_compiler(['CC'])
        self.assert_cxx_compiler(['c++'])
        self.assert_cxx_compiler(['cxx'])

    def test_clang_compiler_call(self):
        self.assert_c_compiler(['clang'])
        self.assert_c_compiler(['clang-3.6'])
        self.assert_cxx_compiler(['clang++'])
        self.assert_cxx_compiler(['clang++-3.5.1'])

    def test_gcc_compiler_call(self):
        self.assert_c_compiler(['gcc'])
        self.assert_cxx_compiler(['g++'])

    def test_intel_compiler_call(self):
        self.assert_c_compiler(['icc'])
        self.assert_cxx_compiler(['icpc'])

    def test_aix_compiler_call(self):
        self.assert_c_compiler(['xlc'])
        self.assert_cxx_compiler(['xlc++'])
        self.assert_cxx_compiler(['xlC'])
        self.assert_c_compiler(['gxlc'])
        self.assert_cxx_compiler(['gxlc++'])

    def test_compiler_call_with_path(self):
        self.assert_c_compiler(['/usr/local/bin/gcc'])
        self.assert_cxx_compiler(['/usr/local/bin/g++'])
        self.assert_c_compiler(['/usr/local/bin/clang'])

    def test_cross_compiler_call(self):
        self.assert_cxx_compiler(['armv7_neno-linux-gnueabi-g++'])

    def test_non_compiler_call(self):
        self.assert_not_compiler([])
        self.assert_not_compiler([''])
        self.assert_not_compiler(['ld'])
        self.assert_not_compiler(['as'])
        self.assert_not_compiler(['/usr/local/bin/compiler'])

    def test_specific_compiler_call(self):
        self.assert_c_compiler(['nope'], cc='nope')
        self.assert_c_compiler(['./nope'], cc='nope')
        self.assert_c_compiler(['/path/nope'], cc='nope')
        self.assert_cxx_compiler(['nope++'], cxx='nope++')
        self.assert_cxx_compiler(['./nope++'], cxx='nope++')
        self.assert_cxx_compiler(['/path/nope++'], cxx='nope++')

    def assert_arguments_equal(self, expected, command):
        value = sut.Compilation._split_compiler(command, 'nope', 'nope')
        self.assertIsNotNone(value)
        self.assertEqual(expected, value[1])


class SplitTest(unittest.TestCase):

    def assert_compilation(self, command):
        result = sut.Compilation._split_command(command, 'nope', 'nope')
        self.assertIsNotNone(result)

    def assert_non_compilation(self, command):
        result = sut.Compilation._split_command(command, 'nope', 'nope')
        self.assertIsNone(result)

    def test_action(self):
        self.assert_compilation(['clang', 'source.c'])
        self.assert_compilation(['clang', '-c', 'source.c'])
        self.assert_compilation(['clang', '-c', 'source.c', '-MF', 'a.d'])

        self.assert_non_compilation(['clang', '-E', 'source.c'])
        self.assert_non_compilation(['clang', '-c', '-E', 'source.c'])
        self.assert_non_compilation(['clang', '-c', '-M', 'source.c'])
        self.assert_non_compilation(['clang', '-c', '-MM', 'source.c'])

    def assert_source_files(self, expected, command):
        result = sut.Compilation._split_command(command, 'nope', 'nope')
        self.assertIsNotNone(result)
        self.assertEqual(expected, result.files)

    def test_source_file(self):
        self.assert_source_files(['src.c'], ['clang', 'src.c'])
        self.assert_source_files(['src.c'], ['clang', '-c', 'src.c'])
        self.assert_source_files(['src.C'], ['clang', '-x', 'c', 'src.C'])
        self.assert_source_files(['src.cpp'], ['clang++', '-c', 'src.cpp'])
        self.assert_source_files(['s1.c', 's2.c'],
                                 ['clang', '-c', 's1.c', 's2.c'])
        self.assert_source_files(['s1.c', 's2.c'],
                                 ['cc', 's1.c', 's2.c', '-ldp', '-o', 'a.out'])
        self.assert_source_files(['src.c'],
                                 ['clang', '-c', '-I', './include', 'src.c'])
        self.assert_source_files(['src.c'],
                                 ['clang', '-c', '-I', '/opt/inc', 'src.c'])
        self.assert_source_files(['src.c'],
                                 ['clang', '-c', '-Dconfig=file.c', 'src.c'])

        self.assert_non_compilation(['cc', 'this.o', 'that.o', '-o', 'a.out'])
        self.assert_non_compilation(['cc', 'this.o', '-lthat', '-o', 'a.out'])

    def assert_flags(self, expected, flags):
        command = ['clang', '-c', 'src.c'] + flags
        result = sut.Compilation._split_command(command, 'nope', 'nope')
        self.assertIsNotNone(result)
        self.assertEqual(expected, result.flags)

    def test_filter_flags(self):

        def same(expected):
            self.assert_flags(expected, expected)

        def filtered(flags):
            self.assert_flags([], flags)

        same([])
        same(['-I', '/opt/me/include', '-DNDEBUG', '-ULIMITS'])
        same(['-O', '-O2'])
        same(['-m32', '-mmms'])
        same(['-Wall', '-Wno-unused', '-g', '-funroll-loops'])

        filtered([])
        filtered(['-lclien', '-L/opt/me/lib', '-L', '/opt/you/lib'])
        filtered(['-static'])
        filtered(['-MD', '-MT', 'something'])
        filtered(['-MMD', '-MF', 'something'])


class SourceClassifierTest(unittest.TestCase):

    def assert_non_source(self, filename):
        result = sut.classify_source(filename)
        self.assertIsNone(result)

    def assert_c_source(self, filename, force):
        result = sut.classify_source(filename, force)
        self.assertEqual('c', result)

    def assert_cxx_source(self, filename, force):
        result = sut.classify_source(filename, force)
        self.assertEqual('c++', result)

    def test_sources(self):
        self.assert_non_source('file.o')
        self.assert_non_source('file.exe')
        self.assert_non_source('/path/file.o')
        self.assert_non_source('clang')

        self.assert_c_source('file.c', True)
        self.assert_cxx_source('file.c', False)

        self.assert_cxx_source('file.cxx', True)
        self.assert_cxx_source('file.cxx', False)
        self.assert_cxx_source('file.c++', True)
        self.assert_cxx_source('file.c++', False)
        self.assert_cxx_source('file.cpp', True)
        self.assert_cxx_source('file.cpp', False)

        self.assert_c_source('/path/file.c', True)
        self.assert_c_source('./path/file.c', True)
        self.assert_c_source('../path/file.c', True)
        self.assert_c_source('/file.c', True)
        self.assert_c_source('./file.c', True)
