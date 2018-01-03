# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.

import libscanbuild.analyze as sut
import unittest
import os
import os.path
import glob
import platform
from test_fixture import temporary_directory

IS_WINDOWS = os.getenv('windows')


class Spy(object):
    def __init__(self):
        self.arg = None
        self.success = 0

    def call(self, params):
        self.arg = params
        return self.success


class CompilerTest(unittest.TestCase):

    @staticmethod
    def compiler_name(arguments):
        spy = Spy()
        opts = {'arguments': [arguments, '-c', 'source.c']}
        sut.compiler_name(opts, spy.call)
        return spy.arg

    def assert_compiler(self, expected, arguments):
        result = CompilerTest.compiler_name(arguments)
        self.assertEqual(expected, result['compiler'])

    def assert_c_compiler(self, command):
        self.assert_compiler('c', command)

    def assert_cxx_compiler(self, command):
        self.assert_compiler('c++', command)

    def assert_not_compiler(self, command):
        self.assert_compiler(None, command)

    def test_compiler_call(self):
        self.assert_c_compiler('cc')
        self.assert_cxx_compiler('CC')
        self.assert_cxx_compiler('c++')
        self.assert_cxx_compiler('cxx')

    def test_clang_compiler_call(self):
        self.assert_c_compiler('clang')
        self.assert_c_compiler('clang-3.6')
        self.assert_cxx_compiler('clang++')
        self.assert_cxx_compiler('clang++-3.5.1')

    def test_gcc_compiler_call(self):
        self.assert_c_compiler('gcc')
        self.assert_cxx_compiler('g++')

    def test_intel_compiler_call(self):
        self.assert_c_compiler('icc')
        self.assert_cxx_compiler('icpc')

    def test_aix_compiler_call(self):
        self.assert_c_compiler('xlc')
        self.assert_cxx_compiler('xlc++')
        self.assert_cxx_compiler('xlC')
        self.assert_c_compiler('gxlc')
        self.assert_cxx_compiler('gxlc++')

    def test_compiler_call_with_path(self):
        self.assert_c_compiler('/usr/local/bin/gcc')
        self.assert_cxx_compiler('/usr/local/bin/g++')
        self.assert_c_compiler('/usr/local/bin/clang')

    def test_cross_compiler_call(self):
        self.assert_cxx_compiler('armv7_neno-linux-gnueabi-g++')

    def test_non_compiler_call(self):
        self.assert_not_compiler('')
        self.assert_not_compiler('ld')
        self.assert_not_compiler('as')
        self.assert_not_compiler('/usr/local/bin/compiler')


class FilteringFlagsTest(unittest.TestCase):

    @staticmethod
    def classify_parameters(flags):
        spy = Spy()
        opts = {'flags': flags}
        sut.classify_parameters(opts, spy.call)
        return spy.arg

    def assertLanguage(self, expected, flags):
        self.assertEqual(
            expected,
            FilteringFlagsTest.classify_parameters(flags)['language'])

    def test_language_captured(self):
        self.assertLanguage(None, [])
        self.assertLanguage('c', ['-x', 'c'])
        self.assertLanguage('cpp', ['-x', 'cpp'])

    def assertArch(self, expected, flags):
        self.assertEqual(
            expected,
            FilteringFlagsTest.classify_parameters(flags)['arch_list'])

    def test_arch(self):
        self.assertArch([], [])
        self.assertArch(['mips'], ['-arch', 'mips'])
        self.assertArch(['mips', 'i386'], ['-arch', 'mips', '-arch', 'i386'])

    def assertFlagsChanged(self, expected, flags):
        self.assertEqual(
            expected,
            FilteringFlagsTest.classify_parameters(flags)['flags'])

    def assertFlagsUnchanged(self, flags):
        self.assertFlagsChanged(flags, flags)

    def assertFlagsFiltered(self, flags):
        self.assertFlagsChanged([], flags)

    def test_optimalizations_pass(self):
        self.assertFlagsUnchanged(['-O'])
        self.assertFlagsUnchanged(['-O1'])
        self.assertFlagsUnchanged(['-Os'])
        self.assertFlagsUnchanged(['-O2'])
        self.assertFlagsUnchanged(['-O3'])

    def test_include_pass(self):
        self.assertFlagsUnchanged([])
        self.assertFlagsUnchanged(['-include', '/usr/local/include'])
        self.assertFlagsUnchanged(['-I.'])
        self.assertFlagsUnchanged(['-I', '.'])
        self.assertFlagsUnchanged(['-I/usr/local/include'])
        self.assertFlagsUnchanged(['-I', '/usr/local/include'])
        self.assertFlagsUnchanged(['-I/opt', '-I', '/opt/otp/include'])
        self.assertFlagsUnchanged(['-isystem', '/path'])
        self.assertFlagsUnchanged(['-isystem=/path'])

    def test_define_pass(self):
        self.assertFlagsUnchanged(['-DNDEBUG'])
        self.assertFlagsUnchanged(['-UNDEBUG'])
        self.assertFlagsUnchanged(['-Dvar1=val1', '-Dvar2=val2'])
        self.assertFlagsUnchanged(['-Dvar="val ues"'])

    def test_output_filtered(self):
        self.assertFlagsFiltered(['-o', 'source.o'])

    def test_some_warning_filtered(self):
        self.assertFlagsFiltered(['-Wall'])
        self.assertFlagsFiltered(['-Wnoexcept'])
        self.assertFlagsFiltered(['-Wreorder', '-Wunused', '-Wundef'])
        self.assertFlagsUnchanged(['-Wno-reorder', '-Wno-unused'])

    def test_compile_only_flags_pass(self):
        self.assertFlagsUnchanged(['-std=C99'])
        self.assertFlagsUnchanged(['-nostdinc'])
        self.assertFlagsUnchanged(['-isystem', '/image/debian'])
        self.assertFlagsUnchanged(['-iprefix', '/usr/local'])
        self.assertFlagsUnchanged(['-iquote=me'])
        self.assertFlagsUnchanged(['-iquote', 'me'])

    def test_compile_and_link_flags_pass(self):
        self.assertFlagsUnchanged(['-fsinged-char'])
        self.assertFlagsUnchanged(['-fPIC'])
        self.assertFlagsUnchanged(['-stdlib=libc++'])
        self.assertFlagsUnchanged(['--sysroot', '/'])
        self.assertFlagsUnchanged(['-isysroot', '/'])

    def test_some_flags_filtered(self):
        self.assertFlagsFiltered(['-g'])
        self.assertFlagsFiltered(['-fsyntax-only'])
        self.assertFlagsFiltered(['-save-temps'])
        self.assertFlagsFiltered(['-init', 'my_init'])
        self.assertFlagsFiltered(['-sectorder', 'a', 'b', 'c'])


class RunAnalyzerTest(unittest.TestCase):

    @staticmethod
    def run_analyzer(content, failures_report):
        with temporary_directory() as tmp_dir:
            filename = os.path.join(tmp_dir, 'test.cpp')
            with open(filename, 'w') as handle:
                handle.write(content)

            opts = {
                'clang': 'clang',
                'directory': os.getcwd(),
                'flags': [],
                'direct_args': [],
                'file': filename,
                'output_dir': tmp_dir,
                'output_format': 'plist',
                'output_failures': failures_report
            }
            spy = Spy()
            result = sut.run_analyzer(opts, spy.call)
            return result, spy.arg

    def test_run_analyzer(self):
        content = "int div(int n, int d) { return n / d; }"
        (result, fwds) = RunAnalyzerTest.run_analyzer(content, False)
        self.assertEqual(None, fwds)
        self.assertEqual(0, result['exit_code'])

    def test_run_analyzer_crash(self):
        content = "int div(int n, int d) { return n / d }"
        (result, fwds) = RunAnalyzerTest.run_analyzer(content, False)
        self.assertEqual(None, fwds)
        self.assertEqual(1, result['exit_code'])

    def test_run_analyzer_crash_and_forwarded(self):
        content = "int div(int n, int d) { return n / d }"
        (_, fwds) = RunAnalyzerTest.run_analyzer(content, True)
        self.assertEqual(1, fwds['exit_code'])
        self.assertTrue(len(fwds['error_output']) > 0)


class ReportFailureTest(unittest.TestCase):

    def assertUnderFailures(self, path):
        self.assertEqual('failures', os.path.basename(os.path.dirname(path)))

    def test_report_failure_create_files(self):
        with temporary_directory() as tmp_dir:
            # create input file
            filename = os.path.join(tmp_dir, 'test.c')
            with open(filename, 'w') as handle:
                handle.write('int main() { return 0')
            uname_msg = ' '.join(platform.uname()).strip()
            error_msg = 'this is my error output'
            # execute test
            opts = {
                'clang': 'clang',
                'directory': os.getcwd(),
                'flags': [],
                'file': filename,
                'output_dir': tmp_dir,
                'language': 'c',
                'error_output': error_msg,
                'exit_code': 13
            }
            sut.report_failure(opts)
            # find the info file
            pp_files = glob.glob(os.path.join(tmp_dir, 'failures', '*.i'))
            self.assertIsNot(pp_files, [])
            pp_file = pp_files[0]
            # info file generated and content dumped
            info_file = pp_file + '.info.txt'
            self.assertTrue(os.path.exists(info_file))
            with open(info_file) as info_handler:
                lines = [line.strip() for line in info_handler.readlines() if
                         line.strip()]
                self.assertEqual('Other Error', lines[1])
                self.assertEqual(uname_msg, lines[3])
            # error file generated and content dumped
            error_file = pp_file + '.stderr.txt'
            self.assertTrue(os.path.exists(error_file))
            with open(error_file) as error_handle:
                self.assertEqual([error_msg], error_handle.readlines())


class AnalyzerTest(unittest.TestCase):

    def test_nodebug_macros_appended(self):
        def test(flags):
            spy = Spy()
            opts = {'flags': flags, 'force_debug': True}
            self.assertEqual(spy.success,
                             sut.filter_debug_flags(opts, spy.call))
            return spy.arg['flags']

        self.assertEqual(['-UNDEBUG'], test([]))
        self.assertEqual(['-DNDEBUG', '-UNDEBUG'], test(['-DNDEBUG']))
        self.assertEqual(['-DSomething', '-UNDEBUG'], test(['-DSomething']))

    def test_set_language_fall_through(self):
        def language(expected, input):
            spy = Spy()
            input.update({'compiler': 'c', 'file': 'test.c'})
            self.assertEqual(spy.success, sut.language_check(input, spy.call))
            self.assertEqual(expected, spy.arg['language'])

        language('c',   {'language': 'c', 'flags': []})
        language('c++', {'language': 'c++', 'flags': []})

    def test_set_language_stops_on_not_supported(self):
        spy = Spy()
        input = {
            'compiler': 'c',
            'flags': [],
            'file': 'test.java',
            'language': 'java'
        }
        self.assertEquals(dict(), sut.language_check(input, spy.call))
        self.assertIsNone(spy.arg)

    def test_set_language_sets_flags(self):
        def flags(expected, input):
            spy = Spy()
            input.update({'compiler': 'c', 'file': 'test.c'})
            self.assertEqual(spy.success, sut.language_check(input, spy.call))
            self.assertEqual(expected, spy.arg['flags'])

        flags(['-x', 'c'],   {'language': 'c', 'flags': []})
        flags(['-x', 'c++'], {'language': 'c++', 'flags': []})

    def test_set_language_from_filename(self):
        def language(expected, input):
            spy = Spy()
            input.update({'language': None, 'flags': []})
            self.assertEqual(spy.success, sut.language_check(input, spy.call))
            self.assertEqual(expected, spy.arg['language'])

        language('c',   {'file': 'file.c',   'compiler': 'c'})
        language('c++', {'file': 'file.c',   'compiler': 'c++'})
        language('c++', {'file': 'file.cxx', 'compiler': 'c'})
        language('c++', {'file': 'file.cxx', 'compiler': 'c++'})
        language('c++', {'file': 'file.cpp', 'compiler': 'c++'})
        language('c-cpp-output',   {'file': 'file.i', 'compiler': 'c'})
        language('c++-cpp-output', {'file': 'file.i', 'compiler': 'c++'})

    def test_arch_loop_sets_flags(self):
        def flags(archs):
            spy = Spy()
            input = {'flags': [], 'arch_list': archs}
            sut.arch_check(input, spy.call)
            return spy.arg['flags']

        self.assertEqual([], flags([]))
        self.assertEqual(['-arch', 'i386'], flags(['i386']))
        self.assertEqual(['-arch', 'i386'], flags(['i386', 'ppc']))
        self.assertEqual(['-arch', 'sparc'], flags(['i386', 'sparc']))

    def test_arch_loop_stops_on_not_supported(self):
        def stop(archs):
            spy = Spy()
            input = {'flags': [], 'arch_list': archs}
            self.assertEqual(dict(), sut.arch_check(input, spy.call))
            self.assertIsNone(spy.arg)

        stop(['ppc'])
        stop(['ppc64'])


@sut.require([])
def method_without_expecteds(opts):
    return 0


@sut.require(['this', 'that'])
def method_with_expecteds(opts):
    return 0


@sut.require([])
def method_exception_from_inside(opts):
    raise Exception('here is one')


class RequireDecoratorTest(unittest.TestCase):

    def test_method_without_expecteds(self):
        self.assertEqual(method_without_expecteds(dict()), 0)
        self.assertEqual(method_without_expecteds({}), 0)
        self.assertEqual(method_without_expecteds({'this': 2}), 0)
        self.assertEqual(method_without_expecteds({'that': 3}), 0)

    def test_method_with_expecteds(self):
        self.assertRaises(AssertionError, method_with_expecteds, dict())
        self.assertRaises(AssertionError, method_with_expecteds, {})
        self.assertRaises(AssertionError, method_with_expecteds, {'this': 2})
        self.assertRaises(AssertionError, method_with_expecteds, {'that': 3})
        self.assertEqual(method_with_expecteds({'this': 0, 'that': 3}), 0)

    def test_method_exception_not_caught(self):
        self.assertRaises(Exception, method_exception_from_inside, dict())


class ReportDirectoryTest(unittest.TestCase):

    # Test that successive report directory names ascend in lexicographic
    # order. This is required so that report directories from two runs of
    # scan-build can be easily matched up to compare results.
    @unittest.skipIf(IS_WINDOWS, 'windows has low resolution timer')
    def test_directory_name_comparison(self):
        with temporary_directory() as tmp_dir, \
             sut.report_directory(tmp_dir, False) as report_dir1, \
             sut.report_directory(tmp_dir, False) as report_dir2, \
             sut.report_directory(tmp_dir, False) as report_dir3:
            self.assertLess(report_dir1, report_dir2)
            self.assertLess(report_dir2, report_dir3)
