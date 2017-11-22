# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.

import libscanbuild.report as sut
import unittest
import os
import os.path
import glob
from test_fixture import temporary_directory

IS_WINDOWS = os.getenv('windows')


def run_bug_parse(content):
    with temporary_directory() as tmp_dir:
        file_name = os.path.join(tmp_dir, 'test.html')
        with open(file_name, 'w') as handle:
            lines = (line + os.linesep for line in content)
            handle.writelines(lines)
        for bug in sut.parse_bug_html(file_name):
            return bug


def run_crash_parse(content, prefix):
    with temporary_directory() as tmp_dir:
        file_name = os.path.join(tmp_dir, prefix + '.info.txt')
        with open(file_name, 'w') as handle:
            lines = (line + os.linesep for line in content)
            handle.writelines(lines)
        return sut.parse_crash(file_name)


class ParseFileTest(unittest.TestCase):

    def test_parse_bug(self):
        content = [
            "some header",
            "<!-- BUGDESC Division by zero -->",
            "<!-- BUGTYPE Division by zero -->",
            "<!-- BUGCATEGORY Logic error -->",
            "<!-- BUGFILE xx -->",
            "<!-- BUGLINE 5 -->",
            "<!-- BUGCOLUMN 22 -->",
            "<!-- BUGPATHLENGTH 4 -->",
            "<!-- BUGMETAEND -->",
            "<!-- REPORTHEADER -->",
            "some tails"]
        result = run_bug_parse(content)
        self.assertEqual(result['bug_category'], 'Logic error')
        self.assertEqual(result['bug_path_length'], 4)
        self.assertEqual(result['bug_line'], 5)
        self.assertEqual(result['bug_description'], 'Division by zero')
        self.assertEqual(result['bug_type'], 'Division by zero')
        self.assertEqual(result['bug_file'], 'xx')

    def test_parse_bug_empty(self):
        content = []
        result = run_bug_parse(content)
        self.assertEqual(result['bug_category'], 'Other')
        self.assertEqual(result['bug_path_length'], 1)
        self.assertEqual(result['bug_line'], 0)

    def test_parse_crash(self):
        content = [
            "/some/path/file.c",
            "Some very serious Error",
            "bla",
            "bla-bla"]
        result = run_crash_parse(content, 'file.i')
        self.assertEqual(result['source'], content[0].rstrip())
        self.assertEqual(result['problem'], content[1].rstrip())
        self.assertEqual(os.path.basename(result['file']),
                         'file.i')
        self.assertEqual(os.path.basename(result['info']),
                         'file.i.info.txt')
        self.assertEqual(os.path.basename(result['stderr']),
                         'file.i.stderr.txt')

    def test_parse_real_crash(self):
        import libscanbuild.analyze as sut2
        with temporary_directory() as tmp_dir:
            filename = os.path.join(tmp_dir, 'test.c')
            with open(filename, 'w') as handle:
                handle.write('int main() { return 0')
            # produce failure report
            opts = {
                'clang': 'clang',
                'directory': os.getcwd(),
                'flags': [],
                'source': filename,
                'output_dir': tmp_dir,
                'language': 'c',
                'error_output': 'some output',
                'exit_code': 13
            }
            sut2.report_failure(opts)
            # find the info file
            pp_files = glob.glob(os.path.join(tmp_dir, 'failures', '*.i'))
            self.assertIsNot(pp_files, [])
            pp_file = pp_files[0]
            # read the failure report back
            result = sut.parse_crash(pp_file + '.info.txt')
            self.assertEqual(result['source'], filename)
            self.assertEqual(result['problem'], 'Other Error')
            self.assertEqual(result['file'], pp_file)
            self.assertEqual(result['info'], pp_file + '.info.txt')
            self.assertEqual(result['stderr'], pp_file + '.stderr.txt')


class ReportMethodTest(unittest.TestCase):

    @unittest.skipIf(IS_WINDOWS, 'windows has different path patterns')
    def test_chop(self):
        self.assertEqual('file', sut.chop('/prefix', '/prefix/file'))
        self.assertEqual('file', sut.chop('/prefix/', '/prefix/file'))
        self.assertEqual('lib/file', sut.chop('/prefix/', '/prefix/lib/file'))
        self.assertEqual('/prefix/file', sut.chop('', '/prefix/file'))

    @unittest.skipIf(IS_WINDOWS, 'windows has different path patterns')
    def test_chop_when_cwd(self):
        self.assertEqual('../src/file', sut.chop('/cwd', '/src/file'))
        self.assertEqual('../src/file', sut.chop('/prefix/cwd',
                                                 '/prefix/src/file'))

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_chop_on_windows(self):
        self.assertEqual('file', sut.chop('c:\\prefix', 'c:\\prefix\\file'))
        self.assertEqual('file', sut.chop('c:\\prefix\\', 'c:\\prefix\\file'))
        self.assertEqual('lib\\file',
                         sut.chop('c:\\prefix\\', 'c:\\prefix\\lib\\file'))
        self.assertEqual('c:\\prefix\\file', sut.chop('', 'c:\\prefix\\file'))

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_chop_when_cwd_on_windows(self):
        self.assertEqual('..\\src\\file',
                         sut.chop('c:\\cwd', 'c:\\src\\file'))
        self.assertEqual('..\\src\\file',
                         sut.chop('z:\\prefix\\cwd', 'z:\\prefix\\src\\file'))


class GetPrefixFromCompilationDatabaseTest(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(
            sut.commonprefix([]), '')

    @unittest.skipIf(IS_WINDOWS, 'windows has different path patterns')
    def test_with_different_filenames(self):
        self.assertEqual(
            sut.commonprefix(['/tmp/a.c', '/tmp/b.c']), '/tmp')

    @unittest.skipIf(IS_WINDOWS, 'windows has different path patterns')
    def test_with_different_dirnames(self):
        self.assertEqual(
            sut.commonprefix(['/tmp/abs/a.c', '/tmp/ack/b.c']), '/tmp')

    @unittest.skipIf(IS_WINDOWS, 'windows has different path patterns')
    def test_no_common_prefix(self):
        self.assertEqual(
            sut.commonprefix(['/tmp/abs/a.c', '/usr/ack/b.c']), '/')

    @unittest.skipIf(IS_WINDOWS, 'windows has different path patterns')
    def test_with_single_file(self):
        self.assertEqual(
            sut.commonprefix(['/tmp/a.c']), '/tmp')

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_with_different_filenames_on_windows(self):
        self.assertEqual(
            sut.commonprefix(['c:\\tmp\\a.c', 'c:\\tmp\\b.c']), 'c:\\tmp')

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_with_different_dirnames_on_windows(self):
        self.assertEqual(
            sut.commonprefix(['c:\\tmp\\abs\\a.c', 'c:\\tmp\\ack\\b.c']),
            'c:\\tmp')

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_no_common_prefix_on_windows(self):
        self.assertEqual(
            sut.commonprefix(['z:\\tmp\\abs\\a.c', 'z:\\usr\\ack\\b.c']),
            'z:\\')

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_different_drive_on_windows(self):
        self.assertEqual(
            sut.commonprefix(['c:\\tmp\\abs\\a.c', 'z:\\usr\\ack\\b.c']),
            '')

    @unittest.skipIf(not IS_WINDOWS, 'windows has different path patterns')
    def test_with_single_file_on_windows(self):
        self.assertEqual(
            sut.commonprefix(['z:\\tmp\\a.c']), 'z:\\tmp')
