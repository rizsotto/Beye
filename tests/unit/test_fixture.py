# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
import contextlib
import unittest
import os.path
import shutil
import tempfile


@contextlib.contextmanager
def temporary_directory(**kwargs):
    name = tempfile.mkdtemp(**kwargs)
    try:
        yield name
    finally:
        shutil.rmtree(name)


class TemporaryDirectoryTest(unittest.TestCase):
    def test_creates_directory(self):
        with temporary_directory() as tmp_dir:
            self.assertTrue(os.path.isdir(tmp_dir))
            dir_name = tmp_dir
        self.assertIsNotNone(dir_name)
        self.assertFalse(os.path.exists(dir_name))

    def test_removes_directory_when_exception(self):
        dir_name = None
        try:
            with temporary_directory() as tmp_dir:
                self.assertTrue(os.path.isdir(tmp_dir))
                dir_name = tmp_dir
                raise RuntimeError('message')
        except RuntimeError:
            self.assertIsNotNone(dir_name)
            self.assertFalse(os.path.exists(dir_name))
