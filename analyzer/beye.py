# -*- coding: utf-8 -*-
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.

import shlex
import logging
import multiprocessing
import subprocess
import json
import itertools
import re
import glob
import os
import os.path
import shutil
from analyzer.decorators import trace
from analyzer.driver import (
    run, filter_dict, get_clang_version, get_clang_arguments)
import analyzer.parallel


def main():
    multiprocessing.freeze_support()
    logging.basicConfig(format='%(message)s')

    def from_number_to_level(num):
        if 0 == num:
            return logging.WARNING
        elif 1 == num:
            return logging.INFO
        elif 2 == num:
            return logging.DEBUG
        else:
            return 5

    args = parse_command_line()

    logging.getLogger().setLevel(from_number_to_level(args.verbose))
    logging.debug(args.__dict__)

    with ReportDirectory(args.output, args.keep_empty) as out_dir:
        logging.warning('output directory: {0}'.format(out_dir))
        run_analyzer(args, out_dir)
        return 1 if generate_report(args.__dict__, out_dir) else 0


class ReportDirectory(object):

    def __init__(self, hint, keep):
        self.name = ReportDirectory._create(hint)
        self.keep = keep

    def __enter__(self):
        return self.name

    def __exit__(self, type, value, traceback):
        empty = 0 == len(glob.glob(os.path.join(self.name, '*')))
        if empty and not self.keep:
            shutil.rmtree(self.name)

    @staticmethod
    def _create(hint):
        if hint != '/tmp':
            import os
            try:
                os.mkdir(hint)
                return hint
            except OSError as ex:
                raise
        else:
            import tempfile
            return tempfile.mkdtemp(prefix='beye-', suffix='.out')


@trace
def parse_command_line():
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    parser = ArgumentParser(prog='beye',
                            formatter_class=ArgumentDefaultsHelpFormatter)
    group1 = parser.add_argument_group('options')
    group1.add_argument(
        '--analyze-headers',
        action='store_true',
        help='Also analyze functions in #included files. By default,\
              such functions are skipped unless they are called by\
              functions within the main source file.')
    group1.add_argument(
        '--output', '-o',
        metavar='<path>',
        default='/tmp',
        help='Specifies the output directory for analyzer reports.\
              Subdirectories will be created as needed to represent separate\
              "runs" of the analyzer.')
    group1.add_argument(
        '--html-title',  # TODO: implement usage
        metavar='<title>',
        help='Specify the title used on generated HTML pages.\
              If not specified, a default title will be used.')
    format_group = group1.add_mutually_exclusive_group()
    format_group.add_argument(
        '--plist',
        dest='output_format',
        const='plist',
        default='html',
        action='store_const',
        help='This option outputs the results as a set of .plist files.')
    format_group.add_argument(
        '--plist-html',
        dest='output_format',
        const='plist-html',
        default='html',
        action='store_const',
        help='This option outputs the results as a set of HTML and .plist\
              files.')
    group1.add_argument(
        '--status-bugs',  # TODO: implement usage
        action='store_true',
        help='By default, the exit status of ‘beye’ is the same as the\
              executed build command. Specifying this option causes the exit\
              status of ‘beye’ to be 1 if it found potential bugs and 0\
              otherwise.')
    group1.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help="Enable verbose output from ‘beye’. A second and third '-v'\
              increases verbosity.")
    # TODO: implement '-view '

    group2 = parser.add_argument_group('advanced options')
    group2.add_argument(
        '--keep-empty',
        action='store_true',
        help="Don't remove the build results directory even if no issues were\
              reported.")
    group2.add_argument(
        '--no-failure-reports',
        dest='report_failures',
        action='store_false',
        help="Do not create a 'failures' subdirectory that includes analyzer\
              crash reports and preprocessed source files.")
    group2.add_argument(
        '--stats',
        action='store_true',
        help='Generates visitation statistics for the project being analyzed.')
    group2.add_argument(
        '--internal-stats',
        action='store_true',
        help='Generate internal analyzer statistics.')
    group2.add_argument(
        '--maxloop',
        metavar='<loop count>',
        type=int,
        default=4,
        help='Specifiy the number of times a block can be visited before\
              giving up. Increase for more comprehensive coverage at a cost\
              of speed.')
    group2.add_argument(
        '--store',
        metavar='<model>',
        dest='store_model',
        default='region',
        choices=['region', 'basic'],
        help='Specify the store model used by the analyzer.\
              ‘region’ specifies a field- sensitive store model.\
              ‘basic’ which is far less precise but can more quickly\
              analyze code. ‘basic’ was the default store model for\
              checker-0.221 and earlier.')
    group2.add_argument(
        '--constraints',
        metavar='<model>',
        dest='constraints_model',
        default='range',
        choices=['range', 'basic'],
        help='Specify the contraint engine used by the analyzer. Specifying\
              ‘basic’ uses a simpler, less powerful constraint model used by\
              checker-0.160 and earlier.')
    group2.add_argument(
        '--use-analyzer',
        metavar='<path>',
        dest='clang',
        default='clang',
        help="‘beye’ uses the ‘clang’ executable relative to itself for\
              static analysis. One can override this behavior with this\
              option by using the ‘clang’ packaged with Xcode (on OS X) or\
              from the PATH.")
    group2.add_argument(
        '--analyzer-config',
        metavar='<options>',
        help="Provide options to pass through to the analyzer's\
              -analyzer-config flag. Several options are separated with comma:\
              'key1=val1,key2=val2'\
              \
              Available options:\
                stable-report-filename=true or false (default)\
                Switch the page naming to:\
                report-<filename>-<function/method name>-<id>.html\
                instead of report-XXXXXX.html")
    group2.add_argument(
        '--input',
        metavar='<file>',
        default="compile_commands.json",
        help="The JSON compilation database.")
    group2.add_argument(
        '--sequential',
        action='store_true',
        help="Execute analyzer sequentialy.")

    group3 = parser.add_argument_group('controlling checkers')
    group3.add_argument(
        '--load-plugin',
        metavar='<plugin library>',
        dest='plugins',
        action='append',
        help='Loading external checkers using the clang plugin interface.')
    group3.add_argument(
        '--enable-checker',
        metavar='<checker name>',
        action='append',
        help='Enable specific checker.')
    group3.add_argument(
        '--disable-checker',
        metavar='<checker name>',
        action='append',
        help='Disable specific checker.')

    return parser.parse_args()


@trace
def generate_report(args, out_dir):
    """ Generate the index.html """
    def consume(result, new):
        def isNotIn(container):
            def isDuplicate(one, two):
                return one['bug_file'] == two['bug_file']\
                    and one['bug_line'] == two['bug_line']\
                    and one['bug_path_length'] == two['bug_path_length']

            for elem in container:
                if isDuplicate(elem, new):
                    return False
            return True

        category = new['bug_category']
        current = result.get(category, [])
        if isNotIn(current):
            current.append(new)
        result.update({category: current})

    @trace
    def copy_resource_files():
        this_dir, _ = os.path.split(__file__)
        resources_dir = os.path.join(this_dir, 'resources')
        shutil.copy(os.path.join(resources_dir, 'scanview.css'), out_dir)
        shutil.copy(os.path.join(resources_dir, 'sorttable.js'), out_dir)
        shutil.copy(os.path.join(resources_dir, 'selectable.js'), out_dir)

    @trace
    def report(bugs, crashes):
        logging.debug('bugs: {0}, crashes: {1}'.format(bugs, crashes))
        result = (len(bugs) + len(crashes)) > 0
        if result:
            opts = filter_dict(args,
                               set(),
                               {'output': os.path.join(out_dir, 'index.html')})
            format_report(opts, bugs, crashes)
            copy_resource_files()
        return result

    bugs = dict()
    analyzer.parallel.run(
        glob.iglob(os.path.join(out_dir, '*.html')),
        scan_file,
        consume,
        bugs)
    return report(bugs, dict())  # TODO: collect crash reports


@trace
def run_analyzer(args, out_dir):
    def set_common_params(opts):
        def uname():
            return subprocess.check_output(['uname', '-a']).decode('ascii')

        return filter_dict(
            opts,
            frozenset([
                'output',
                'html_title',
                'keep_empty',
                'status_bugs',
                'input',
                'sequential']),
            {'html_dir': out_dir,
             'uname': uname()})

    const = set_common_params(args.__dict__)
    with open(args.input, 'r') as fd:
        pool = multiprocessing.Pool(1 if args.sequential else None)
        for c in json.load(fd):
            c.update(const)
            c.update(command=shlex.split(c['command']))
            pool.apply_async(func=run, args=(c,))
        pool.close()
        pool.join()


@trace
def get_default_checkers(clang):
    """ To get the default plugins we execute Clang to print how this
    comilation would be called. For input file we specify stdin. And
    pass only language information. """
    def checkers(language):
        pattern = re.compile('^-analyzer-checker=(.*)$')
        cmd = [clang, '--analyze', '-x', language, '-']
        return [pattern.match(arg).group(1)
                for arg
                in get_clang_arguments('.', cmd)
                if pattern.match(arg)]
    return set(itertools.chain.from_iterable(
               [checkers(language)
                for language
                in ['c', 'c++', 'objective-c', 'objective-c++']]))


@trace
def scan_file(result):
    """ Parse out the bug information from HTML output. """
    patterns = frozenset(
        [re.compile('<!-- BUGTYPE (?P<bug_type>.*) -->$'),
         re.compile('<!-- BUGFILE (?P<bug_file>.*) -->$'),
         re.compile('<!-- BUGPATHLENGTH (?P<bug_path_length>.*) -->$'),
         re.compile('<!-- BUGLINE (?P<bug_line>.*) -->$'),
         re.compile('<!-- BUGCATEGORY (?P<bug_category>.*) -->$'),
         re.compile('<!-- BUGDESC (?P<bug_description>.*) -->$'),
         re.compile('<!-- FUNCTIONNAME (?P<bug_function>.*) -->$')])
    endsign = re.compile('<!-- BUGMETAEND -->')

    bug_info = dict()
    with open(result) as handler:
        for line in handler.readlines():
            # do not read the file further
            if endsign.match(line):
                break
            # search for the right lines
            for regex in patterns:
                match = regex.match(line.strip())
                if match:
                    bug_info.update(match.groupdict())

    # fix some default values
    bug_info['bug_category'] = bug_info.get('bug_category', 'Other')
    bug_info['bug_path_length'] = int(bug_info.get('bug_path_length', 1))
    bug_info['bug_line'] = int(bug_info.get('bug_line', 0))
    bug_info['report_file'] = result

    return bug_info


@trace
def format_report(opts, bugs, crashes):
    import textwrap
    main = textwrap.dedent("""
        <!DOCTYPE html>
        <html>
          <head>
            <title>{html_title}</title>
            <link type="text/css" rel="stylesheet" href="scanview.css"/>
            <script type='text/javascript' src="sorttable.js"></script>
            <script type='text/javascript' src='selectable.js'></script>
          </head>
          <body>
            <h1>{html_title}</h1>
            <table>
              <tr><th>User:</th><td>{user_name}@{host_name}</td></tr>
              <tr><th>Working Directory:</th><td>{current_dir}</td></tr>
              <tr><th>Command Line:</th><td>{cmd_args}</td></tr>
              <tr><th>Clang Version:</th><td>{clang_version}</td></tr>
              <tr><th>Date:</th><td>{date}</td></tr>
        {version_section}
            </table>
        {bug_section}
        {crash_section}
          </body>
        </html>
        """).strip()

    bug_section = textwrap.dedent("""
        <h2>Bug Summary</h2>
        {bugs_summary}
        <h2>Reports</h2>
        <table class="sortable" style="table-layout:automatic">
          <thead>
            <tr>
              <td>Bug Group</td>
              <td class="sorttable_sorted">Bug Type
                <span id="sorttable_sortfwdind">&nbsp;&#x25BE;</span>
              </td>
              <td>File</td>
              <td class="Q">Line</td>
              <td class="Q">Path Length</td>
              <td class="sorttable_nosort"></td>
              <!-- REPORTBUGCOL -->
            </tr>
          </thead>
          <tbody>
        {bugs}
          </tbody>
        </table>
        """).strip()

    crash_section = textwrap.dedent("""
        <h2>Analyzer Failures</h2>
        {crashes}
        """).strip()

    with open(opts['output'], 'w') as handle:
        handle.write(
            main.format(
                html_title='{}',
                user_name='{}',
                host_name='{}',
                current_dir=os.getcwd(),
                cmd_args='{}',
                clang_version=get_clang_version(opts['clang']),
                date='{}',
                version_section='',
                bug_section='{}',
                crash_section='{}'))
