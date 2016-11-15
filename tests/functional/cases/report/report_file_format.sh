#!/usr/bin/env bash

# RUN: bash %s %T/report_file_format
# RUN: cd %T/report_file_format; %{scan-build} --output . --keep-empty ./run.sh | ./check_html.sh
# RUN: cd %T/report_file_format; %{scan-build} --output . --keep-empty --plist ./run.sh | ./check_plist.sh
# RUN: cd %T/report_file_format; %{scan-build} --output . --keep-empty --plist-html ./run.sh | ./check_html.sh
# RUN: cd %T/report_file_format; %{scan-build} --output . --keep-empty --plist-html ./run.sh | ./check_plist.sh
# RUN: cd %T/report_file_format; %{scan-build} --output . --keep-empty --plist-multi-file ./run.sh | ./check_plist.sh

set -o errexit
set -o nounset
set -o xtrace

# the test creates a subdirectory inside output dir.
#
# ${root_dir}
# ├── run.sh
# ├── check_plist.sh
# ├── check_html.sh
# └── src
#    └── broken.c

root_dir=$1
mkdir -p "${root_dir}/src"

cp "${test_input_dir}/div_zero.c" "${root_dir}/src/broken.c"

build_file="${root_dir}/run.sh"
cat >> "${build_file}" << EOF
#!/usr/bin/env bash

set -o nounset
set -o xtrace

\${CC} -c -o src/broken.o src/broken.c
true
EOF
chmod +x "${build_file}"

check_one="${root_dir}/check_plist.sh"
cat >> "${check_one}" << EOF
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o xtrace

out_dir=\$(sed -n 's/\(.*\) Report directory created: \(.*\)/\2/p')
if [ -d "\$out_dir" ]
then
    ls \$out_dir/*.plist
else
    echo "output directory should exists"
    false
fi
EOF
chmod +x "${check_one}"

check_two="${root_dir}/check_html.sh"
cat >> "${check_two}" << EOF
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o xtrace

out_dir=\$(sed -n 's/\(.*\) Report directory created: \(.*\)/\2/p')
if [ -d "\$out_dir" ]
then
    ls "\$out_dir/index.html"
    ls \$out_dir/report-*.html
else
    echo "output directory should exists"
    false
fi
EOF
chmod +x "${check_two}"
