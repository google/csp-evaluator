#!/usr/bin/env bash
# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# @fileoverview Shell script to facilitate build-related tasks for csp-evaluator
#

PYTHON_CMD="python"
JSCOMPILE_CMD="java -jar third_party/closure-compiler/build/compiler.jar --flagfile=compiler.flags"
CKSUM_CMD="cksum" # chosen because it's available on most Linux/OS X installations
BUILD_DIR="build"
BUILD_TPL_DIR="$BUILD_DIR/ui"
cd "${0%/*}"

evaluator_assert_dependencies() {
  # Check if required binaries are present.
  type "$PYTHON_CMD" >/dev/null 2>&1 || { echo >&2 "Python is required to build csp-evaluator."; exit 1; }
  type ant >/dev/null 2>&1 || { echo >&2 "Ant is required to build csp-evaluator."; exit 1; }
  type java >/dev/null 2>&1 || { echo >&2 "Java is required to build csp-evaluator."; exit 1; }
  jversion=$(java -version 2>&1 | grep version | awk -F '"' '{print $2}')
  if [[ $jversion < "1.7" ]]; then
    echo "Java 1.7 or higher is required to build csp-evaluator."
    exit 1
  fi
  # Check if required files are present.
  files=(third_party/closure-library \
    third_party/closure-templates-compiler \
    third_party/closure-compiler/build/compiler.jar \
    third_party/closure-compiler/contrib/externs/chrome_extensions.js \
  )
  for var in "${files[@]}"
  do
    if [ ! -e "$var" ]; then
      echo "$var" "not found"
      echo >&2 "Download libraries needed to build first. Use $0 install_deps."
      exit 1
    fi
  done
  echo "All dependencies met."
}

evaluator_get_file_cksum() {
  # creates a checksum of a given file spec
  # no-op if $CKSUM_CMD is not available
  type $CKSUM_CMD >/dev/null 2>&1 && (find -name "$1" | sort | xargs $CKSUM_CMD | $CKSUM_CMD) || true
}

evaluator_build_templates() {
  evaluator_assert_dependencies
  set -e
  mkdir -p "$BUILD_TPL_DIR"
  rm -rf "$BUILD_TPL_DIR/*"
  # Compile soy templates
  echo "Compiling Soy templates..."
  rm -f "$BUILD_TPL_DIR/cksum"
  evaluator_get_file_cksum '*.soy' > "$BUILD_TPL_DIR/cksum"
  find "ui" -name '*.soy' -exec java -jar third_party/closure-templates-compiler/SoyToJsSrcCompiler.jar \
  --shouldProvideRequireSoyNamespaces --shouldDeclareTopLevelNamespaces --srcs {} \
  --outputPathFormat "$BUILD_TPL_DIR/{INPUT_DIRECTORY}{INPUT_FILE_NAME}.js" \;
  echo "Done."
}

evaluator_assert_buildfiles() {
  if [ ! -d "$BUILD_DIR" ] || [ ! -f "$BUILD_DIR/evaluator.html" ]; then
    echo "Please build csp-evaluator first."
    exit 1
  fi
}

evaluator_assert_templates() {
  if [ ! -d $BUILD_TPL_DIR ]; then
    evaluator_build_templates
  else
    # If cmp is unavailable, just ignore the check, instead of exiting
    type cmp >/dev/null 2>&1 && (evaluator_get_file_cksum '*.soy' | cmp "$BUILD_TPL_DIR/cksum" - >/dev/null 2>&1) || true
    if [ -f "$BUILD_TPL_DIR/cksum" -a $? -eq 0 ] ; then
      echo "Using previous template build. Run ./do.sh clean if you want to rebuild the templates."
    else
      echo "Template files changed since last build. Rebuilding..."
      evaluator_build_templates
    fi
  fi
}

evaluator_assert_jsdeps() {
  if [ ! -f "$BUILD_DIR/deps.js" ]; then
    evaluator_generate_jsdeps
  fi
}

evaluator_build_closure_lib_() {
  # $1 - Closure entry point
  # $2 - Filename
  # $3 - Additional source dir
  # $4 - [debug|optimized]
  ENTRY_POINT=$1
  FNAME=$2
  SRC_DIRS=( \
    evaluator/ \
    whitelist_bypasses \
    ui \
    checks \
    demo \
    third_party/closure-library/closure/goog \
    third_party/closure-library/third_party/closure/goog \
    third_party/closure-templates-compiler )
  if [ -d "$3" ]; then
    SRC_DIRS+=("$3")
  fi
  jscompile_evaluator="$JSCOMPILE_CMD"
  for var in "${SRC_DIRS[@]}"
  do
    jscompile_evaluator+=" --js='$var/**.js' --js='!$var/**_test.js' --js='!$var/**_perf.js'"
  done
  jscompile_evaluator+=" --js='!third_party/closure-library/closure/goog/demos/**.js'"
  if [ "$4" == "debug" ]; then
     jscompile_evaluator+=" --debug --formatting=PRETTY_PRINT -O WHITESPACE_ONLY"
  elif [ "$4" == "optimized" ]; then
     jscompile_evaluator+=" -O ADVANCED"
  fi
  echo -n "."
  $jscompile_evaluator --closure_entry_point "$ENTRY_POINT" --js_output_file "$FNAME"
}

evaluator_build_jsmodule() {
  echo "Building JS module $1 into $BUILD_DIR/$1.js..."
  evaluator_assert_dependencies
  set -e
  evaluator_assert_jsdeps
  mkdir -p "$BUILD_DIR"
  if [ "$2" == "debug" ]; then
    echo "Debug mode enabled"
  fi
  evaluator_build_closure_lib_ "$1" "$BUILD_DIR/$1.js" "" "$2";
  echo ""
  echo "Done."
}

evaluator_build() {
  evaluator_assert_dependencies
  set -e
  evaluator_assert_jsdeps
  evaluator_assert_templates

  echo "Building csp-evaluator app to $BUILD_DIR"
  # compile javascript files
  if [ "$1" == "debug" ]; then
    echo "Debug mode enabled"
  fi
  echo "Compiling JS files..."
  evaluator_build_closure_lib_ "csp.Demo" "$BUILD_DIR/evaluator_binary.js" "$BUILD_TPL_DIR" "$1"

  echo "Copying main demo html file"
  cp demo/demo.html "$BUILD_DIR"

  echo "Done."
}

evaluator_build_clean() {
  echo "Cleaning all builds..."
  rm -rfv "$BUILD_DIR"
  echo "Done."
}

evaluator_clean_deps() {
  echo "Removing all build dependencies. Install them with ./do.sh install_deps."
  rm -rfv lib
  echo "Done."
}

evaluator_install_deps() {
  set -e
  echo "Installing build dependencies..."
  ./download-libs.sh
  echo "Done."
}

evaluator_generate_jsdeps() {
  evaluator_assert_templates
  $PYTHON_CMD third_party/closure-library/closure/bin/build/depswriter.py \
    --root_with_prefix="ui/ ui/" \
    --root_with_prefix="checks/ checks/" \
    --root_with_prefix="whitelist_bypasses/ whitelist_bypasses/" \
    --root_with_prefix="./ ./" \
    --root_with_prefix="third_party/closure-templates-compiler/ third_party/closure-templates-compiler/" \
    > "$BUILD_DIR/deps.js"
}

RETVAL=0

CMD=$1
shift

case "$CMD" in
  check_deps)
    evaluator_assert_dependencies;
    ;;
  install_deps)
    evaluator_install_deps;
    ;;
  build)
    evaluator_build "$1";
    ;;
  build_templates)
    evaluator_build_templates;
    ;;
  build_jsmodule)
    evaluator_build_jsmodule "$*";
    ;;
  clean)
    evaluator_build_clean;
    ;;
  clean_deps)
    evaluator_clean_deps;
    ;;
  run)
    evaluator_run;
    ;;
  deps)
    evaluator_generate_deps;
    ;;
  *)
    echo "Usage:   $0 PARAMETER"
    echo "Setup:   $0 {install_deps|check_deps}"
    echo "Build:   $0 {build|build_templates} [debug]"
    echo "Cleanup: $0 {clean|clean_deps}"
    RETVAL=1
esac

exit $RETVAL
