cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(btest)

# Install scripts
install(DIRECTORY DESTINATION bin)
install(PROGRAMS
    btest
    btest-ask-update
    btest-bg-run
    btest-bg-run-helper
    btest-bg-wait
    btest-diff
    btest-setsid
    btest-progress
    sphinx/btest-diff-rst
    sphinx/btest-rst-cmd
    sphinx/btest-rst-include
    sphinx/btest-rst-pipe
    DESTINATION bin)

if ( NOT PY_MOD_INSTALL_DIR )
    # This is not a Zeek-bundled install, from which we'd inherit that
    # variable.  Default to "home"-style install.
    set(PY_MOD_INSTALL_DIR lib/python)
endif ()

# Install the Python module
install(DIRECTORY DESTINATION ${PY_MOD_INSTALL_DIR})
install(FILES sphinx/btest-sphinx.py DESTINATION ${PY_MOD_INSTALL_DIR})

message(
    "\n====================|  BTest Build Summary  |==================="
    "\n"
    "\nInstall prefix:      ${CMAKE_INSTALL_PREFIX}"
    "\nPython module path:  ${PY_MOD_INSTALL_DIR}"
    "\n"
    "\n================================================================\n"
)
