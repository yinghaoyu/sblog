# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Produce verbose output by default.
VERBOSE = 1

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/g/others/sblog

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/g/others/sblog/build

# Include any dependencies generated for this target.
include sylar/CMakeFiles/test_daemon.dir/depend.make

# Include the progress variables for this target.
include sylar/CMakeFiles/test_daemon.dir/progress.make

# Include the compile flags for this target's objects.
include sylar/CMakeFiles/test_daemon.dir/flags.make

sylar/CMakeFiles/test_daemon.dir/tests/test_daemon.cc.o: sylar/CMakeFiles/test_daemon.dir/flags.make
sylar/CMakeFiles/test_daemon.dir/tests/test_daemon.cc.o: ../sylar/tests/test_daemon.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object sylar/CMakeFiles/test_daemon.dir/tests/test_daemon.cc.o"
	cd /mnt/g/others/sblog/build/sylar && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"tests/test_daemon.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_daemon.dir/tests/test_daemon.cc.o -c /mnt/g/others/sblog/sylar/tests/test_daemon.cc

sylar/CMakeFiles/test_daemon.dir/tests/test_daemon.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_daemon.dir/tests/test_daemon.cc.i"
	cd /mnt/g/others/sblog/build/sylar && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"tests/test_daemon.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/sylar/tests/test_daemon.cc > CMakeFiles/test_daemon.dir/tests/test_daemon.cc.i

sylar/CMakeFiles/test_daemon.dir/tests/test_daemon.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_daemon.dir/tests/test_daemon.cc.s"
	cd /mnt/g/others/sblog/build/sylar && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"tests/test_daemon.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/sylar/tests/test_daemon.cc -o CMakeFiles/test_daemon.dir/tests/test_daemon.cc.s

# Object files for target test_daemon
test_daemon_OBJECTS = \
"CMakeFiles/test_daemon.dir/tests/test_daemon.cc.o"

# External object files for target test_daemon
test_daemon_EXTERNAL_OBJECTS =

../sylar/bin/test_daemon: sylar/CMakeFiles/test_daemon.dir/tests/test_daemon.cc.o
../sylar/bin/test_daemon: sylar/CMakeFiles/test_daemon.dir/build.make
../sylar/bin/test_daemon: ../sylar/lib/libsylar.so
../sylar/bin/test_daemon: /usr/local/lib/libjsoncpp.so.1.9.5
../sylar/bin/test_daemon: /usr/lib/x86_64-linux-gnu/libssl.so
../sylar/bin/test_daemon: /usr/lib/x86_64-linux-gnu/libcrypto.so
../sylar/bin/test_daemon: /usr/lib/x86_64-linux-gnu/libprotobuf.so
../sylar/bin/test_daemon: /usr/lib/x86_64-linux-gnu/libz.so
../sylar/bin/test_daemon: /usr/lib/x86_64-linux-gnu/libsqlite3.so
../sylar/bin/test_daemon: sylar/CMakeFiles/test_daemon.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../sylar/bin/test_daemon"
	cd /mnt/g/others/sblog/build/sylar && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_daemon.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
sylar/CMakeFiles/test_daemon.dir/build: ../sylar/bin/test_daemon

.PHONY : sylar/CMakeFiles/test_daemon.dir/build

sylar/CMakeFiles/test_daemon.dir/clean:
	cd /mnt/g/others/sblog/build/sylar && $(CMAKE_COMMAND) -P CMakeFiles/test_daemon.dir/cmake_clean.cmake
.PHONY : sylar/CMakeFiles/test_daemon.dir/clean

sylar/CMakeFiles/test_daemon.dir/depend:
	cd /mnt/g/others/sblog/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/g/others/sblog /mnt/g/others/sblog/sylar /mnt/g/others/sblog/build /mnt/g/others/sblog/build/sylar /mnt/g/others/sblog/build/sylar/CMakeFiles/test_daemon.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : sylar/CMakeFiles/test_daemon.dir/depend

