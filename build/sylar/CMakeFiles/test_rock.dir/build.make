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
include sylar/CMakeFiles/test_rock.dir/depend.make

# Include the progress variables for this target.
include sylar/CMakeFiles/test_rock.dir/progress.make

# Include the compile flags for this target's objects.
include sylar/CMakeFiles/test_rock.dir/flags.make

sylar/CMakeFiles/test_rock.dir/tests/test_rock.cc.o: sylar/CMakeFiles/test_rock.dir/flags.make
sylar/CMakeFiles/test_rock.dir/tests/test_rock.cc.o: ../sylar/tests/test_rock.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object sylar/CMakeFiles/test_rock.dir/tests/test_rock.cc.o"
	cd /mnt/g/others/sblog/build/sylar && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"tests/test_rock.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_rock.dir/tests/test_rock.cc.o -c /mnt/g/others/sblog/sylar/tests/test_rock.cc

sylar/CMakeFiles/test_rock.dir/tests/test_rock.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_rock.dir/tests/test_rock.cc.i"
	cd /mnt/g/others/sblog/build/sylar && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"tests/test_rock.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/sylar/tests/test_rock.cc > CMakeFiles/test_rock.dir/tests/test_rock.cc.i

sylar/CMakeFiles/test_rock.dir/tests/test_rock.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_rock.dir/tests/test_rock.cc.s"
	cd /mnt/g/others/sblog/build/sylar && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"tests/test_rock.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/sylar/tests/test_rock.cc -o CMakeFiles/test_rock.dir/tests/test_rock.cc.s

# Object files for target test_rock
test_rock_OBJECTS = \
"CMakeFiles/test_rock.dir/tests/test_rock.cc.o"

# External object files for target test_rock
test_rock_EXTERNAL_OBJECTS =

../sylar/bin/test_rock: sylar/CMakeFiles/test_rock.dir/tests/test_rock.cc.o
../sylar/bin/test_rock: sylar/CMakeFiles/test_rock.dir/build.make
../sylar/bin/test_rock: ../sylar/lib/libsylar.so
../sylar/bin/test_rock: /usr/local/lib/libjsoncpp.so.1.9.5
../sylar/bin/test_rock: /usr/lib/x86_64-linux-gnu/libssl.so
../sylar/bin/test_rock: /usr/lib/x86_64-linux-gnu/libcrypto.so
../sylar/bin/test_rock: /usr/lib/x86_64-linux-gnu/libprotobuf.so
../sylar/bin/test_rock: /usr/lib/x86_64-linux-gnu/libz.so
../sylar/bin/test_rock: /usr/lib/x86_64-linux-gnu/libsqlite3.so
../sylar/bin/test_rock: sylar/CMakeFiles/test_rock.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../sylar/bin/test_rock"
	cd /mnt/g/others/sblog/build/sylar && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_rock.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
sylar/CMakeFiles/test_rock.dir/build: ../sylar/bin/test_rock

.PHONY : sylar/CMakeFiles/test_rock.dir/build

sylar/CMakeFiles/test_rock.dir/clean:
	cd /mnt/g/others/sblog/build/sylar && $(CMAKE_COMMAND) -P CMakeFiles/test_rock.dir/cmake_clean.cmake
.PHONY : sylar/CMakeFiles/test_rock.dir/clean

sylar/CMakeFiles/test_rock.dir/depend:
	cd /mnt/g/others/sblog/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/g/others/sblog /mnt/g/others/sblog/sylar /mnt/g/others/sblog/build /mnt/g/others/sblog/build/sylar /mnt/g/others/sblog/build/sylar/CMakeFiles/test_rock.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : sylar/CMakeFiles/test_rock.dir/depend

