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
include orm_out/CMakeFiles/orm_data.dir/depend.make

# Include the progress variables for this target.
include orm_out/CMakeFiles/orm_data.dir/progress.make

# Include the compile flags for this target's objects.
include orm_out/CMakeFiles/orm_data.dir/flags.make

orm_out/CMakeFiles/orm_data.dir/blog/data/article_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/article_info.cc.o: ../orm_out/blog/data/article_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/article_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/article_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/article_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/article_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/article_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/article_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/article_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/article_info.cc > CMakeFiles/orm_data.dir/blog/data/article_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/article_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/article_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/article_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/article_info.cc -o CMakeFiles/orm_data.dir/blog/data/article_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.o: ../orm_out/blog/data/article_category_rel_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/article_category_rel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/article_category_rel_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/article_category_rel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/article_category_rel_info.cc > CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/article_category_rel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/article_category_rel_info.cc -o CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.o: ../orm_out/blog/data/article_label_rel_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/article_label_rel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/article_label_rel_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/article_label_rel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/article_label_rel_info.cc > CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/article_label_rel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/article_label_rel_info.cc -o CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/category_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/category_info.cc.o: ../orm_out/blog/data/category_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/category_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/category_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/category_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/category_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/category_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/category_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/category_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/category_info.cc > CMakeFiles/orm_data.dir/blog/data/category_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/category_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/category_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/category_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/category_info.cc -o CMakeFiles/orm_data.dir/blog/data/category_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/channel_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/channel_info.cc.o: ../orm_out/blog/data/channel_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/channel_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/channel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/channel_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/channel_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/channel_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/channel_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/channel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/channel_info.cc > CMakeFiles/orm_data.dir/blog/data/channel_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/channel_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/channel_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/channel_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/channel_info.cc -o CMakeFiles/orm_data.dir/blog/data/channel_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/comment_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/comment_info.cc.o: ../orm_out/blog/data/comment_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/comment_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/comment_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/comment_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/comment_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/comment_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/comment_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/comment_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/comment_info.cc > CMakeFiles/orm_data.dir/blog/data/comment_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/comment_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/comment_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/comment_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/comment_info.cc -o CMakeFiles/orm_data.dir/blog/data/comment_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/label_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/label_info.cc.o: ../orm_out/blog/data/label_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/label_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/label_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/label_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/label_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/label_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/label_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/label_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/label_info.cc > CMakeFiles/orm_data.dir/blog/data/label_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/label_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/label_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/label_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/label_info.cc -o CMakeFiles/orm_data.dir/blog/data/label_info.cc.s

orm_out/CMakeFiles/orm_data.dir/blog/data/user_info.cc.o: orm_out/CMakeFiles/orm_data.dir/flags.make
orm_out/CMakeFiles/orm_data.dir/blog/data/user_info.cc.o: ../orm_out/blog/data/user_info.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object orm_out/CMakeFiles/orm_data.dir/blog/data/user_info.cc.o"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++  $(CXX_DEFINES) -D__FILE__=\"blog/data/user_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/orm_data.dir/blog/data/user_info.cc.o -c /mnt/g/others/sblog/orm_out/blog/data/user_info.cc

orm_out/CMakeFiles/orm_data.dir/blog/data/user_info.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/orm_data.dir/blog/data/user_info.cc.i"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/user_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/g/others/sblog/orm_out/blog/data/user_info.cc > CMakeFiles/orm_data.dir/blog/data/user_info.cc.i

orm_out/CMakeFiles/orm_data.dir/blog/data/user_info.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/orm_data.dir/blog/data/user_info.cc.s"
	cd /mnt/g/others/sblog/build/orm_out && /usr/bin/c++ $(CXX_DEFINES) -D__FILE__=\"blog/data/user_info.cc\" $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/g/others/sblog/orm_out/blog/data/user_info.cc -o CMakeFiles/orm_data.dir/blog/data/user_info.cc.s

# Object files for target orm_data
orm_data_OBJECTS = \
"CMakeFiles/orm_data.dir/blog/data/article_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/category_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/channel_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/comment_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/label_info.cc.o" \
"CMakeFiles/orm_data.dir/blog/data/user_info.cc.o"

# External object files for target orm_data
orm_data_EXTERNAL_OBJECTS =

orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/article_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/article_category_rel_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/article_label_rel_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/category_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/channel_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/comment_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/label_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/blog/data/user_info.cc.o
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/build.make
orm_out/liborm_data.a: orm_out/CMakeFiles/orm_data.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/g/others/sblog/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX static library liborm_data.a"
	cd /mnt/g/others/sblog/build/orm_out && $(CMAKE_COMMAND) -P CMakeFiles/orm_data.dir/cmake_clean_target.cmake
	cd /mnt/g/others/sblog/build/orm_out && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/orm_data.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
orm_out/CMakeFiles/orm_data.dir/build: orm_out/liborm_data.a

.PHONY : orm_out/CMakeFiles/orm_data.dir/build

orm_out/CMakeFiles/orm_data.dir/clean:
	cd /mnt/g/others/sblog/build/orm_out && $(CMAKE_COMMAND) -P CMakeFiles/orm_data.dir/cmake_clean.cmake
.PHONY : orm_out/CMakeFiles/orm_data.dir/clean

orm_out/CMakeFiles/orm_data.dir/depend:
	cd /mnt/g/others/sblog/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/g/others/sblog /mnt/g/others/sblog/orm_out /mnt/g/others/sblog/build /mnt/g/others/sblog/build/orm_out /mnt/g/others/sblog/build/orm_out/CMakeFiles/orm_data.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : orm_out/CMakeFiles/orm_data.dir/depend

