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
CMAKE_SOURCE_DIR = /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09

# Include any dependencies generated for this target.
include 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/depend.make

# Include the progress variables for this target.
include 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/progress.make

# Include the compile flags for this target's objects.
include 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/flags.make

3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/memplumber.cpp.o: 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/flags.make
3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/memplumber.cpp.o: 3rdParty/MemPlumber/MemPlumber/memplumber.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/memplumber.cpp.o"
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/memplumber.dir/memplumber.cpp.o -c /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber/memplumber.cpp

3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/memplumber.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/memplumber.dir/memplumber.cpp.i"
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber/memplumber.cpp > CMakeFiles/memplumber.dir/memplumber.cpp.i

3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/memplumber.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/memplumber.dir/memplumber.cpp.s"
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber/memplumber.cpp -o CMakeFiles/memplumber.dir/memplumber.cpp.s

# Object files for target memplumber
memplumber_OBJECTS = \
"CMakeFiles/memplumber.dir/memplumber.cpp.o"

# External object files for target memplumber
memplumber_EXTERNAL_OBJECTS =

3rdParty/MemPlumber/MemPlumber/libmemplumber.a: 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/memplumber.cpp.o
3rdParty/MemPlumber/MemPlumber/libmemplumber.a: 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/build.make
3rdParty/MemPlumber/MemPlumber/libmemplumber.a: 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libmemplumber.a"
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber && $(CMAKE_COMMAND) -P CMakeFiles/memplumber.dir/cmake_clean_target.cmake
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/memplumber.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/build: 3rdParty/MemPlumber/MemPlumber/libmemplumber.a

.PHONY : 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/build

3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/clean:
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber && $(CMAKE_COMMAND) -P CMakeFiles/memplumber.dir/cmake_clean.cmake
.PHONY : 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/clean

3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/depend:
	cd /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09 /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09 /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : 3rdParty/MemPlumber/MemPlumber/CMakeFiles/memplumber.dir/depend

