# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

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
CMAKE_SOURCE_DIR = /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build

# Utility rule file for ContinuousTest.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/ContinuousTest:
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && /usr/bin/ctest -D ContinuousTest

ContinuousTest: depends/libsnark/libsnark/CMakeFiles/ContinuousTest
ContinuousTest: depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/build.make

.PHONY : ContinuousTest

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/build: ContinuousTest

.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/build

depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/clean:
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousTest.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/clean

depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/depend:
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/depends/libsnark/libsnark /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousTest.dir/depend

