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

# Include any dependencies generated for this target.
include depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o: ../depends/libsnark/libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o"
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o -c /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/depends/libsnark/libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.i"
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/depends/libsnark/libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp > CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.i

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.s"
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/depends/libsnark/libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp -o CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.s

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.requires:

.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.requires

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.provides: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.requires
	$(MAKE) -f depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/build.make depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.provides.build
.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.provides

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.provides.build: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o


# Object files for target demo_r1cs_ppzkadsnark
demo_r1cs_ppzkadsnark_OBJECTS = \
"CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o"

# External object files for target demo_r1cs_ppzkadsnark
demo_r1cs_ppzkadsnark_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/build.make
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/libsnark/libsnark_adsnark.a
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/depends/libsnark_supercop.a
depends/libsnark/libsnark/demo_r1cs_ppzkadsnark: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable demo_r1cs_ppzkadsnark"
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/demo_r1cs_ppzkadsnark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/build: depends/libsnark/libsnark/demo_r1cs_ppzkadsnark

.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/build

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/requires: depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/demo_r1cs_ppzkadsnark.cpp.o.requires

.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/requires

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/clean:
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/demo_r1cs_ppzkadsnark.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/clean

depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/depend:
	cd /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/depends/libsnark/libsnark /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark /home/zhiyong/Desktop/Cryptography/Research/projects/ZKDT_release/ZKDT/build/depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/demo_r1cs_ppzkadsnark.dir/depend

