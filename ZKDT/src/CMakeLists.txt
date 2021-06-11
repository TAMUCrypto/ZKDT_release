include_directories(.)

add_executable(
  dt_path
        dt_path.cpp
)
target_link_libraries(
  dt_path
        snark
)
target_include_directories(
  dt_path
        PUBLIC
        include
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_executable(
        dt_batch
        dt_batch.cpp
)
target_link_libraries(
        dt_batch
        snark
)
target_include_directories(
        dt_batch
        PUBLIC
        include
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mavx2 -faligned-new -lstdc++ -O3 -DNDEBUG")
