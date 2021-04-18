cmake_minimum_required(VERSION 3.17)
project(panda)

set(CMAKE_CXX_STANDARD 20)

add_library(panda SHARED src/library.cpp src/library.h src/hooks.hpp src/hooks.cpp src/logger.hpp src/logger.cpp src/msv.hpp)

get_filename_component(PLH_DIR "F:\\PolyHook_2_0" ABSOLUTE)

message(STATUS ${PLH_DIR})

include_directories(${PLH_DIR})

target_compile_options(${PROJECT_NAME} PRIVATE /std:c++latest)

#Link the capstone lib according to config mode
target_link_libraries(${PROJECT_NAME} ${PLH_DIR}\\_install\\lib\\capstone.lib)
target_link_libraries(${PROJECT_NAME} ${PLH_DIR}\\_install\\lib\\PolyHook_2.lib)

# include capstone headers
target_include_directories(${PROJECT_NAME} PUBLIC ${PLH_DIR}\\_install\\include)