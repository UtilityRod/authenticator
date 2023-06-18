project(authenticator)
cmake_minimum_required(VERSION 3.10)

add_subdirectory(deps)

set(
    SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/authenticator_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/password_file.c
)

add_executable(authenticator_main ${SOURCES})
target_compile_options(authenticator_main PUBLIC "-g")
target_link_libraries(authenticator_main PUBLIC networking_shared eloop_static)