cmake_minimum_required(VERSION 3.0)

if(NOT WIN32)
    include(ncurses)
endif()

include(libscap)
include(libsinsp)

add_subdirectory(falco_engine)

include_directories(
    "${LIBSINSP_INCLUDE_DIRS}"
    "./falco_engine"
)

set(SOURCE_FILES
    falcon_behavior_engine.cpp
)

set(CREATE_PATTERN_SOURCE_FILES
    create_pattern.cpp
)

add_executable(falcon_behavior_engine ${SOURCE_FILES})
add_executable(create_pattern ${CREATE_PATTERN_SOURCE_FILES})

if(USE_BUNDLED_DEPS)
    add_dependencies(falcon_behavior_engine njson)
    add_dependencies(falcon_behavior_engine yaml-cpp)
    add_dependencies(create_pattern zlib)
endif()

target_include_directories(
    falcon_behavior_engine
    PUBLIC
    ${LIBSCAP_INCLUDE_DIRS}
    ${LIBSINSP_INCLUDE_DIRS}
    ${YAMLCPP_INCLUDE_DIR}
    ${NJSON_INCLUDE_DIR}
)

set(ZLIB_LIB ${ZLIB_INCLUDE}/libz.a)
target_include_directories(
    create_pattern
    PUBLIC
    ${ZLIB_INCLUDE}
)

if(NOT WIN32)
    include_directories(${PROJECT_BINARY_DIR}/driver/src)

    target_link_libraries(falcon_behavior_engine
        falco_engine
        sinsp
        ${YAMLCPP_LIB}
    )

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

    target_link_libraries(create_pattern
        ${JSONCPP_LIB}
        ${ZLIB_LIB}
    )

    install(TARGETS falcon_behavior_engine
        DESTINATION bin COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

else()
    include(luajit)

    target_link_libraries(falcon_behavior_engine
        falco_engine
        sinsp
        "${YAMLCPP_LIB}"
    )

    target_link_libraries(falcon_behavior_engine
        odbc32.lib
        odbccp32.lib
        Netapi32.lib
        Iphlpapi.lib
    )

    add_custom_command(TARGET falcon_behavior_engine POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${LUAJIT_SRC}/lua51.dll"
            "${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll"
    )

    add_custom_command(TARGET falcon_behavior_engine POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            $<TARGET_FILE:falcon_behavior_engine>
            "${PROJECT_BINARY_DIR}/$(Configuration)/falcon_behavior_engine.exe"
    )

    install(TARGETS falcon_behavior_engine
        DESTINATION programs
        COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

    install(FILES "${LUAJIT_SRC}/lua51.dll"
        DESTINATION programs
        COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

endif()
