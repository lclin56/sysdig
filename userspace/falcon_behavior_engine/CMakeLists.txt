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
    fbeng.cpp
    ifbeng.cpp
    logcxx.cpp
    main.cpp
)

set(CREATE_PATTERN_SOURCE_FILES
    create_pattern.cpp
)

add_executable(fbeng ${SOURCE_FILES})
add_library(libfbeng SHARED ${SOURCE_FILES})
add_executable(create_pattern ${CREATE_PATTERN_SOURCE_FILES})

if(USE_BUNDLED_DEPS)
    add_dependencies(fbeng njson yaml-cpp)
    add_dependencies(libfbeng njson yaml-cpp)
    add_dependencies(create_pattern zlib)
endif()

target_include_directories(
    fbeng
    PUBLIC
    ${LIBSCAP_INCLUDE_DIRS}
    ${LIBSINSP_INCLUDE_DIRS}
    ${YAMLCPP_INCLUDE_DIR}
    ${NJSON_INCLUDE_DIR}
)

target_include_directories(
    libfbeng
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

    target_link_libraries(fbeng
        falco_engine
        sinsp
        ${YAMLCPP_LIB}
    )

    # target_link_options(fbeng PRIVATE 
    #     -static)

    target_link_libraries(libfbeng
        falco_engine
        sinsp
        ${YAMLCPP_LIB}
        -static-libgcc
        -static-libstdc++
    )

    set_target_properties(libfbeng PROPERTIES 
        OUTPUT_NAME "fbeng")
    
    # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

    # target_link_options(libfbeng PRIVATE 
    #     -static)

    target_link_libraries(create_pattern
        ${JSONCPP_LIB}
        ${ZLIB_LIB}
    )

    install(TARGETS fbeng
        DESTINATION bin 
        COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

    install(TARGETS libfbeng
        LIBRARY DESTINATION lib
        COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

else()
    include(luajit)

    target_link_libraries(fbeng
        falco_engine
        sinsp
        "${YAMLCPP_LIB}"
        odbc32.lib
        odbccp32.lib
        Netapi32.lib
        Iphlpapi.lib
    )

    target_link_libraries(libfbeng
        falco_engine
        sinsp
        "${YAMLCPP_LIB}"
        odbc32.lib
        odbccp32.lib
        Netapi32.lib
        Iphlpapi.lib
    )

    add_custom_command(TARGET fbeng POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${LUAJIT_SRC}/lua51.dll"
            "${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll"
    )

    add_custom_command(TARGET fbeng POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            $<TARGET_FILE:fbeng>
            "${PROJECT_BINARY_DIR}/$(Configuration)/fbeng.exe"
    )

    install(TARGETS fbeng
        DESTINATION programs
        COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

    install(TARGETS libfbeng
    LIBRARY DESTINATION lib
    COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

    install(FILES "${LUAJIT_SRC}/lua51.dll"
        DESTINATION programs
        COMPONENT "${SYSDIG_COMPONENT_NAME}"
    )

endif()
