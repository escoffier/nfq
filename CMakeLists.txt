cmake_minimum_required (VERSION 3.10.2)
project(nfq)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCES
    packet.h
    tcp.c
    main.cpp
)

add_executable(nfq ${SOURCES})

# target_include_directories(nfq PRIVATE )
target_link_libraries(nfq -lnetfilter_queue -lpthread -lnfnetlink)
