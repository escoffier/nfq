cmake_minimum_required (VERSION 3.10.2)
project(nfq)

add_executable(nfq main.cpp)
target_link_libraries(nfq -lnetfilter_queue -lpthread -lnfnetlink)
