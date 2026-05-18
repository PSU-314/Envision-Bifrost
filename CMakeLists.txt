cmake_minimum_required(VERSION 3.10)
project(Bifrost)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 3. Find Dependencies
# Finds OpenSSL on Arch Linux (provided by libssl-dev/openssl)
find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

# Fetch CPR (C++ Requests)
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 1.10.5 # Or stable release of your choice
)
# Disable CPR's internal tests and PDF generation to keep build times fast
set(CPR_BUILD_TESTS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(cpr)    

file (GLOB SOURCES "src/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto cpr::cpr nlohmann_json::nlohmann_json)

