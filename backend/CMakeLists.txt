cmake_minimum_required(VERSION 3.20)
project(chat_backend VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Drogon CONFIG REQUIRED)

add_library(chat_config config/Config.cc)
target_include_directories(chat_config PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(chat_config PUBLIC Drogon::Drogon)

# Validators have no framework or database dependency.
add_library(chat_validators validators/AuthValidators.cc)
target_include_directories(chat_validators PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(chat_validators PRIVATE -Wall -Wextra -Wpedantic)

add_library(chat_repositories
    repositories/UserRepository.cc
    repositories/SessionRepository.cc)
target_include_directories(chat_repositories PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(chat_repositories PUBLIC Drogon::Drogon)
target_compile_options(chat_repositories PRIVATE -Wall -Wextra -Wpedantic)

add_executable(chat_backend main.cc controllers/HealthController.cc
    services/HealthService.cc repositories/HealthRepository.cc)
target_link_libraries(chat_backend PRIVATE chat_config chat_validators chat_repositories)
target_compile_options(chat_backend PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
    add_executable(config_tests tests/ConfigTest.cc)
    target_link_libraries(config_tests PRIVATE chat_config)
    add_test(NAME config_tests COMMAND config_tests ${CMAKE_CURRENT_SOURCE_DIR}/config/config.json)

    add_executable(validator_tests tests/ValidatorTest.cc)
    target_link_libraries(validator_tests PRIVATE chat_validators)
    add_test(NAME validator_tests COMMAND validator_tests)

    add_executable(repository_tests tests/RepositoryTest.cc)
    target_link_libraries(repository_tests PRIVATE chat_repositories chat_config)
    add_test(NAME repository_tests COMMAND repository_tests ${CMAKE_CURRENT_SOURCE_DIR}/config/config.json)
    set_tests_properties(repository_tests PROPERTIES
        SKIP_RETURN_CODE 77 LABELS integration TIMEOUT 60 RUN_SERIAL TRUE)
endif()