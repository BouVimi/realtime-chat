cmake_minimum_required(VERSION 3.20)
project(chat_backend VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Drogon CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_path(SODIUM_INCLUDE_DIR sodium.h REQUIRED)
find_library(SODIUM_LIBRARY sodium REQUIRED)
add_library(Sodium::Sodium UNKNOWN IMPORTED)
set_target_properties(Sodium::Sodium PROPERTIES
    IMPORTED_LOCATION "${SODIUM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")

add_library(chat_config config/Config.cc config/AuthConfig.cc)
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

add_library(chat_auth
    services/AuthPolicy.cc services/AuthService.cc
    utils/AuthCrypto.cc utils/AuthHttp.cc)
target_include_directories(chat_auth PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(chat_auth PUBLIC chat_config chat_validators chat_repositories Sodium::Sodium Threads::Threads)
target_compile_options(chat_auth PRIVATE -Wall -Wextra -Wpedantic)

add_executable(chat_backend main.cc controllers/HealthController.cc
    controllers/AuthController.cc filters/AuthFilter.cc
    services/HealthService.cc repositories/HealthRepository.cc)
target_link_libraries(chat_backend PRIVATE chat_config chat_validators chat_repositories chat_auth)
target_compile_options(chat_backend PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
    add_executable(config_tests tests/ConfigTest.cc)
    target_link_libraries(config_tests PRIVATE chat_config)
    add_test(NAME config_tests COMMAND config_tests ${CMAKE_CURRENT_SOURCE_DIR}/config/config.json)

    add_executable(validator_tests tests/ValidatorTest.cc)
    target_link_libraries(validator_tests PRIVATE chat_validators)
    add_test(NAME validator_tests COMMAND validator_tests)

    add_executable(auth_tests tests/AuthTest.cc)
    target_link_libraries(auth_tests PRIVATE chat_auth)
    add_test(NAME auth_tests COMMAND auth_tests)
    set_tests_properties(auth_tests PROPERTIES TIMEOUT 30)

    add_executable(auth_http_tests tests/AuthHttpTest.cc)
    target_link_libraries(auth_http_tests PRIVATE chat_auth)
    add_test(NAME auth_http_tests COMMAND auth_http_tests)
    set_tests_properties(auth_http_tests PROPERTIES TIMEOUT 10)

    add_executable(repository_tests tests/RepositoryTest.cc)
    target_link_libraries(repository_tests PRIVATE chat_repositories chat_config)
    add_test(NAME repository_tests COMMAND repository_tests ${CMAKE_CURRENT_SOURCE_DIR}/config/config.json)
    set_tests_properties(repository_tests PROPERTIES
        SKIP_RETURN_CODE 77 LABELS integration TIMEOUT 60 RUN_SERIAL TRUE)
endif()
