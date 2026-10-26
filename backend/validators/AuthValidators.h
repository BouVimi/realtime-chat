#pragma once
#include "dto/AuthDto.h"
#include <string>
#include <string_view>
#include <vector>

namespace chat::validation {
struct ValidationResult {
    bool valid{true};
    std::vector<dto::FieldError> errors;
    // Email: trimmed/lowercase. Username: unchanged. Password: always empty.
    std::string normalized;
};
ValidationResult validateEmail(std::string_view input);
ValidationResult validateUsername(std::string_view input);
ValidationResult validatePassword(std::string_view password,
                                  std::string_view username,
                                  std::string_view email);
dto::ValidationErrorResponse toErrorResponse(const ValidationResult &result);
}
