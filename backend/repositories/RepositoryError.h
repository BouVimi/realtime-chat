#pragma once
#include <stdexcept>
namespace chat {
// Infrastructure failures stay distinct from not-found and expected conflicts.
// Never pass underlying DB exception messages to clients or logs.
class RepositoryError : public std::runtime_error {
public:
    RepositoryError() : std::runtime_error("Database operation failed") {}
};
}
