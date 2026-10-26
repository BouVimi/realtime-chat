#pragma once
#include <json/json.h>
#include <string>
namespace chat { Json::Value loadConfig(const std::string &path); }
