#pragma once
#include "StringConversion.h"

#include <atlbase.h> 
#include <atlconv.h>
#include <sstream>

namespace StringConversion
{
	const char* ToAscii(const wchar_t* str, char* buf, size_t bufsize);
	const wchar_t* ToUtf16(const char* str, wchar_t* buf, size_t bufsize);
	uint64_t hex2dec(std::string hex);
};
