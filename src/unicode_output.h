//----------------------------------------------------------------------
// unicode_output.h
//----------------------------------------------------------------------
// Copyright 2016-2017 IAR Systems AB.
//----------------------------------------------------------------------

#ifndef UNICODE_OUTPUT_H
#define UNICODE_OUTPUT_H

#include <ostream>
#include <string>

namespace unicode_output
{
#ifdef _WIN32
typedef std::wostream uostream;
extern std::wostream &ucout;
extern std::wostream &ucerr;
extern std::wstring ustring(std::string str);

#else
typedef std::ostream uostream;
extern std::ostream &ucout;
extern std::ostream &ucerr;
extern std::string ustring(std::string str);
#endif

#ifdef _WIN32
std::string utf16_to_utf8(const std::wstring &str);
std::wstring utf8_to_utf16(const std::string &str, bool replace = true);

bool setup();
#endif
}

#endif // UNICODE_OUTPUT_H
