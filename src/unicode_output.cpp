///////////////////////////////// -*- C++ -*- /////////////////////////////////
//----------------------------------------------------------------------
// unicode_output.cpp
//----------------------------------------------------------------------
// Copyright 2016-2017 IAR Systems AB.
//----------------------------------------------------------------------

#include "unicode_output.h"

#include <iostream>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

using std::string;

//----------------------------------------------------------------------

#ifdef _WIN32
std::wostream &unicode_output::ucout = std::wcout;
std::wostream &unicode_output::ucerr = std::wcerr;
#else
std::ostream &unicode_output::ucout = std::cout;
std::ostream &unicode_output::ucerr = std::cerr;
#endif

//----------------------------------------------------------------------

#ifdef _WIN32

std::wstring unicode_output::ustring(std::string str)
{
  return utf8_to_utf16(str);
}

#else

std::string unicode_output::ustring(std::string str) { return str; }

#endif

//----------------------------------------------------------------------

#ifdef _WIN32

string unicode_output::utf16_to_utf8(const std::wstring &str)
{
  if (str.empty())
    return "";
  int nbytes = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, NULL,
                                   0, // ask for nbytes
                                   NULL, NULL);
  if (nbytes == 0)
  {
    throw "Fatal error: WideCharToMultiByte";
  }
  char *buff = new char[nbytes];
  int nbytes2 = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, buff, nbytes,
                                    NULL, NULL);
  if (nbytes2 == 0)
  {
    throw "Fatal error: WideCharToMultiByte";
  }
  string res = buff;
  delete[] buff;
  return res;
}

//----------------------------------------------------------------------

std::wstring unicode_output::utf8_to_utf16(const string &str, bool replace)
{
  if (str.empty())
    return L"";
  DWORD dwFlags = replace ? 0 : MB_ERR_INVALID_CHARS;
  int nwords = MultiByteToWideChar(CP_UTF8, dwFlags, str.c_str(),
                                   -1, NULL, 0);
  if (nwords == 0)
  {
    throw "Fatal error: MultiByteToWideChar";
  }
  wchar_t *buff = new wchar_t[nwords];
  int nwords2 = MultiByteToWideChar(CP_UTF8, dwFlags, str.c_str(),
                                    -1, buff, nwords);
  if (nwords == 0)
  {
    throw "Fatal error: MultiByteToWideChar";
  }
  std::wstring res = buff;
  delete[] buff;
  return res;
}

//----------------------------------------------------------------------

bool unicode_output::setup()
{
  int res = _setmode(1, _O_U8TEXT);
  if (res == -1)
    return false;

  res = _setmode(2, _O_U8TEXT);
  if (res == -1)
    return false;

  return true;
}

#endif
