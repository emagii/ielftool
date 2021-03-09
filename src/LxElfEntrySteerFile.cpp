///////////////////////////////// -*- C++ -*- /////////////////////////////////
/*
 * Copyright 2007-2017 IAR Systems AB.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Rev: 21495 $ */

// Class that implements the command for stripping an elf file

#include "LxElfEntrySteerFile.h"
#include "LxElfException.h"
#include "LxElfFile.h"
#include "unicode_output.h"

#include <fstream>
#include <sstream>

#include "LxOutput.h"           // last include

using namespace std;

using unicode_output::ucout;

LxElfEntrySteerFileCmd::
LxElfEntrySteerFileCmd(const std::string & fileName)
  : mFilename(fileName)
{
}

static
Elf32_Word
GetStringIndex(LxElfSection * symScn, Elf64_Addr addr)
{
  LxElfReader ri(symScn->mData);
  Elf64_Sym   entrySym;
  while (!ri.AtEnd())
  {
    entrySym.st_name  = ri.GetWord();
    entrySym.st_value = ri.GetAddr();
    entrySym.st_size  = ri.GetWord();
    entrySym.st_info  = ri.GetByte();
    entrySym.st_other = ri.GetByte();
    entrySym.st_shndx = ri.GetHalf();
    // if the address matches AND the symbol is global, accept it
    if (   (entrySym.st_value == addr)
        && (entrySym.st_info >> 4) == STB_GLOBAL)
    {
      return entrySym.st_name;
    }
  }
  // the symbol's address did not exist, convert the address to a string
  // and report the missing symbol
  std::ostringstream os;
  os << std::hex << addr;
  throw LxSymbolException(os.str(), LxSymbolException::kSymbolAddressNotFound);
}

static
std::string
GenerateIsfName(std::string fileName)
{
  string newName = fileName;
  size_t i = fileName.length();
  if (i)
  {
    i -= 1;
    while (i && newName[i] != '.')
      --i;
    if (i)
      newName = fileName.substr(0,i+1);
  }
  return newName + "isf";
}

void LxElfEntrySteerFileCmd::
Execute(LxElfFile & elfFile, bool verbose)
{
  if (verbose)
    ucout << "Generating entry steer file" << endl;

  // extract program entry address
  Elf64_Addr entryAddr = elfFile.GetEntryAddr();
  if (verbose)
    ucout << "Program entry found at address: 0x" << std::hex << entryAddr << endl;

  // locate matching symbol
  LxElfSection * symScn     = elfFile.GetSymbolSection();
  Elf32_Word     entryIndex = GetStringIndex(symScn, entryAddr);
  string         entryName  = elfFile.GetString(entryIndex, symScn->mHdr.sh_link);
  if (verbose)
    ucout << "The entry " << entryName.c_str() << ", that resides at 0x"
         << std::hex << entryAddr << ", chosen as redirect target\n";

  // output steering file
  string isfFilename = GenerateIsfName(mFilename);
  if (verbose)
    ucout << "Steer file name is \"" << isfFilename.c_str() << "\"\n";
  ofstream outFile(isfFilename.c_str(), ios::binary);
  outFile << "rename " << entryName << " as " << entryName << "_slave\n";
  outFile << "show " << entryName << "_slave";
  outFile << endl;
}
