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

/* $Rev: 58215 $ */

// Class that implements the command for saving as binary

#include "LxElfSaveBinCmd.h"
#include "LxElfException.h"
#include "LxElfFile.h"
#include "unicode_output.h"

#include <algorithm>
#include <sstream>

#include "LxOutput.h"           // last include

using namespace std;

using unicode_output::ucout;
using unicode_output::ucerr;

LxElfSaveBinCmd::LxElfSaveBinCmd(string const & fileName,
                                 bool multipleFiles,
                                 LxSymbolicRanges const & ranges)
  : mFileName(fileName),
    mMultipleFiles(multipleFiles),
    mRanges(ranges)
{
}


void
LxElfSaveBinCmd::Execute(LxElfFile & elfFile, bool verbose)
{
  if (verbose && !mMultipleFiles)
  {
    ucout << "Saving binary file to " << LxFixFilename(mFileName).c_str()
          << endl;
  }

  Save(elfFile, verbose);
}

static
std::string
AddHexAddress(std::string const & str, Elf64_Addr addr)
{
  size_t p = str.rfind('.');
  std::string str1 = str.substr(0, p);
  std::string str2;
  if (p != std::string::npos)
    str2 = str.substr(p);
  std::ostringstream os;
  os << str1 << "-0x" << std::hex << addr << str2;
  return os.str();
}

void
LxElfSaveBinCmd::Save(LxElfFile const & elfFile,
                      bool              verbose) const
{
  LxElfConstSegments segs = elfFile.GetLoadSegments();

  LxAddressRanges aRanges = LxGetAddressRanges(mRanges, elfFile);
  std::stable_sort(aRanges.begin(), aRanges.end(), LxRangeSort());
  if (LxRangesOverlap(aRanges))
    throw std::runtime_error("Bin ranges overlap!");

  typedef LxAddressRanges::const_iterator RIter;
  RIter ri = aRanges.begin();
  RIter rn = aRanges.end();
  bool anyRange = ri != rn;

  ofstream outFile;

  const Elf64_Addr kNoAddress = static_cast<Elf64_Addr>(-1);
  Elf64_Addr lastAddr = kNoAddress;
  typedef LxElfConstSegments::const_iterator SIter;
  for (SIter p = segs.begin(), q = segs.end(); p != q;)
  {
    // skip segments without bytes
    if (!(*p)->mHdr.p_filesz)
    {
      ++p;
      continue;
    }
    Elf64_Addr currAddr = (*p)->mHdr.p_paddr;

    // Skip ranges that end before currAddr
    while (ri != rn && ri->GetEnd() < currAddr)
    {
      ++ri;
    }

    // If no overlap with lowest range, get next segment
    if (   anyRange
        && (ri == rn || currAddr + (*p)->mHdr.p_filesz < ri->GetStart()))
    {
      ++p;
      continue;
    }

    if (anyRange && ri->GetStart() >= currAddr)
    {
      currAddr = ri->GetStart();
      outFile.close(); // Force new file
    }
    else if (mMultipleFiles && !anyRange)
      outFile.close();

    if (!outFile.is_open())
    {
      Elf64_Addr addr = anyRange ? ri->GetStart() : currAddr;
      if (!mMultipleFiles)
        outFile.open(LxFixFilename(mFileName).c_str(), ios::binary);
      else
      {
        auto fileName(LxFixFilename(AddHexAddress(mFileName, addr)));
        if (verbose)
          ucout << "Saving binary file to " << fileName.c_str() << endl;
        outFile.open(fileName.c_str(), ios::binary);
      }
      lastAddr = addr - 1;
    }
    PadFile(outFile, (currAddr - lastAddr) - 1);

    size_t offs = static_cast<size_t>(currAddr - (*p)->mHdr.p_paddr);
    size_t end = static_cast<size_t>((*p)->mHdr.p_filesz);
    if (anyRange)
    {
      size_t lim = static_cast<size_t>(ri->GetEnd() + 1 - (*p)->mHdr.p_paddr);
      if (lim < end)
        end = lim;
    }

    typedef LxElfDataBuffer::const_iterator Iter;
    for (Iter i = (*p)->mData.begin() + offs, n = (*p)->mData.begin() + end;
         i != n;
         ++i)
    {
      outFile << *i;
    }

    lastAddr = currAddr + end - offs - 1;
    if (!anyRange || ri->GetEnd() >= lastAddr + 1)
      ++p;
    else
    {
      ++ri;
      if (anyRange)
        outFile.close();
    }
  }
}

void
LxElfSaveBinCmd::PadFile(std::ofstream & outFile, Elf64_Word len) const
{
  for (Elf64_Word i = 0; i < len; i++)
  {
    outFile << '\0';
  }
}
