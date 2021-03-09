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

/* $Rev: 57699 $ */

// Class that implements the command for saving as binary

#include "LxElfSaveCmdBase.h"
#include "LxElfFile.h"
#include "unicode_output.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "LxOutput.h"           // last include

using unicode_output::ucout;

LxElfSaveCmdBase::
LxElfSaveCmdBase(std::string const & filename,
                 std::string const & kind,
                 std::ios_base::openmode mode)
  : mFilename(filename), mKind(kind), mMode(mode)
{
}


void LxElfSaveCmdBase::
Execute(LxElfFile & file, bool verbose)
{
  if (verbose)
  {
    ucout << "Saving " << mKind.c_str() << " file to "
               << LxFixFilename(mFilename).c_str() << std::endl;
  }

  std::ofstream outFile(LxFixFilename(mFilename).c_str(), mMode);
  if (!outFile)
    throw std::runtime_error("Could not open " + mFilename + " for output");

  Save(file, verbose, outFile);

  if (!outFile)
    throw std::runtime_error("Problem writing to " + mFilename);
}


namespace
{
  bool SegAddrLess(LxElfSegment const * x, LxElfSegment const * y)
  {
    return x->mHdr.p_paddr < y->mHdr.p_paddr;
  }

  typedef LxElfConstSegments::const_iterator SIter;
}

static
void
GetAddresses(SIter i, SIter n, Elf64_Addr & current, Elf64_Addr & next)
{
  // current physical address
  current = (*i)->mHdr.p_paddr;
  // next segment
  SIter j = i+1;

  if (j == n || (*j)->mHdr.p_memsz == 0)
	// no next element, or an empty one
    next = current - 1;
  else
	// non empty next element, use it
    next = (*j)->mHdr.p_paddr;
}

void LxElfSaveCmdBase::
Save(LxElfFile const & file,
     bool verbose,
     std::ostream & o)
{
  LxElfConstSegments segs = file.GetLoadSegments();

  DumpHeader(file, o);

  bool cont = false;
  for (SIter i = segs.begin(), n = segs.end(); i != n; ++i)
  {
    Elf64_Addr currentAddr, nextAddr;
    GetAddresses(i, n, currentAddr, nextAddr);
    cont = DumpData(file, currentAddr, nextAddr, (*i)->mData, verbose, cont, o);
  }
  DumpFooter(file, o);
}
