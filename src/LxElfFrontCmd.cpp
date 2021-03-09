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

/* $Rev: 56283 $ */

// Class that implements the command for moving program and section headers
// to the front of an elf file.

#include "LxElfFrontCmd.h"
#include "LxElfFile.h"
#include "unicode_output.h"

#include "LxOutput.h"           // last include

using namespace std;

using unicode_output::ucout;

LxElfFrontCmd::
LxElfFrontCmd()
{
}


void LxElfFrontCmd::
Execute(LxElfFile & elfFile, bool verbose)
{
  if (verbose)
    ucout << "Moving program and section headers to the front" << endl;

  elfFile.MoveHeadersToFront();
}
