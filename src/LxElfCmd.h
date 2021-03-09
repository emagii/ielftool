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

// Base class used for transforming an elf file

#ifndef LX_ELF_CMD
#define LX_ELF_CMD

#include "LxElfFile.h"
#include "LxElfTypes.h"

class LxElfCmdOffset
{
public:
  // ctors
  LxElfCmdOffset();
  LxElfCmdOffset(uint64_t offs);
  LxElfCmdOffset(int64_t  offs);

  // Set a signed or unsigned offset
  void SetOffset(uint64_t offs);
  void SetNegativeOffset(uint64_t  offs);

  // Get the result of modifying an address, this will throw if the
  // new addresses would require 33+ bits or if it would become
  // negative
  uint64_t Modify(uint64_t addr, bool is64bit) const;

  // selectors for the members
  uint64_t GetOffset()  const;
  bool     IsNegative() const;

private:
  template<typename T> uint64_t ModifyX(uint64_t addr) const;

  uint64_t    mOffset;
  bool        mIsNegative;
};

// Throws if the value does not fit in 32 bits
uint32_t LxCheck32(uint64_t x);

class LxElfCmd
{
public:
  virtual ~LxElfCmd() { }

  // To signal an error, a command can throw either an LxElfError
  // or a std::exception object.
  virtual void Execute(LxElfFile & file, bool verbose) = 0;
};

#endif // LX_ELF_CMD
