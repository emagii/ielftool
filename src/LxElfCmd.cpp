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

#include "LxElfCmd.h"
#include "LxElfException.h"

LxElfCmdOffset::
LxElfCmdOffset()
  : mOffset(0), mIsNegative(false)
{}

LxElfCmdOffset::
LxElfCmdOffset(uint64_t offs)
  : mOffset(offs), mIsNegative(false)
{}

LxElfCmdOffset::
LxElfCmdOffset(int64_t offs)
  : mOffset(offs >= 0 ? offs : 0-offs), mIsNegative(offs >= 0 ? false : true)
{}

void LxElfCmdOffset::
SetOffset(uint64_t offs)
{
  mOffset     = offs;
  mIsNegative = false;
}

void LxElfCmdOffset::
SetNegativeOffset(uint64_t offs)
{
  mOffset     = offs;
  mIsNegative = true;
}

template<typename T>
uint64_t LxElfCmdOffset::
ModifyX(uint64_t addr64) const
{
  T addr = static_cast<T>(addr64);
  T tmp;
  if (mIsNegative)
  {
    tmp = static_cast<T>(addr - mOffset);
    if (tmp > addr)
      // wrap around
      throw LxOffsetException(addr, mOffset, mIsNegative);
  }
  else
  {
    tmp = static_cast<T>(addr + mOffset);
    if (tmp < addr)
      // wrap around
      throw LxOffsetException(addr, mOffset, mIsNegative);
  }
  return tmp;
}

uint64_t LxElfCmdOffset::
Modify(uint64_t addr, bool is64bit) const
{
  if (is64bit)
    return ModifyX<uint64_t>(addr);
  else
    return ModifyX<uint32_t>(static_cast<uint32_t>(addr));
}

uint64_t LxElfCmdOffset::
GetOffset() const
{
  return mOffset;
}

bool LxElfCmdOffset::
IsNegative() const
{
  return mIsNegative;
}

uint32_t
LxCheck32(uint64_t x)
{
  uint32_t res = static_cast<uint32_t>(x);
  if (res != x)
    throw LxSaveException();
  return res;
}