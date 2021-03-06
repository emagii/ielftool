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

// Class that encapsulates a data buffer used for section data

#ifndef LX_ELF_DATABUFFER_H
#define LX_ELF_DATABUFFER_H

#include "LxElfTypes.h"

#include <fstream>
#include <stddef.h>


class LxElfDataBuffer
{
public:
  LxElfDataBuffer();
  LxElfDataBuffer(bool elfBigEndian);
  LxElfDataBuffer(Elf64_Off bufSize, bool elfBigEndian);
  LxElfDataBuffer(LxElfDataBuffer const & x);
  LxElfDataBuffer & operator = (LxElfDataBuffer const & x);
  ~LxElfDataBuffer();
  void swap(LxElfDataBuffer & x);

  // This buffer is just a window into another.
  void SetWindow(LxElfDataBuffer & base, Elf64_Off offset, Elf64_Off size);

  void Allocate(Elf64_Off bufSize);
  void Expand  (Elf64_Off expSize);
  void Shrink  (Elf64_Off delta);

  void SetEndian(bool bigEndian) {mElfBigEndian = bigEndian;};
  bool IsBigEndian() const {return mElfBigEndian;};

  typedef uint8_t const * const_iterator;
  typedef uint8_t       * iterator;

  const_iterator begin() const;
  iterator       begin();
  const_iterator end  () const;
  iterator       end  ();

  uint64_t GetBufLen() const {return mBufSize;};

  bool IsOwner() const;

private:

  void Reset();

  /* One of two cases:
     If mOffset is -1, we own a buffer
     If mOffset is anything else, we are just a window into a buffer
     owned by someone else. */
  uint64_t mOffset;
  union
  {
    uint8_t * mOwnedBuf;
    LxElfDataBuffer * mBase;
  };

  // Size of the buffer
  uint64_t  mBufSize;

  // True if the buffer uses big endian data order
  bool mElfBigEndian;
};

bool LxLoad(LxElfDataBuffer & buf,
            std::istream & inFile,
            Elf64_Off offset,
            Elf64_Off length);
bool LxSave(LxElfDataBuffer const & buf,
            std::ostream & outFile,
            std::streamsize offs = 0);

class LxElfReader
{
public:
  LxElfReader(LxElfDataBuffer const & buf, Elf64_Off off = 0)
    : mBuf(&buf), mOffset(off), mEnd(buf.GetBufLen())
  {
  }
  LxElfReader(LxElfDataBuffer const & buf, Elf64_Off off, Elf64_Off end)
    : mBuf(&buf), mOffset(off), mEnd(end)
  {
  }

  bool AtEnd() const;

  uint64_t        GetDoubleWord();

  Elf32_Off       GetOff  ();
  Elf32_Addr      GetAddr ();
  Elf32_Word      GetWord ();
  Elf32_Sword     GetSword();
  Elf32_Half      GetHalf ();
  uint8_t         GetByte ();

  uint8_t const * Ptr();

private:
  LxElfDataBuffer const * mBuf;
  Elf64_Off mOffset;
  Elf64_Off mEnd;
};

class LxElfWriter
{
public:
  LxElfWriter(LxElfDataBuffer & buf, Elf64_Off off = 0)
    : mBuf(&buf), mOffset(off)
  {
  }

  void PutDoubleWord(uint64_t x);
  void PutOff (Elf32_Off  x);
  void PutAddr(Elf32_Addr x);
  void PutWord(Elf32_Word x);
  void PutHalf(Elf32_Half x);
  void PutByte(uint8_t    x);

  void Put(LxElfDataBuffer const & x);

private:
  LxElfDataBuffer * mBuf;
  Elf64_Off mOffset;
};

void Fill(LxElfDataBuffer &   buf,
          FillPattern const & pattern,
          Elf64_Off           patOffset);

#endif  // LX_ELF_DATABUFFER_H
