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

/* $Rev: 59129 $ */

// This class implements low-level elf file handling

#ifndef ELFFILE_H
#define ELFFILE_H

#include "LxElfTypes.h"
#include "LxElfDataBuffer.h"
#include <vector>
#include <string>

// Utility
#ifdef _WIN32
std::wstring LxFixFilename(std::string const & x);
#else // !_WIN32
#define LxFixFilename(x) (x)
#endif // _WIN32

class LxElfSegment
{
public:
LxElfSegment(Elf64_Phdr const & segHdr, bool elfBigEndian, bool is_virtual = false) :
  mHdr(segHdr), mData(elfBigEndian), mVirtual(is_virtual) {};

  bool IsVirtual() const
  {
    return mVirtual;
  }

  bool IsLoad() const
  {
    return mHdr.p_type == PT_LOAD;
  }

  LxAddressRange GetRange() const
  {
    return LxAddressRange(mHdr.p_vaddr, mHdr.p_vaddr + mHdr.p_filesz - 1);
  }

  Elf64_Phdr       mHdr;
  LxElfDataBuffer  mData;
  bool             mVirtual;
};

class LxElfSection
{
public:
  LxElfSection(Elf64_Shdr const & scnHdr, bool elfBigEndian) :
    mHdr(scnHdr), mData(elfBigEndian){};

  bool IsAlloc() const
  {
    return ((mHdr.sh_flags & SHF_ALLOC) == SHF_ALLOC);
  }

  bool IsProgBits() const
  {
    return (mHdr.sh_type == SHT_PROGBITS);
  }

  bool IsNoBits() const
  {
    return (mHdr.sh_type == SHT_NOBITS);
  }

  bool IsSymbolTable() const
  {
    return mHdr.sh_type == SHT_SYMTAB;
  }

  bool IsNull() const
  {
    return (mHdr.sh_type == SHT_NULL);
  }

  LxAddressRange GetRange() const
  {
    return LxAddressRange(mHdr.sh_addr,
                          mHdr.sh_addr + mHdr.sh_size - 1);
  }

  Elf64_Shdr       mHdr;
  LxElfDataBuffer  mData;
};

class LxElfVirtualFill;

class LxElfVirtualSegment : public LxElfSegment
{
public:
  LxElfVirtualSegment(Elf64_Phdr const & hdr, LxAddressRange const & rng,
    FillPattern const & fill)
    : LxElfSegment(hdr, /*endian*/ false, /*is_virtual*/ true),
      mRange(rng), mFill(fill)
  {
  }

  LxAddressRange      mRange;
  FillPattern         mFill;

};

// Method used for sorting elf sections by address
inline
bool
LxElfScnSortByAddr(LxElfSection const * a,
                   LxElfSection const * b)
{
  return (a->mHdr.sh_addr < b->mHdr.sh_addr);
}

inline
bool
LxElfSegmentSortByVAddr(LxElfSegment const * a,
                        LxElfSegment const * b)
{
  return (a->mHdr.p_vaddr < b->mHdr.p_vaddr);
}

inline
bool
LxElfVirtualSegmentSortByVAddr(LxElfSegment const * a,
                                LxElfSegment const * b)
{
  Elf64_Addr aAddr = a->IsVirtual() ?
    static_cast<LxElfVirtualSegment const *>(a)->mRange.GetStart() :
    a->mHdr.p_vaddr;
  Elf64_Addr bAddr = b->IsVirtual() ?
    static_cast<LxElfVirtualSegment const *>(b)->mRange.GetStart() :
    b->mHdr.p_vaddr;
  return (aAddr < bAddr);
}


class LxElfFile;

class LxElfFileObserver;

typedef std::vector<LxElfSection       *> LxElfSections;
typedef std::vector<LxElfSection const *> LxElfConstSections;
typedef std::vector<LxElfSegment       *> LxElfSegments;
typedef std::vector<LxElfSegment const *> LxElfConstSegments;
typedef std::vector<LxElfFileObserver  *> LxElfFileObservers;


class LxByteVisitor
{
public:
  virtual ~LxByteVisitor() {};

  virtual void SetVisitRange(const LxAddressRange & currentRange, bool reverse) {};
  virtual void VisitBegin() {};
  virtual void VisitByte(uint8_t b) = 0;
  virtual void VisitEnd() {};
};

class LxElfVirtualFill
{
public:
  // ctor
  LxElfVirtualFill(LxAddressRange const & range, FillPattern const & fill);
  // dtor
  ~LxElfVirtualFill();
  // cpy ctor
  LxElfVirtualFill(LxElfVirtualFill const & src);
  // assignment
  LxElfVirtualFill const & operator=(LxElfVirtualFill const & src);

  LxAddressRange const & Range() const   { return mRange; }
  FillPattern const &    Fill()  const   { return *mFill;  }
  LxElfSegment const *   Segment() const { return mSegment; }

private:
  LxAddressRange         mRange;
  FillPattern const *    mFill;
  LxElfVirtualSegment * mSegment;
};

class LxElfFile
{
public:
  // "empty" file.
  LxElfFile(bool bigEndian,
            bool is64bit,
            Elf32_Half machine,
            Elf32_Word flags,
            Elf64_Addr entry);
  // Throws LxElfError on failure.
  LxElfFile(std::string const & filename);
  ~LxElfFile();

  // Swap contents with other file
  void swap(LxElfFile & x);

  // Returns the entry address of the elf file
  Elf64_Addr GetEntryAddr() const {return mElfHdr.e_entry;};

  // Methods for accessing sections
  Elf32_Word           GetNrOfSections() const;
  LxElfSection const * GetSection(Elf32_Word idx) const;
  LxElfSection       * GetSection(Elf32_Word idx);

  // And for segments
  Elf32_Word           GetNrOfSegments() const;
  LxElfSegment const * GetSegment(Elf32_Word idx) const;
  LxElfSegment       * GetSegment(Elf32_Word idx);

  LxElfConstSegments   GetLoadSegments() const;

  Elf32_Half    GetSectionLabelsIdx() const;
  LxElfSection* GetSymbolSection() const; // Throws if no symbol section

  LxElfSection* GetSectionAtAddr(Elf64_Addr addr);

  // Gets the sections that cover the given range
  // Sections are sorted by start address
  void GetSectionsInAddrRange(LxAddressRange  range,
                              LxElfSections & scns);
  void GetSectionsInAddrRange(LxAddressRange  range,
                              LxElfConstSections & scns) const;

  void GetSegmentsInAddrRange(LxAddressRange  range,
                              LxElfConstSegments & segments) const;

  void VisitSectionRanges(LxByteVisitor & v, LxAddressRanges const & ranges);
  void VisitSegmentRanges(LxByteVisitor & v, LxAddressRanges const & ranges, bool rSign);

  // Add a load segment. If secName is not empty, adds a section as well.
  LxElfSegment * AddLoadSegment(Elf64_Word memSize,
                                Elf64_Word fileSize,
                                Elf64_Word align,
                                Elf32_Word flags,
                                Elf64_Addr addr,
                                Elf64_Off  pos,
                                std::string const & secName);

  // Add a section. The new section will get a separate part of the
  // file. If overlap with a segment is needed, use AddLoadSegment.
  LxElfSection * AddSection(std::string const & name,
                            Elf32_Word type,
                            Elf64_Word flags,
                            Elf64_Addr addr,
                            Elf64_Word size,
                            Elf32_Word link,
                            Elf32_Word info,
                            Elf64_Word align,
                            Elf64_Word entSize,
                            Elf64_Off  pos);

  void ExpandSection(LxElfSection * sec, size_t extra);

  bool RemoveSection(Elf32_Word idx);

  bool IsRemovableSection(Elf32_Half idx);

  // Methods for reading the string and symbol tables
  Elf32_Word GetStringIndex(const std::string & symbol,
                            Elf32_Word          sectionIdx) const;

  std::string GetString(Elf32_Word index, Elf32_Half strShdrIdx) const;

  std::pair<Elf64_Sym, Elf32_Word> GetSymbol(Elf32_Word   strIndex) const;

  Elf64_Addr GetSymbolAddress(std::string const & name) const;


  // Adds a string to the string table
  Elf32_Word AddStringToStringTable(std::string const & str,
                                    Elf32_Half          sectionIdx);

  void AddSymbol(const Elf64_Sym & sym);

  void MoveHeadersToFront();

  ElfHeader GetElfHeader() const;

  bool IsBigEndian() const;

  bool Is64Bit() const;

  bool HasSymbolTable() const;

  Elf32_Half GetSymTabHdrIdx() const;

  std::string GetFileName() const;

  bool IsARM() const;

  void RegisterObserver(LxElfFileObserver* o);
  void UnRegisterObserver(LxElfFileObserver* o);

  void DescribeSectionWithRange(LxElfSection const * sec,
                                std::ostream & o) const;

  typedef std::vector<LxElfSegment *> Segments;

  void AddVirtualFill(LxElfVirtualFill const & fill, bool verbose);

  typedef std::vector<LxElfVirtualFill> VirtualFills;
  typedef VirtualFills::const_iterator VirtualFillIter;
  bool AnyVirtualFill() const;
  VirtualFillIter Begin() const;
  VirtualFillIter End() const;

private:
  LxElfFile(LxElfFile const &);       // Not implemented
  void operator =(LxElfFile const &); // Not implemented

  // Loading
  void Load(std::string const & filename);
  void Load(std::istream & inFile);
  void LoadElfHeader(std::istream & inFile);
  void LoadPgHeaders(Elf32_Half     phnum,
                     Elf64_Off      phoff,
                     Elf32_Half     phentsize,
                     std::istream & inFile);
  void LoadSectionHeaders(Elf32_Half     shnum,
                          Elf64_Off      shoff,
                          Elf32_Half     shentsize,
                          std::istream & inFile);
  void LoadContents(std::istream & inFile);

  void AdjustSize(Elf64_Off offset, Elf64_Word length, bool larger);

  // Adds space in the elf file (initialized to 0)
  void InsertSpace(Elf64_Off offset, Elf64_Word length);

  // Removes space in the elf file
  void RemoveSpace(Elf64_Off offset, Elf64_Word length);

  LxElfSection * AddSectionHeader(Elf64_Shdr const & shdr);

  void NotifySizeChange(Elf64_Off off, Elf64_Word size, bool larger);

  static Elf32_Word AlignUp(Elf32_Word value);
  static Elf32_Word AlignDown(Elf32_Word value);

  // True if the elf file has the big endian data order
  bool mElfBigEndian;

  // True for 64-bit ELF
  bool mIs64Bit;

  // The elf header structure
  ElfHeader mElfHdr;

  // Vector of all segments.
  Segments mSegments;

  // Vector of all sections, including headers
  LxElfSections mScns;

  // The index of the symbol table in the section header list
  Elf32_Half mSymTabHdrIdx;

  // True if the elf file contains a symbol table
  bool mHasSymbolTable;

  // List of observers that get notified when the ELF file changes
  LxElfFileObservers mObservers;

  std::string mFileName;

  VirtualFills mVirtualFills;

  //

};

#endif
