#pragma once
#pragma pack(1)  //aligning structure
#include "stdafx.h"




/*************************************************************************************
* Author: Teoderick Contreras [tccontre18 - Br3akp0int]
*
* Description: This POC tool is designed to test the evasion and persistence
*              using reg restore function
*
*
*
**************************************************************************************/

struct REGF_HEADER
{
	DWORD dwRegfSig;
	DWORD dwPrimarySequenceNumber;
	DWORD dwSecondSequenceNumber;
	BYTE LastModDateAndTime[8];
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	DWORD dwType;
	DWORD dwFormat;
	DWORD dwRootKeyOffset;
	DWORD dwHiveBinDataSize;
	DWORD dwClusteringFactor;
	BYTE unknown1[64];
	BYTE unknown2[396];
	DWORD dwChecksum;
	BYTE reserved[3576];
	DWORD dwBootType;
	DWORD dwBootRecover;

};

struct HIVE_BIN_HEADER
{
	DWORD dwHbinSig;
	DWORD dwOffset;               // This bin's distance from the first hive bin
	DWORD dwSize;                 // This hive bin's size(multiple of 4096)
	BYTE unknown[16];            // Relative offset of next hive bin (should be the same value as at offset 0x8)
	DWORD unknown4;             // List of cells used to store various records (see below)

};

struct CELL_FMT
{
	DWORD dwCellLength;
	WORD wCellTypeIdentifier;
};


struct SUBKEYLIST_VK
{
	SHORT wValueNameSize;
	INT dwDataSize;
	DWORD dwDataOffset;
	DWORD dwDataType;
	WORD wFlags;
	WORD wPadding;
};


struct SUBKEYLIST_SK
{
	WORD unknown1;
	DWORD dwPreviousSecurityKeyOffset;
	DWORD dwNextSecurityOffset;
	DWORD dwReferenceCount;
	DWORD dwSizeOfSecurityDescriptor;
};


struct NAMEDKEY_NK
{
	WORD wFlags;
	BYTE LastKeyWrittenDateAndTime[8];
	DWORD unknown1;
	DWORD dwParentCellOffset;
	DWORD dwSubkeyCountStable;
	DWORD dwSubkeyCountVolatile;
	DWORD dwSubkeyListOffsetStable;
	DWORD dwSubkeyListOffsetVolatile;
	INT   dwValueCount;
	DWORD dwValuesListOffset;
	DWORD dwSecurityKeyOffset;
	DWORD dwClassNameOffset;
	WORD  wMaxNameLength;
	BYTE  bUserVirtFlags;
	BYTE  bDebug;
	DWORD dwMaxClassLength;
	DWORD dwMaxValueNameLength;
	DWORD dwMaxValueDataLength;
	DWORD unknown2;
	WORD wKeyNameSize;
	WORD wClassSameSize;

};



