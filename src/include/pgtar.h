/*-------------------------------------------------------------------------
 *
 * pgtar.h
 *	  Functions for manipulating tarfile datastructures (src/port/tar.c)
 *
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/pgtar.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_TAR_H
#define PG_TAR_H

#define		TAR_BLOCK_SIZE	512

/*
 * Sizes of the fixed-width string fields in a traditional ustar header.
 * These are part of the on-disk format and must not be changed.
 */
#define		TAR_NAME_FIELD_SIZE		100
#define		TAR_PREFIX_FIELD_SIZE	155
#define		TAR_LINKNAME_FIELD_SIZE	100

/*
 * Maximum size of a PAX extended header payload that we are willing to
 * accept.  The only extensions we care about are "path" and "linkpath",
 * both of which are bounded by MAXPGPATH, so there is no reason to accept
 * arbitrarily large payloads.
 */
#define		TAR_MAX_PAX_PAYLOAD		(MAXPGPATH * 4)

/* Name used for the PAX extended header member itself. */
#define		TAR_PAX_HEADER_NAME		"PaxHeader"

enum tarError
{
	TAR_OK = 0,
	TAR_NAME_TOO_LONG,
	TAR_SYMLINK_TOO_LONG,
	TAR_BUFFER_TOO_SMALL,
};

/*
 * Offsets of fields within a 512-byte tar header.
 *
 * "tar number" values should be generated using print_tar_number() and can be
 * read using read_tar_number(). Fields that contain strings are generally
 * both filled and read using strlcpy().
 *
 * The value for the checksum field can be computed using tarChecksum().
 *
 * Some fields are not used by PostgreSQL; see tarCreateHeader().
 */
enum tarHeaderOffset
{
	TAR_OFFSET_NAME = 0,		/* 100 byte string */
	TAR_OFFSET_MODE = 100,		/* 8 byte tar number, excludes S_IFMT */
	TAR_OFFSET_UID = 108,		/* 8 byte tar number */
	TAR_OFFSET_GID = 116,		/* 8 byte tar number */
	TAR_OFFSET_SIZE = 124,		/* 8 byte tar number */
	TAR_OFFSET_MTIME = 136,		/* 12 byte tar number */
	TAR_OFFSET_CHECKSUM = 148,	/* 8 byte tar number */
	TAR_OFFSET_TYPEFLAG = 156,	/* 1 byte file type, see TAR_FILETYPE_* */
	TAR_OFFSET_LINKNAME = 157,	/* 100 byte string */
	TAR_OFFSET_MAGIC = 257,		/* "ustar" with terminating zero byte */
	TAR_OFFSET_VERSION = 263,	/* "00" */
	TAR_OFFSET_UNAME = 265,		/* 32 byte string */
	TAR_OFFSET_GNAME = 297,		/* 32 byte string */
	TAR_OFFSET_DEVMAJOR = 329,	/* 8 byte tar number */
	TAR_OFFSET_DEVMINOR = 337,	/* 8 byte tar number */
	TAR_OFFSET_PREFIX = 345,	/* 155 byte string */
	/* last 12 bytes of the 512-byte block are unassigned */
};

/* See POSIX (not all the standard file type codes are listed here) */
enum tarFileType
{
	TAR_FILETYPE_PLAIN = '0',
	TAR_FILETYPE_PLAIN_OLD = '\0',	/* backwards compatibility, per POSIX */
	TAR_FILETYPE_SYMLINK = '2',
	TAR_FILETYPE_DIRECTORY = '5',
	TAR_FILETYPE_PAX_EXTENDED = 'x',
	TAR_FILETYPE_PAX_EXTENDED_GLOBAL = 'g',
};

extern enum tarError tarCreateHeader(char *h, const char *filename,
									 const char *linktarget, pgoff_t size,
									 mode_t mode, uid_t uid, gid_t gid,
									 time_t mtime);

/*
 * Compute the number of bytes needed to represent a tar member, including a
 * PAX extended header if the file name or symbolic link target cannot be
 * represented using the traditional ustar fields.  Returns 0 if the name or
 * link target is longer than MAXPGPATH, in which case no archive
 * representation is possible.
 */
extern size_t tarCreateHeaderExtSize(const char *filename,
									 const char *linktarget);

/*
 * Build the on-disk representation of a tar member at 'h', which must have
 * room for tarCreateHeaderExtSize(filename, linktarget) bytes.  If a PAX
 * extended header is required, it is written before the traditional header,
 * and the traditional header uses a truncated placeholder for the long
 * field(s); consumers must give precedence to the PAX attributes.
 *
 * On success, *bytes_written is set to the total number of bytes emitted.
 */
extern enum tarError tarCreateHeaderExt(char *h, size_t hsize,
										const char *filename,
										const char *linktarget,
										pgoff_t size, mode_t mode,
										uid_t uid, gid_t gid, time_t mtime,
										size_t *bytes_written);

extern uint64 read_tar_number(const char *s, int len);
extern void print_tar_number(char *s, int len, uint64 val);
extern int	tarChecksum(const char *header);
extern bool isValidTarHeader(const char *header);

/*
 * Compute the number of padding bytes required for an entry in a tar
 * archive. We must pad out to a multiple of TAR_BLOCK_SIZE. Since that's
 * a power of 2, we can use TYPEALIGN().
 */
static inline size_t
tarPaddingBytesRequired(size_t len)
{
	return TYPEALIGN(TAR_BLOCK_SIZE, len) - len;
}

#endif
