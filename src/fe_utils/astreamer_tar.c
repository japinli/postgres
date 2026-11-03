/*-------------------------------------------------------------------------
 *
 * astreamer_tar.c
 *
 * This module implements three types of tar processing. A tar parser
 * expects unlabelled chunks of data (e.g. ASTREAMER_UNKNOWN) and splits
 * it into labelled chunks (any other value of astreamer_archive_context).
 * A tar archiver does the reverse: it takes a bunch of labelled chunks
 * and produces a tarfile, optionally replacing member headers and trailers
 * so that upstream astreamer objects can perform surgery on the tarfile
 * contents without knowing the details of the tar format. A tar terminator
 * just adds two blocks of NUL bytes to the end of the file, since older
 * server versions produce files with this terminator omitted.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  src/fe_utils/astreamer_tar.c
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include <time.h>

#include "common/logging.h"
#include "fe_utils/astreamer.h"
#include "pgtar.h"

typedef enum
{
	TAR_PARSE_MEMBER_HEADER,
	TAR_PARSE_PAX_PAYLOAD,
	TAR_PARSE_PAX_PADDING,
	TAR_PARSE_MEMBER_CONTENTS,
	TAR_PARSE_MEMBER_TRAILER,
	TAR_PARSE_ARCHIVE_TRAILER,
} tar_parser_state;

typedef struct astreamer_tar_parser
{
	astreamer	base;
	tar_parser_state next_context;
	astreamer_member member;
	size_t		file_bytes_sent;
	size_t		pad_bytes_expected;
	size_t		pax_bytes_expected;
	size_t		pax_pad_bytes_expected;
	bool		pax_pending;
	bool		pax_has_path;
	bool		pax_has_linkpath;
	char		pax_path[MAXPGPATH];
	char		pax_linkpath[MAXPGPATH];
} astreamer_tar_parser;

typedef struct astreamer_tar_archiver
{
	astreamer	base;
	bool		rearchive_member;
} astreamer_tar_archiver;

typedef enum
{
	TAR_HEADER_MEMBER,
	TAR_HEADER_PAX,
	TAR_HEADER_ARCHIVE_END,
} tar_header_result;

static void astreamer_tar_parser_content(astreamer *streamer,
										 astreamer_member *member,
										 const char *data, int len,
										 astreamer_archive_context context);
static void astreamer_tar_parser_finalize(astreamer *streamer);
static void astreamer_tar_parser_free(astreamer *streamer);
static tar_header_result
astreamer_tar_header(astreamer_tar_parser *mystreamer);
static void astreamer_tar_parse_pax(astreamer_tar_parser *mystreamer,
									const char *data, size_t len);
static void tarReadStringField(char *dst, size_t dstsize,
							   const char *src, size_t srclen);

static const astreamer_ops astreamer_tar_parser_ops = {
	.content = astreamer_tar_parser_content,
	.finalize = astreamer_tar_parser_finalize,
	.free = astreamer_tar_parser_free
};

static void astreamer_tar_archiver_content(astreamer *streamer,
										   astreamer_member *member,
										   const char *data, int len,
										   astreamer_archive_context context);
static void astreamer_tar_archiver_finalize(astreamer *streamer);
static void astreamer_tar_archiver_free(astreamer *streamer);

static const astreamer_ops astreamer_tar_archiver_ops = {
	.content = astreamer_tar_archiver_content,
	.finalize = astreamer_tar_archiver_finalize,
	.free = astreamer_tar_archiver_free
};

static void astreamer_tar_terminator_content(astreamer *streamer,
											 astreamer_member *member,
											 const char *data, int len,
											 astreamer_archive_context context);
static void astreamer_tar_terminator_finalize(astreamer *streamer);
static void astreamer_tar_terminator_free(astreamer *streamer);

static const astreamer_ops astreamer_tar_terminator_ops = {
	.content = astreamer_tar_terminator_content,
	.finalize = astreamer_tar_terminator_finalize,
	.free = astreamer_tar_terminator_free
};

/*
 * Create a astreamer that can parse a stream of content as tar data.
 *
 * The input should be a series of ASTREAMER_UNKNOWN chunks; the astreamer
 * specified by 'next' will receive a series of typed chunks, as per the
 * conventions described in astreamer.h.
 */
astreamer *
astreamer_tar_parser_new(astreamer *next)
{
	astreamer_tar_parser *streamer;

	streamer = palloc0_object(astreamer_tar_parser);
	*((const astreamer_ops **) &streamer->base.bbs_ops) =
		&astreamer_tar_parser_ops;
	streamer->base.bbs_next = next;
	initStringInfo(&streamer->base.bbs_buffer);
	streamer->next_context = TAR_PARSE_MEMBER_HEADER;

	return &streamer->base;
}

/*
 * Parse unknown content as tar data.
 */
static void
astreamer_tar_parser_content(astreamer *streamer, astreamer_member *member,
							 const char *data, int len,
							 astreamer_archive_context context)
{
	astreamer_tar_parser *mystreamer = (astreamer_tar_parser *) streamer;
	size_t		nbytes;

	/* Expect unparsed input. */
	Assert(member == NULL);
	Assert(context == ASTREAMER_UNKNOWN);

	while (len > 0)
	{
		switch (mystreamer->next_context)
		{
			case TAR_PARSE_MEMBER_HEADER:
				{
					tar_header_result result;

					/*
					 * If we're expecting an archive member header,
					 * accumulate a full block of data before doing anything
					 * further.
					 */
					if (!astreamer_buffer_until(streamer, &data, &len,
												TAR_BLOCK_SIZE))
						return;

					/*
					 * Now we can process the header and get ready to process
					 * the file contents; however, we might find out that what
					 * we thought was the next file header is actually the
					 * start of the archive trailer.  Alternatively, it might
					 * be a PAX extended header, in which case we need to read
					 * its payload before the actual member header.
					 */
					result = astreamer_tar_header(mystreamer);
					if (result == TAR_HEADER_ARCHIVE_END)
					{
						if (mystreamer->pax_pending)
							pg_fatal("tar archive ended while a pax extended header was pending");
						mystreamer->next_context = TAR_PARSE_ARCHIVE_TRAILER;
					}
					else if (result == TAR_HEADER_PAX)
					{
						mystreamer->base.bbs_buffer.len = 0;
						mystreamer->file_bytes_sent = 0;
						mystreamer->next_context = TAR_PARSE_PAX_PAYLOAD;
					}
					else
					{
						if (mystreamer->member.size == 0)
						{
							/* No content; trailer is zero-length. */
							astreamer_content(mystreamer->base.bbs_next,
											  &mystreamer->member,
											  NULL, 0,
											  ASTREAMER_MEMBER_TRAILER);

							/* Expect next header. */
							mystreamer->next_context = TAR_PARSE_MEMBER_HEADER;
						}
						else
						{
							/* Expect contents. */
							mystreamer->next_context = TAR_PARSE_MEMBER_CONTENTS;
						}
						mystreamer->base.bbs_buffer.len = 0;
						mystreamer->file_bytes_sent = 0;
					}
				}
				break;

			case TAR_PARSE_PAX_PAYLOAD:

				/*
				 * Accumulate the complete PAX extended header payload.
				 */
				if (!astreamer_buffer_until(streamer, &data, &len,
											mystreamer->pax_bytes_expected))
					return;

				Assert(mystreamer->base.bbs_buffer.len ==
					   mystreamer->pax_bytes_expected);

				/* Parse the records and remember path/linkpath overrides. */
				astreamer_tar_parse_pax(mystreamer,
										mystreamer->base.bbs_buffer.data,
										mystreamer->base.bbs_buffer.len);

				mystreamer->base.bbs_buffer.len = 0;

				if (mystreamer->pax_pad_bytes_expected > 0)
					mystreamer->next_context = TAR_PARSE_PAX_PADDING;
				else
					mystreamer->next_context = TAR_PARSE_MEMBER_HEADER;
				break;

			case TAR_PARSE_PAX_PADDING:
				{
					size_t		i;

					/*
					 * Consume the NUL padding that follows the PAX payload.
					 */
					if (!astreamer_buffer_until(streamer, &data, &len,
												mystreamer->pax_pad_bytes_expected))
						return;

					for (i = 0; i < mystreamer->pax_pad_bytes_expected; ++i)
					{
						if (mystreamer->base.bbs_buffer.data[i] != '\0')
							pg_fatal("invalid padding after pax extended header");
					}

					mystreamer->base.bbs_buffer.len = 0;
					mystreamer->next_context = TAR_PARSE_MEMBER_HEADER;
				}
				break;

			case TAR_PARSE_MEMBER_CONTENTS:

				/*
				 * Send as much content as we have, but not more than the
				 * remaining file length.
				 */
				Assert(mystreamer->file_bytes_sent < mystreamer->member.size);
				nbytes = mystreamer->member.size - mystreamer->file_bytes_sent;
				nbytes = Min(nbytes, len);
				Assert(nbytes > 0);
				astreamer_content(mystreamer->base.bbs_next,
								  &mystreamer->member,
								  data, nbytes,
								  ASTREAMER_MEMBER_CONTENTS);
				mystreamer->file_bytes_sent += nbytes;
				data += nbytes;
				len -= nbytes;

				/*
				 * If we've not yet sent the whole file, then there's more
				 * content to come; otherwise, it's time to expect the file
				 * trailer.
				 */
				Assert(mystreamer->file_bytes_sent <= mystreamer->member.size);
				if (mystreamer->file_bytes_sent == mystreamer->member.size)
				{
					if (mystreamer->pad_bytes_expected == 0)
					{
						/* Trailer is zero-length. */
						astreamer_content(mystreamer->base.bbs_next,
										  &mystreamer->member,
										  NULL, 0,
										  ASTREAMER_MEMBER_TRAILER);

						/* Expect next header. */
						mystreamer->next_context = TAR_PARSE_MEMBER_HEADER;
					}
					else
					{
						/* Trailer is not zero-length. */
						mystreamer->next_context = TAR_PARSE_MEMBER_TRAILER;
					}
					mystreamer->base.bbs_buffer.len = 0;
				}
				break;

			case TAR_PARSE_MEMBER_TRAILER:

				/*
				 * If we're expecting an archive member trailer, accumulate
				 * the expected number of padding bytes before sending
				 * anything onward.
				 */
				if (!astreamer_buffer_until(streamer, &data, &len,
											mystreamer->pad_bytes_expected))
					return;

				/* OK, now we can send it. */
				astreamer_content(mystreamer->base.bbs_next,
								  &mystreamer->member,
								  mystreamer->base.bbs_buffer.data,
								  mystreamer->pad_bytes_expected,
								  ASTREAMER_MEMBER_TRAILER);

				/* Expect next file header. */
				mystreamer->next_context = TAR_PARSE_MEMBER_HEADER;
				mystreamer->base.bbs_buffer.len = 0;
				break;

			case TAR_PARSE_ARCHIVE_TRAILER:

				/*
				 * We've seen an end-of-archive indicator, so anything more is
				 * buffered and sent as part of the archive trailer.
				 *
				 * Per POSIX, the last physical block of a tar archive is
				 * always full-sized, so there may be undefined data after the
				 * two zero blocks that mark end-of-archive.  GNU tar, for
				 * example, zero-pads to a 10kB boundary by default.  We just
				 * buffer whatever we receive and pass it along at finalize
				 * time.
				 */
				astreamer_buffer_bytes(streamer, &data, &len, len);
				return;

			default:
				/* Shouldn't happen. */
				pg_fatal("unexpected state while parsing tar archive");
		}
	}
}

/*
 * Copy a fixed-size string field from a tar header.  The field is not
 * guaranteed to be NUL-terminated, and may be followed immediately by other
 * header fields, so we must never scan past its declared length.
 */
static void
tarReadStringField(char *dst, size_t dstsize, const char *src, size_t srclen)
{
	const char *nul = memchr(src, '\0', srclen);
	size_t		len = nul ? (size_t) (nul - src) : srclen;

	if (len >= dstsize)
		pg_fatal("tar member field is too long");

	memcpy(dst, src, len);
	dst[len] = '\0';
}

/*
 * Parse the payload of a PAX extended header ('x') member.
 *
 * Records have the form "<length> <key>=<value>\n", where <length> counts
 * the entire record including the length digits and the trailing newline.
 * Unknown keys are ignored, as required by POSIX.  If a key is repeated, the
 * last occurrence wins.
 */
static void
astreamer_tar_parse_pax(astreamer_tar_parser *mystreamer,
						const char *data, size_t len)
{
	size_t		pos = 0;

	while (pos < len)
	{
		size_t		start = pos;
		size_t		reclen = 0;
		const char *key;
		const char *eq;
		const char *rec_end;
		size_t		keylen;

		/* Parse the record length. */
		while (pos < len && data[pos] >= '0' && data[pos] <= '9')
		{
			size_t		digit = data[pos] - '0';

			if (reclen > (SIZE_MAX - digit) / 10)
				pg_fatal("invalid pax extended header: record length overflow");
			reclen = reclen * 10 + digit;
			pos++;
		}

		if (pos == start || pos >= len || data[pos] != ' ')
			pg_fatal("invalid pax extended header record");

		if (reclen == 0 || reclen > len - start)
			pg_fatal("invalid pax extended header: record length exceeds payload");

		if (data[start + reclen - 1] != '\n')
			pg_fatal("invalid pax extended header: record does not end with newline");

		rec_end = data + start + reclen;

		/* The key starts after the space following the length. */
		key = data + pos + 1;
		if ((size_t) (rec_end - 1 - key) < 2)
			pg_fatal("invalid pax extended header: malformed key/value record");
		eq = memchr(key, '=', (rec_end - 1) - key);
		if (eq == NULL || eq == key)
			pg_fatal("invalid pax extended header: malformed key/value record");

		keylen = eq - key;

		/* Neither the key nor the value may contain an embedded NUL. */
		if (memchr(key, '\0', keylen) != NULL)
			pg_fatal("invalid pax extended header: NUL in key");

		{
			const char *value = eq + 1;
			size_t		valuelen = (rec_end - 1) - value;

			if (memchr(value, '\0', valuelen) != NULL)
				pg_fatal("invalid pax extended header: NUL in value");

			if (keylen == 4 && memcmp(key, "path", 4) == 0)
			{
				if (valuelen >= MAXPGPATH)
					pg_fatal("pax extended header path is too long");
				memcpy(mystreamer->pax_path, value, valuelen);
				mystreamer->pax_path[valuelen] = '\0';
				mystreamer->pax_has_path = true;
			}
			else if (keylen == 8 && memcmp(key, "linkpath", 8) == 0)
			{
				if (valuelen >= MAXPGPATH)
					pg_fatal("pax extended header linkpath is too long");
				memcpy(mystreamer->pax_linkpath, value, valuelen);
				mystreamer->pax_linkpath[valuelen] = '\0';
				mystreamer->pax_has_linkpath = true;
			}
			else
				pg_log_debug("ignoring unknown pax extended header key \"%.*s\"",
							 (int) keylen, key);
		}

		pos = start + reclen;
	}
}

/*
 * Parse a file header within a tar stream.
 *
 * We pass member headers on to the next astreamer.  A PAX extended header
 * ('x') is consumed internally, and its path/linkpath attributes are applied
 * to the member that follows it.  Global PAX headers ('g') are rejected.
 * We throw error if we see invalid data.
 */
static tar_header_result
astreamer_tar_header(astreamer_tar_parser *mystreamer)
{
	bool		has_nonzero_byte = false;
	int			i;
	astreamer_member *member = &mystreamer->member;
	char	   *buffer = mystreamer->base.bbs_buffer.data;
	char		prefix[TAR_PREFIX_FIELD_SIZE + 1];
	char		typeflag;

	Assert(mystreamer->base.bbs_buffer.len == TAR_BLOCK_SIZE);

	/* Zero out fields of *member, just for consistency. */
	memset(member, 0, sizeof(astreamer_member));

	/* Check whether we've got a block of all zero bytes. */
	for (i = 0; i < TAR_BLOCK_SIZE; ++i)
	{
		if (buffer[i] != '\0')
		{
			has_nonzero_byte = true;
			break;
		}
	}

	/*
	 * If the entire block was zeros, this is the end of the archive, not the
	 * start of the next file.
	 */
	if (!has_nonzero_byte)
		return TAR_HEADER_ARCHIVE_END;

	/*
	 * Verify that we have a reasonable-looking header.
	 */
	if (!isValidTarHeader(buffer))
		pg_fatal("input file does not appear to be a valid tar archive");

	typeflag = buffer[TAR_OFFSET_TYPEFLAG];

	/*
	 * A PAX extended header describes the member that follows it.  Read and
	 * parse its payload in the caller's state machine.
	 */
	if (typeflag == TAR_FILETYPE_PAX_EXTENDED)
	{
		uint64		paxsize;

		if (mystreamer->pax_pending)
			pg_fatal("consecutive pax extended headers are not supported");

		paxsize = read_tar_number(&buffer[TAR_OFFSET_SIZE], 12);
		if (paxsize == 0)
			pg_fatal("pax extended header has zero size");
		if (paxsize > TAR_MAX_PAX_PAYLOAD)
			pg_fatal("pax extended header is too large");

		mystreamer->pax_bytes_expected = (size_t) paxsize;
		mystreamer->pax_pad_bytes_expected =
			tarPaddingBytesRequired(mystreamer->pax_bytes_expected);
		mystreamer->pax_pending = true;
		mystreamer->pax_has_path = false;
		mystreamer->pax_has_linkpath = false;
		mystreamer->pax_path[0] = '\0';
		mystreamer->pax_linkpath[0] = '\0';

		return TAR_HEADER_PAX;
	}
	else if (typeflag == TAR_FILETYPE_PAX_EXTENDED_GLOBAL)
		pg_fatal("global pax extended headers are not supported");

	/*
	 * Parse key fields out of the header.  The ustar prefix field, when
	 * present, is prepended to the name field.  Both fields are fixed-width
	 * and need not be NUL-terminated.
	 */
	tarReadStringField(member->pathname, MAXPGPATH,
					   &buffer[TAR_OFFSET_NAME], TAR_NAME_FIELD_SIZE);
	tarReadStringField(prefix, sizeof(prefix),
					   &buffer[TAR_OFFSET_PREFIX], TAR_PREFIX_FIELD_SIZE);

	if (prefix[0] != '\0')
	{
		char		fullpath[MAXPGPATH];
		int			pathlen;

		/*
		 * Build the combined path in a separate buffer: snprintf() must not
		 * have the same buffer as both an input and the output.
		 */
		pathlen = snprintf(fullpath, sizeof(fullpath), "%s/%s",
						   prefix, member->pathname);
		if (pathlen < 0 || pathlen >= MAXPGPATH)
			pg_fatal("tar member path is too long");
		strlcpy(member->pathname, fullpath, MAXPGPATH);
	}

	/* PAX path, when present, overrides the traditional fields. */
	if (mystreamer->pax_pending && mystreamer->pax_has_path)
		strlcpy(member->pathname, mystreamer->pax_path, MAXPGPATH);

	if (member->pathname[0] == '\0')
		pg_fatal("tar member has empty name");
	if (!path_is_safe_for_extraction(member->pathname))
		pg_fatal("tar member has unsafe path name: \"%s\"",
				 member->pathname);

	member->size = read_tar_number(&buffer[TAR_OFFSET_SIZE], 12);
	member->mode = read_tar_number(&buffer[TAR_OFFSET_MODE], 8);
	member->uid = read_tar_number(&buffer[TAR_OFFSET_UID], 8);
	member->gid = read_tar_number(&buffer[TAR_OFFSET_GID], 8);

	{
		bool		pax_applied = mystreamer->pax_pending;

		switch (typeflag)
		{
			case TAR_FILETYPE_PLAIN:
			case TAR_FILETYPE_PLAIN_OLD:
				member->is_regular = true;
				break;
			case TAR_FILETYPE_DIRECTORY:
				member->is_directory = true;
				break;
			case TAR_FILETYPE_SYMLINK:
				member->is_symlink = true;
				tarReadStringField(member->linktarget, MAXPGPATH,
								   &buffer[TAR_OFFSET_LINKNAME],
								   TAR_LINKNAME_FIELD_SIZE);

				/* PAX linkpath, when present, overrides the linkname field. */
				if (mystreamer->pax_pending && mystreamer->pax_has_linkpath)
					strlcpy(member->linktarget, mystreamer->pax_linkpath,
							MAXPGPATH);
				break;
			default:
				/* For special filetypes, set none of the three is_xxx flags */
				break;
		}

		/*
		 * Whether or not we used them, PAX attributes apply only to this
		 * member.
		 */
		mystreamer->pax_pending = false;
		mystreamer->pax_has_path = false;
		mystreamer->pax_has_linkpath = false;

		/* Compute number of padding bytes. */
		mystreamer->pad_bytes_expected =
			tarPaddingBytesRequired(member->size);

		/*
		 * If a PAX header was in effect, the traditional header block may
		 * contain only a placeholder for the real path or link target.  Do
		 * not forward it; telling the next astreamer that no header block is
		 * available forces anyone who needs to emit a tar stream (e.g.
		 * astreamer_tar_archiver) to reconstruct it from 'member'.
		 */
		if (pax_applied)
			astreamer_content(mystreamer->base.bbs_next, member,
							  NULL, 0,
							  ASTREAMER_MEMBER_HEADER);
		else
			astreamer_content(mystreamer->base.bbs_next, member,
							  buffer, TAR_BLOCK_SIZE,
							  ASTREAMER_MEMBER_HEADER);
	}

	return TAR_HEADER_MEMBER;
}

/*
 * End-of-stream processing for a tar parser.
 */
static void
astreamer_tar_parser_finalize(astreamer *streamer)
{
	astreamer_tar_parser *mystreamer = (astreamer_tar_parser *) streamer;

	if (mystreamer->pax_pending)
		pg_fatal("COPY stream ended while a pax extended header was pending");

	if (mystreamer->next_context != TAR_PARSE_ARCHIVE_TRAILER &&
		(mystreamer->next_context != TAR_PARSE_MEMBER_HEADER ||
		 mystreamer->base.bbs_buffer.len > 0))
		pg_fatal("COPY stream ended before last file was finished");

	/* Send the archive trailer, even if empty. */
	astreamer_content(streamer->bbs_next, NULL,
					  streamer->bbs_buffer.data, streamer->bbs_buffer.len,
					  ASTREAMER_ARCHIVE_TRAILER);

	/* Now finalize successor. */
	astreamer_finalize(streamer->bbs_next);
}

/*
 * Free memory associated with a tar parser.
 */
static void
astreamer_tar_parser_free(astreamer *streamer)
{
	pfree(streamer->bbs_buffer.data);
	astreamer_free(streamer->bbs_next);
	pfree(streamer);
}

/*
 * Create a astreamer that can generate a tar archive.
 *
 * This is intended to be usable either for generating a brand-new tar archive
 * or for modifying one on the fly. The input should be a series of typed
 * chunks (i.e. not ASTREAMER_UNKNOWN). See also the comments for
 * astreamer_tar_parser_content.
 */
astreamer *
astreamer_tar_archiver_new(astreamer *next)
{
	astreamer_tar_archiver *streamer;

	streamer = palloc0_object(astreamer_tar_archiver);
	*((const astreamer_ops **) &streamer->base.bbs_ops) =
		&astreamer_tar_archiver_ops;
	streamer->base.bbs_next = next;

	return &streamer->base;
}

/*
 * Fix up the stream of input chunks to create a valid tar file.
 *
 * If a ASTREAMER_MEMBER_HEADER chunk is of size 0, it is replaced with a
 * newly-constructed tar header.  A header is also reconstructed when the
 * member's path or link target requires a PAX extended header; this happens
 * when the input stream used PAX and the parser supplied the real values via
 * the astreamer_member.  Otherwise, a TAR_BLOCK_SIZE header is passed through
 * without change.  Any other size is a fatal error (and indicates a bug).
 *
 * Whenever a new ASTREAMER_MEMBER_HEADER chunk is constructed, the
 * corresponding ASTREAMER_MEMBER_TRAILER chunk is also constructed from
 * scratch. Specifically, we construct a block of zero bytes sufficient to
 * pad out to a block boundary, as required by the tar format. Other
 * ASTREAMER_MEMBER_TRAILER chunks are passed through without change.
 *
 * Any ASTREAMER_MEMBER_CONTENTS chunks are passed through without change.
 *
 * The ASTREAMER_ARCHIVE_TRAILER chunk is replaced with two
 * blocks of zero bytes. Not all tar programs require this, but apparently
 * some do. The server does not supply this trailer. If no archive trailer is
 * present, one will be added by astreamer_tar_parser_finalize.
 */
static void
astreamer_tar_archiver_content(astreamer *streamer,
							   astreamer_member *member,
							   const char *data, int len,
							   astreamer_archive_context context)
{
	astreamer_tar_archiver *mystreamer = (astreamer_tar_archiver *) streamer;
	char		buffer[2 * TAR_BLOCK_SIZE];
	char	   *allocated = NULL;

	Assert(context != ASTREAMER_UNKNOWN);

	if (context == ASTREAMER_MEMBER_HEADER)
	{
		const char *linktarget =
			member->is_symlink ? member->linktarget : NULL;
		size_t		hdrsize;
		bool		constructed = (len != TAR_BLOCK_SIZE);

		Assert(len == 0 || len == TAR_BLOCK_SIZE);

		hdrsize = tarCreateHeaderExtSize(member->pathname, linktarget);

		if (hdrsize == 0)
			pg_fatal("tar member name or link target is too long: \"%s\"",
					 member->pathname);

		/*
		 * We must replace the header not only when the input did not have
		 * one, but also when the member's full path or link target requires
		 * a PAX extended header.  The latter happens when the input archive
		 * used PAX and the parser supplied the long values via 'member'
		 * while the original header block contains only a placeholder.
		 */
		if (constructed || hdrsize != TAR_BLOCK_SIZE)
		{
			size_t		written;
			char	   *header;
			enum tarError rc;

			if (hdrsize <= sizeof(buffer))
				header = buffer;
			else
				header = allocated = palloc(hdrsize);

			rc = tarCreateHeaderExt(header, hdrsize, member->pathname,
									linktarget, member->size, member->mode,
									member->uid, member->gid, time(NULL),
									&written);
			if (rc == TAR_NAME_TOO_LONG)
				pg_fatal("file name too long for tar format: \"%s\"",
						 member->pathname);
			else if (rc == TAR_SYMLINK_TOO_LONG)
				pg_fatal("symbolic link target too long for tar format: "
						 "file name \"%s\", target \"%s\"",
						 member->pathname, linktarget);
			else if (rc != TAR_OK)
				pg_fatal("could not generate tar header for \"%s\"",
						 member->pathname);

			Assert(written == hdrsize);
			data = header;
			len = (int) hdrsize;

			/* Also replace padding if we had to construct a header. */
			if (constructed)
				mystreamer->rearchive_member = true;
		}
	}
	else if (context == ASTREAMER_MEMBER_TRAILER &&
			 mystreamer->rearchive_member)
	{
		int			pad_bytes = tarPaddingBytesRequired(member->size);

		/* Also replace padding, if we regenerated the header. */
		memset(buffer, 0, pad_bytes);
		data = buffer;
		len = pad_bytes;

		/* Don't do this again unless we replace another header. */
		mystreamer->rearchive_member = false;
	}
	else if (context == ASTREAMER_ARCHIVE_TRAILER)
	{
		/* Trailer should always be two blocks of zero bytes. */
		memset(buffer, 0, 2 * TAR_BLOCK_SIZE);
		data = buffer;
		len = 2 * TAR_BLOCK_SIZE;
	}

	astreamer_content(streamer->bbs_next, member, data, len, context);

	if (allocated != NULL)
		pfree(allocated);
}

/*
 * End-of-stream processing for a tar archiver.
 */
static void
astreamer_tar_archiver_finalize(astreamer *streamer)
{
	astreamer_finalize(streamer->bbs_next);
}

/*
 * Free memory associated with a tar archiver.
 */
static void
astreamer_tar_archiver_free(astreamer *streamer)
{
	astreamer_free(streamer->bbs_next);
	pfree(streamer);
}

/*
 * Create a astreamer that blindly adds two blocks of NUL bytes to the
 * end of an incomplete tarfile that the server might send us.
 */
astreamer *
astreamer_tar_terminator_new(astreamer *next)
{
	astreamer  *streamer;

	streamer = palloc0_object(astreamer);
	*((const astreamer_ops **) &streamer->bbs_ops) =
		&astreamer_tar_terminator_ops;
	streamer->bbs_next = next;

	return streamer;
}

/*
 * Pass all the content through without change.
 */
static void
astreamer_tar_terminator_content(astreamer *streamer,
								 astreamer_member *member,
								 const char *data, int len,
								 astreamer_archive_context context)
{
	/* Expect unparsed input. */
	Assert(member == NULL);
	Assert(context == ASTREAMER_UNKNOWN);

	/* Just forward it. */
	astreamer_content(streamer->bbs_next, member, data, len, context);
}

/*
 * At the end, blindly add the two blocks of NUL bytes which the server fails
 * to supply.
 */
static void
astreamer_tar_terminator_finalize(astreamer *streamer)
{
	char		buffer[2 * TAR_BLOCK_SIZE];

	memset(buffer, 0, 2 * TAR_BLOCK_SIZE);
	astreamer_content(streamer->bbs_next, NULL, buffer,
					  2 * TAR_BLOCK_SIZE, ASTREAMER_UNKNOWN);
	astreamer_finalize(streamer->bbs_next);
}

/*
 * Free memory associated with a tar terminator.
 */
static void
astreamer_tar_terminator_free(astreamer *streamer)
{
	astreamer_free(streamer->bbs_next);
	pfree(streamer);
}
