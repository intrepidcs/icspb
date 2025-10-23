#ifndef _NANOPBPROTOUPDATE_H_
#define _NANOPBPROTOUPDATE_H_

#include "icsglb.h"
#include "pb.h"

#if defined(__cplusplus)
extern "C"
{
#endif

	/**
	 * Updates a protobuf struct by iterating over fields and selectively updating what is present
	 * spec: shared spec for the src and dest struct
	 * src: source struct with selective updates to apply
	 * dest: destination struct to apply updates to. This is updated while running
	 *   recommend passing in a temporary struct initialized to current settings
	 *   and overwriting the full struct when this returns success
	 * returns true / false for successful parsing / copying
	 */
	bool UpdatePBFields(const pb_msgdesc_t* spec, const void* src, void* dest);

#if defined(__cplusplus)
}
#endif

#endif // _NANOPBPROTOUPDATE_H_
