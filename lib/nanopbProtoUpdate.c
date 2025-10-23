#include "icsglb.h"
#include "include/nanopb/nanopbProtoUpdate.h"
#include "pb_common.h"
#include <stdio.h>

bool UpdatePBFields(const pb_msgdesc_t* spec, const void* src, void* dest)
{
	pb_field_iter_t srcIter;
	bool success = pb_field_iter_begin_const(&srcIter, spec, src);
	if (!success)
	{
		return false;
	}
	while (success)
	{
		pb_field_iter_t destIter;
		// get an iterator for the destination
		success = pb_field_iter_begin(&destIter, spec, dest);
		// find this tag
		success = success && pb_field_iter_find(&destIter, srcIter.tag);
		if (!success)
		{
			break;
		}
		pb_type_t htype = PB_HTYPE(srcIter.type);
		pb_type_t ltype = PB_LTYPE(srcIter.type);
		size_t count = 1;
		switch (htype)
		{
		case PB_HTYPE_REQUIRED:
			// Required is deprecated so we should never have any required fields
			LogVerbose("Unexpected required field\n");
			success = false;
			break;
		case PB_HTYPE_OPTIONAL:
		//case PB_HTYPE_SINGULAR:
		{
			// Optional and singular enum values are the same!
			// pSize points to a bool in this case
			bool* srcHasPtr = (bool*)srcIter.pSize;
			bool* destHasPtr = (bool*)destIter.pSize;
			if (srcHasPtr && *srcHasPtr == false)
			{
				// This is the case where the field is optional and not present
				// Do not copy
				count = 0;
			}
			if (destHasPtr && srcHasPtr && *srcHasPtr)
			{
				// Field is optional and present
				// Copy and make sure presence is set to true
				*destHasPtr = true;
			}
			// if the srcHasPtr is null, the field is not optional
			// we will copy and not update the presence flag in the destination
			break;
		}
		case PB_HTYPE_REPEATED:
		//case PB_HTYPE_FIXARRAY:
		{
			// Repeated and fixarray enum values are the same!
			// pSize points to a pb_size_t count in this case
			pb_size_t* srcCount = (pb_size_t*)srcIter.pSize;
			pb_size_t* destCount = (pb_size_t*)destIter.pSize;
			if (srcCount)
			{
				// this is how many we're copying
				count = *srcCount;
			}
			else
			{
				// this field was empty. do not copy
				count = 0;
			}
			if (srcCount && destCount && *srcCount)
			{
				// simplification. Always match the two counts rather than appending
				*destCount = *srcCount;
			}
			break;
		}
		case PB_HTYPE_ONEOF:
			// We don't use this yet
			LogVerbose("Unsupported oneof field\n");
			success = false;
			break;
		}
		if (count && success)
		{
			// A couple defensive checks
			if (count > destIter.array_size)
			{
				count = destIter.array_size;
				LogVerbose("Truncated count to destination size\n");
			}
			if (srcIter.data_size != destIter.data_size)
			{
				LogError("Incompatible field size\n");
				success = false;
			}
			if (success)
			{
				switch (ltype)
				{
				case PB_LTYPE_SUBMESSAGE:
				{
					// We could have an array of submessages
					for (size_t i = 0; i < count; ++i)
					{
						// Point to the i-th instance of the submessage in src and dest
						const void* copyFrom = (uint8_t*)srcIter.pField + srcIter.data_size * i;
						void* copyTo = (uint8_t*)destIter.pField + destIter.data_size * i;
						// recursively handle the submessage by calling this function again
						success = UpdatePBFields(srcIter.submsg_desc, copyFrom, copyTo);
						if (!success)
						{
							break;
						}
					}
					break;
				}
				case PB_LTYPE_BOOL:
				case PB_LTYPE_VARINT:
				case PB_LTYPE_UVARINT:
				case PB_LTYPE_SVARINT:
				case PB_LTYPE_FIXED32:
				case PB_LTYPE_FIXED64:
				case PB_LTYPE_FIXED_LENGTH_BYTES:
					// these are all a simple memcpy
					memcpy(destIter.pData, srcIter.pData, srcIter.data_size * count);
					break;
				case PB_LTYPE_STRING:
				{
					// copy the string without overrun
					int ret = snprintf((char*)destIter.pData, destIter.data_size, "%s", (const char*)srcIter.pData);
					success = ret >= 0 && ret < destIter.data_size;
					break;
				}
				case PB_LTYPE_BYTES:
				case PB_LTYPE_SUBMSG_W_CB:
					// we're not using these right now
				default:
					LogError("Unsupported field type\n");
					success = false;
					break;
				}
			}
		}
		// keep iterating while successful
		success = success && pb_field_iter_next(&srcIter);
	}
	return true;
}
