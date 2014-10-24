/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

// TODO: Auto-generated Javadoc
/**
 * Interface implemented by protocol headers that maintain a header and possibly
 * payload checksums.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JHeaderChecksum {

	/**
	 * Retrieves the header's checksum.
	 * 
	 * @return header's stored checksum
	 */
	public int checksum();

	/**
	 * Calculates a checksum using protocol specification for a header. Checksums
	 * for partial headers or fragmented packets (unless the protocol alows it)
	 * are not calculated.
	 * 
	 * @return header's calculated checksum
	 */
	public int calculateChecksum();

	/**
	 * Validates the header's data against the stored checksum. Checksums for
	 * partial headers or fragmented packets (unless the protocol alows it) are
	 * not validated and true is always returned.
	 * 
	 * @return Calculates a checksum and validates it against the store checksum
	 *         in the header. If checksums match or header is a fragment true is
	 *         returned, otherwise if the checksums don't match false is returned.
	 */
	public boolean isChecksumValid();

}
