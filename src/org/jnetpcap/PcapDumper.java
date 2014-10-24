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
package org.jnetpcap;

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * Class peered with native <code>pcap_dumper</code> structure. A dumper that
 * allows a previously opened pcap session to be dumped to a "savefile" which is
 * a file containing captured packets in pcap file format. To get an object of
 * type PcapDumper, use method <code>Pcap.dumpOpen</code>.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapDumper {

	/** The physical. */
	private volatile long physical;

	/**
	 * Inits the i ds.
	 */
	private static native void initIDs();

	static {
		initIDs();
	}

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop().
	 * 
	 * @param hdr
	 *          pcap capture header
	 * @param packet
	 *          packet buffer
	 * @deprecated use of PcapPktHdr has been replaced by PcapHeader
	 * @see PcapHeader
	 */
	public void dump(PcapPktHdr hdr, ByteBuffer packet) {
		dump(hdr.getSeconds(), hdr.getUseconds(), hdr.getCaplen(), hdr.getLen(),
		    packet);
	}

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop().
	 * 
	 * @param hdr
	 *          pcap capture header
	 * @param packet
	 *          packet buffer
	 * @since 1.2
	 */
	public native void dump(PcapHeader hdr, ByteBuffer packet);

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop().
	 * 
	 * @param hdr
	 *          pcap capture header
	 * @param packet
	 *          packet buffer
	 * @since 1.2
	 */
	public native void dump(PcapHeader hdr, JBuffer packet);

	/**
	 * Outputs a packet to the "savefile" opened with <code>dumpOpen</code>.
	 * Note that the calling arguments are suitable for use with dipstach() or
	 * loop(). This a convenience method, which takes the parameters of PcapPkthdr
	 * class directly.
	 * 
	 * @param seconds
	 *          timestamp in seconds
	 * @param useconds
	 *          timestamp fraction in microseconds
	 * @param caplen
	 *          how much was captured
	 * @param len
	 *          actual packet length on wire
	 * @param packet
	 *          packet buffer
	 */
	public native void dump(long seconds, int useconds, int caplen, int len,
	    ByteBuffer packet);

	/**
	 * Returns the current file position for the "savefile", representing the
	 * number of bytes written by <code>Pcap.dumpOpen</code> and
	 * <code>Pcap.dump</code>.
	 * 
	 * @return position within the file, or -1 on error
	 */
	public native long ftell();

	/**
	 * Flushes the output buffer to the "savefile", so that any packets written
	 * with <code>Pcap.dump</code> but not yet written to the "savefile" will be
	 * written.
	 * 
	 * @return 0 on success, -1 on error
	 */
	public native int flush();

	/**
	 * Closes a savefile. The existing PcapDumper object on which close method was
	 * invoked is no longer usable and needs to be discarded.
	 */
	public native void close();

}
