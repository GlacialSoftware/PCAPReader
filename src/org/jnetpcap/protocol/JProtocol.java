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
package org.jnetpcap.protocol;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.lan.IEEESnap;
import org.jnetpcap.protocol.lan.SLL;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtp;
import org.jnetpcap.protocol.voip.Sdp;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.vpn.L2TP;
import org.jnetpcap.protocol.wan.PPP;

// TODO: Auto-generated Javadoc
/**
 * Enum table of core protocols supported by the scanner.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum JProtocol {
	
	/**
	 * Builtin header type that encapsulates the portion of the packet buffer not
	 * matched by any protocol header.
	 */
	PAYLOAD(Payload.class),

	/** DIX Ethernet2 header. */
	ETHERNET(Ethernet.class, PcapDLT.EN10MB),

	/** Ip version 4 header. */
	IP4(Ip4.class),

	/** Ip version 6 header. */
	IP6(Ip6.class),

	/** TCP/IP header. */
	TCP(Tcp.class),

	/** UDP/IP header. */
	UDP(Udp.class),

	/**
	 * IEEE 802.3 header type
	 */
	IEEE_802DOT3(IEEE802dot3.class, PcapDLT.IEEE802),

	/** IEEE LLC2 header. */
	IEEE_802DOT2(IEEE802dot2.class),

	/** IEEE SNAP header. */
	IEEE_SNAP(IEEESnap.class),

	/** IEEE VLAN tag header. */
	IEEE_802DOT1Q(IEEE802dot1q.class),

	/** Layer 2 tunneling protocol header. */
	L2TP(L2TP.class),

	/** Point to Point Protocol header. */
	PPP(PPP.class, PcapDLT.PPP),

	/** Internet Control Message Protocol header. */
	ICMP(Icmp.class),

	/** Hyper Text Transmission Protocol header. */
	HTTP(Http.class),

	/** Hyper Text Markup Language header. */
	HTML(Html.class),

	/** An Image header transmitted via http. */
	WEB_IMAGE(WebImage.class),
	
	/** Address Resolution Protocol. */
	ARP(Arp.class),
	
	/** Session Intiation Protocol. */
	SIP(Sip.class),
	
	/** Session Data Protocol. */
	SDP(Sdp.class),
	
	/** Realtime Transfer Protocol. */
	RTP(Rtp.class),
	
	/** Linux cooked sockets. */
	SLL(SLL.class, PcapDLT.LINUX_SLL),
	
	;

	/**
	 * A protocol suite. Meta data interface that provides general category for
	 * the protocol as a family of related protocols.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface Suite {

		/**
		 * Retrieves the name of the protocol suite.
		 * 
		 * @return name of the protocol family
		 */
		public String name();
	}

	/** Unique ID of this protocol. */
	private final int ID;

	/** Main class for the network header of this protocol. */
	private Class<? extends JHeader> clazz;

	/** The class name. */
	private final String className;

	/**
	 * A header scanner that capable of scanning this protocol. All protocols
	 * defined in JProtocol are bound to a direct native scanner. While it is
	 * possible to override this default using JRegistery with a custom scanner.
	 */

	/**
	 * A mapping to pcap dlt. If no mapping exists for a protocol, it is null.
	 */
	private final PcapDLT[] dlt;

	/** The Constant PAYLOAD_ID. */
	public final static int PAYLOAD_ID = 0;

	/** The Constant ETHERNET_ID. */
	public final static int ETHERNET_ID = 1;

	/** The Constant IP4_ID. */
	public final static int IP4_ID = 2;

	/** The Constant IP6_ID. */
	public final static int IP6_ID = 3;

	/** The Constant TCP_ID. */
	public final static int TCP_ID = 4;

	/** The Constant UDP_ID. */
	public final static int UDP_ID = 5;

	/** The Constant IEEE_802DOT3_ID. */
	public final static int IEEE_802DOT3_ID = 6;

	/** The Constant IEEE_802DOT2_ID. */
	public final static int IEEE_802DOT2_ID = 7;

	/** The Constant IEEE_SNAP_ID. */
	public final static int IEEE_SNAP_ID = 8;

	/** The Constant IEEE_802DOT1Q_ID. */
	public final static int IEEE_802DOT1Q_ID = 9;

	/** The Constant L2TP_ID. */
	public final static int L2TP_ID = 10;

	/** The Constant PPP_ID. */
	public final static int PPP_ID = 11;

	/** The Constant ICMP_ID. */
	public final static int ICMP_ID = 12;

	/** The Constant HTTP_ID. */
	public final static int HTTP_ID = 13;

	/** The Constant HTML_ID. */
	public final static int HTML_ID = 14;

	/** The Constant WEB_IMAGE_ID. */
	public final static int WEB_IMAGE_ID = 15;
	
	/** The Constant ARP_ID. */
	public final static int ARP_ID = 16;
	
	/** The Constant SIP_ID. */
	public final static int SIP_ID = 17;

	/** The Constant SDP_ID. */
	public final static int SDP_ID = 18;

	/** The Constant RTP_ID. */
	public final static int RTP_ID = 19;
	
	/** The Constant SLL_ID. */
	public final static int SLL_ID = 20;
	
	/** The Constant LAST_ID. */
	public final static int LAST_ID = JProtocol.values().length;

	/**
	 * Instantiates a new j protocol.
	 * 
	 * @param className
	 *          the class name
	 */
	private JProtocol(String className) {
		this(className, new PcapDLT[0]);
	}

	/**
	 * Instantiates a new j protocol.
	 * 
	 * @param c
	 *          the c
	 */
	private JProtocol(Class<? extends JHeader> c) {
		this(c, new PcapDLT[0]);
	}

	/**
	 * Instantiates a new j protocol.
	 * 
	 * @param c
	 *          the c
	 * @param dlt
	 *          the dlt
	 */
	private JProtocol(Class<? extends JHeader> c, PcapDLT... dlt) {
		this.clazz = c;
		this.className = c.getCanonicalName();
		this.dlt = dlt;
		this.ID = ordinal();
	}

	/**
	 * Instantiates a new j protocol.
	 * 
	 * @param className
	 *          the class name
	 * @param dlt
	 *          the dlt
	 */
	private JProtocol(String className, PcapDLT... dlt) {
		this.className = className;
		this.dlt = dlt;
		this.ID = ordinal();

		if (getClass().getResource(className) == null) {
			throw new IllegalStateException("unable to find class " + className);
		}
	}

	/**
	 * Gets the header class.
	 * 
	 * @return the header class
	 */
	@SuppressWarnings("unchecked")
	public Class<? extends JHeader> getHeaderClass() {
		if (this.clazz == null) {
			try {
				this.clazz = (Class<? extends JHeader>) Class.forName(className);
			} catch (ClassNotFoundException e) {
				throw new IllegalStateException(e);
			}
		}

		return this.clazz;
	}

	/**
	 * Gets the header class name.
	 * 
	 * @return the header class name
	 */
	public String getHeaderClassName() {
		return this.className;
	}

	/**
	 * Checks the supplied ID if its is one of jNetPcap's core protocol set.
	 * 
	 * @param id
	 *          numerical ID of the header as assigned by JRegistry
	 * @return true if header is part of the core protocol set otherwise false
	 */
	public static boolean isCoreProtocol(int id) {
		return id < values().length;
	}

	/**
	 * Checks the supplied header by class if its is one of jNetPcap's core
	 * protocol set.
	 * 
	 * @param c
	 *          class name of the header to check
	 * @return true if header is part of the core protocol set otherwise false
	 */
	public static boolean isCoreProtocol(Class<? extends JHeader> c) {
		return (valueOf(c) == null) ? false : true;
	}

	/**
	 * Converts a protocol header to a JPRotocol constant.
	 * 
	 * @param c
	 *          header class to convert
	 * @return an enum constant or null if class is not part of the core protocol
	 *         set
	 */
	public static JProtocol valueOf(Class<? extends JHeader> c) {
		for (JProtocol p : values()) {
			if (p.clazz == c) {
				return p;
			}
		}

		return null;
	}

	/**
	 * Converts a protocol header to a JPRotocol constant.
	 * 
	 * @param id
	 *          numerical ID of the header assigned by JRegistry
	 * @return an enum constant or null if class is not part of the core protocol
	 *         set
	 */
	public static JProtocol valueOf(int id) {
		if (id >= values().length) {
			return null;
		}

		return values()[id];
	}

	/**
	 * Gets the numerical ID of the data link header for the open pcap handle. A
	 * call to Pcap.datalink() is made and the value translated to an appropriate
	 * jNetPcap protocol header ID.
	 * 
	 * @param pcap
	 *          open Pcap handle
	 * @return enum constant or the Payload header as the catch all if no headers
	 *         are matched
	 */
	public static JProtocol valueOf(Pcap pcap) {
		return valueOf(PcapDLT.valueOf(pcap.datalink()));
	}

	/**
	 * Gets the numerical ID of the data link header for supplied pcap dlt
	 * constant. A call to Pcap.datalink() is made and the value translated to an
	 * appropriate jNetPcap protocol header ID.
	 * 
	 * @param dlt
	 *          pcap dlt constant
	 * @return enum constant or the Payload header as the catch all if no headers
	 *         are matched
	 */
	public static JProtocol valueOf(PcapDLT dlt) {
		if (dlt == null) {
			return PAYLOAD;
		}

		for (JProtocol p : values()) {

			for (PcapDLT d : p.dlt) {
				if (dlt == d) {
					return p;
				}
			}
		}

		return PAYLOAD; // Not found
	}

	/**
	 * Gets the corresponding Pcap defined Data Link Type.
	 * 
	 * @return the dlt dlt for this protocol
	 */
	public PcapDLT[] getDlt() {
		return dlt;
	}

	/**
	 * Gets a unique runtime numerica ID of this protocol assigned by jNetStream.
	 * 
	 * @return the protocol id
	 */
	public int getId() {
		return ID;
	}

	/**
	 * Gets the main class for the network header of this protocol.
	 * 
	 * @return the main class for the network header of this protocol
	 */
	public final Class<? extends JHeader> getClazz() {
  	return this.clazz;
  }

}