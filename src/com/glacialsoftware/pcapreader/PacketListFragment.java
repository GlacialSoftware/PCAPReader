
package com.glacialsoftware.pcapreader;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import android.app.Activity;
import android.app.Fragment;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ListView;




public class PacketListFragment extends Fragment {
	
	public PacketListAdapter packetListAdapter=null;
	private ListView listView=null;
	
	private JHeaderPool headerPool = new JHeaderPool();
	private long referenceEpochTime=0;
	private int firstVisiblePosition=0;
	
	public interface PacketListCallbacks{
		public void onPacketSelected(int position);
		public boolean filteredOut(PcapPacket packet);
	}
	
	private PacketListCallbacks packetListCallbacks;
	
	@Override
	public void onAttach(Activity activity) {
		super.onAttach(activity);
		
		packetListCallbacks = (PacketListCallbacks) activity;
	}
	
	@Override
	public void onCreate (Bundle savedInstanceState){
		super.onCreate(savedInstanceState);
		
		packetListAdapter =new PacketListAdapter(PcapFileLoader.nPackets.value, getActivity(), R.layout.item_packet_list, this);
		PcapFileLoader.packetListAdapter=packetListAdapter;
	}

	@Override
	public View onCreateView(LayoutInflater inflater,ViewGroup container, Bundle savedInstanceState){
		View view = inflater.inflate(R.layout.fragment_packet_list, container,false);
		
        TypedValue typedValue = new TypedValue();
        getActivity().getTheme().resolveAttribute(android.R.attr.windowBackground, typedValue, true);
        
        if (typedValue.type >= TypedValue.TYPE_FIRST_COLOR_INT && typedValue.type <= TypedValue.TYPE_LAST_COLOR_INT) {
            int backgroundColor = typedValue.data;
            view.setBackgroundColor(backgroundColor);
            
        } else {
            Drawable drawable = getActivity().getResources().getDrawable(typedValue.resourceId);
            view.setBackgroundDrawable(drawable);
        }

        return view;
    }
	
		
	@Override
	public void onStart (){
		super.onStart();
		
        listView = (ListView) getView().findViewById(R.id.packetListView);
        
        listView.setAdapter(packetListAdapter);
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {

    	     public void onItemClick(AdapterView<?> parentAdapter, View view, int position,
    	                             long id) {
    	    	 
    	    	 packetListCallbacks.onPacketSelected(position);
    	    	 
    	     }
    	});
        listView.setSelection(firstVisiblePosition);
	}
	
	public void setReferenceEpochTime(long time){
		referenceEpochTime=time;
	}
	
	public void setFirstVisiblePosition(int firstVisiblePosition){
		this.firstVisiblePosition=firstVisiblePosition;
	}
	
	public int getFirstVisiblePosition(){
		return listView.getFirstVisiblePosition();
	}
	
	public PacketListItem summarizePacket(PcapPacket packet, int position){
		PacketListItem packetListItem = new PacketListItem();
		
		packetListItem.setFrameNumber(position+1);
		packetListItem.setLength(packet.getPacketWirelen());
		
		double timeSinceReference= (double)(packet.getCaptureHeader().timestampInNanos()-referenceEpochTime)/1000000000.0;
		packetListItem.setTimeSinceReference(timeSinceReference);
				
		String source="";
		String destination="";
		
		if (packet.hasHeader(JProtocol.IP4_ID)){
			final int index = packet.getState().findHeaderIndex(JProtocol.IP4_ID, 0);
			final Ip4 ip4=headerPool.getHeader(Ip4.class,JProtocol.IP4_ID);
			packet.getHeaderByIndex(index, ip4);
			source=FormatUtils.ip(ip4.source());
			destination=FormatUtils.ip(ip4.destination());
		}
		else if(packet.hasHeader(JProtocol.IP6_ID)){
			final int index = packet.getState().findHeaderIndex(JProtocol.IP6_ID, 0);
			final Ip6 ip6=headerPool.getHeader(Ip6.class,JProtocol.IP6_ID);
			packet.getHeaderByIndex(index, ip6);
			source=FormatUtils.asStringIp6(ip6.source(), false);
			destination=FormatUtils.asStringIp6(ip6.destination(), false);
		}
		else if(packet.hasHeader(JProtocol.ETHERNET_ID)){
			final int index = packet.getState().findHeaderIndex(JProtocol.ETHERNET_ID, 0);
			final Ethernet ethernet=headerPool.getHeader(Ethernet.class, JProtocol.ETHERNET_ID);
			packet.getHeaderByIndex(index, ethernet);
			source=FormatUtils.mac(ethernet.source());
			destination=FormatUtils.mac(ethernet.destination());
		}
		
		boolean tcpRstFlagSet=false;
		boolean tcpSynFlagSet=false;
		boolean tcpFinFlagSet=false;
		boolean tcpPort80=false;
		
		if (packet.hasHeader(JProtocol.TCP_ID)){
			final int index = packet.getState().findHeaderIndex(JProtocol.TCP_ID, 0);
			final Tcp tcp=headerPool.getHeader(Tcp.class,JProtocol.TCP_ID);
			packet.getHeaderByIndex(index, tcp);
			tcpRstFlagSet=tcp.flags_RST();
			tcpSynFlagSet=tcp.flags_SYN();
			tcpFinFlagSet=tcp.flags_FIN();
			final int tcpSourcePort=tcp.source();
			final int tcpDestinationPort=tcp.destination();
			tcpPort80= (tcpSourcePort == 80 || tcpDestinationPort == 80);
			source+=":"+Integer.toString(tcpSourcePort);
			destination+=":"+Integer.toString(tcpDestinationPort);
		}
		else if(packet.hasHeader(JProtocol.UDP_ID)){
			final int index = packet.getState().findHeaderIndex(JProtocol.UDP_ID, 0);
			final Udp udp=headerPool.getHeader(Udp.class,JProtocol.UDP_ID);
			packet.getHeaderByIndex(index, udp);
			source+=":"+Integer.toString(udp.source());
			destination+=":"+Integer.toString(udp.destination());
		}
		
		packetListItem.setSource(source);
		packetListItem.setDestination(destination);
		
		int highestIndex=packet.getHeaderCount()-1;
		if (packet.getHeaderIdByIndex(highestIndex)==JProtocol.PAYLOAD_ID && highestIndex>0){
			highestIndex--;
		}
		
		final int id = packet.getHeaderIdByIndex(highestIndex);
		final JHeader header = headerPool.getHeader(id);
		packet.getHeaderByIndex(highestIndex, header);

		packetListItem.setHighestProtocol(header.getName());

		if (tcpRstFlagSet){
			packetListItem.setColor(0xFFA40000);
		}
		else if (id==JProtocol.HTTP_ID || tcpPort80){
			packetListItem.setColor(0xFFE4FFC7);
		}
		else if (tcpSynFlagSet || tcpFinFlagSet){
			packetListItem.setColor(0xFFA0A0A0);
		}
		else if (id==JProtocol.TCP_ID){
			packetListItem.setColor(0xFFE7E5FF);
		}
		else if (id==JProtocol.UDP_ID){
			packetListItem.setColor(0xFFDAEEFF);
		}	
		else if (id==JProtocol.ARP_ID){
			packetListItem.setColor(0xFFFAF0D7);
		}
		else if (id==JProtocol.ICMP_ID){
			final Icmp icmp = (Icmp) header;
			final int type = icmp.type();
			if (type==3 || type==4 || type==5 || type==11){
				packetListItem.setColor(0xFF12272E);
			}
			else {
				packetListItem.setColor(0xFFFCE0FF);
			}
		}

		return packetListItem;
	}

	
}