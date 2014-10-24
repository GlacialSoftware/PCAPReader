package com.glacialsoftware.pcapreader;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;

import com.glacialsoftware.pcapreader.PcapFileLoader.IntHolder;

import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

public class PacketListAdapter extends BaseAdapter{

	private Context context;
	private int resource;
	private int length;
	PacketListFragment packetListFragment;
	
	static class ViewHolder{
		TextView frameNumber;
		TextView highestProtocol;
		TextView length;
		TextView timeSinceReference;
		TextView source;
		TextView destination;
	}
	
	public PacketListAdapter(int length, Context context, int resource, PacketListFragment packetListFragment){
		this.length=length;
		this.context=context;
		this.resource=resource;
		this.packetListFragment=packetListFragment;
	}
	
	public View getView(int position, View convertView, ViewGroup parent){
		ViewHolder viewHolder;
		
		if (convertView==null){
			convertView= LayoutInflater.from(context).inflate(resource, parent, false);
			
			viewHolder = new ViewHolder();
			viewHolder.frameNumber=(TextView) convertView.findViewById(R.id.frameNumber);
			viewHolder.highestProtocol=(TextView) convertView.findViewById(R.id.highestProtocol);
			viewHolder.length=(TextView) convertView.findViewById(R.id.length);
			viewHolder.timeSinceReference=(TextView) convertView.findViewById(R.id.timeSinceReference);
			viewHolder.source=(TextView) convertView.findViewById(R.id.source);
			viewHolder.destination=(TextView) convertView.findViewById(R.id.destination);
			
			convertView.setTag(viewHolder);
		} else {
			viewHolder=(ViewHolder) convertView.getTag();
		}
		
		PacketListItem packetListItem=(PacketListItem) getItem(position);
		
		viewHolder.frameNumber.setText(packetListItem.getFrameNumber());
		viewHolder.highestProtocol.setText(packetListItem.getHighestProtocol());
		viewHolder.length.setText(packetListItem.getLength());
		viewHolder.timeSinceReference.setText(packetListItem.getTimeSinceReference());
		viewHolder.source.setText(packetListItem.getSource());
		viewHolder.destination.setText(packetListItem.getDestination());
		convertView.setBackgroundColor(packetListItem.getColor());
		
		return convertView;
	}


	@Override
	public int getCount() {
		return length;
	}
	
	public PcapPacket p0;
	public PcapPacket p1;
	public boolean p1done=false;
	public boolean hasrun0=false;
	public boolean hasrun1=false;
	PacketListAdapter pla = this;

	@Override
	public Object getItem(int position) {
		/*
		if (position==0){
			
			
			Runnable r0 = new Runnable(){

				@Override
				public void run() {
					PcapPacketHandler<IntHolder> pcapPacketHandler = new PcapPacketHandler<IntHolder>() {  
			            public void nextPacket(PcapPacket packet, IntHolder current) { 
			            	
			            	p0=packet;
			            	++current.value;
			            }
				 };

				final StringBuilder errbuf = new StringBuilder();
		   	 	Pcap pcap = Pcap.openOffline(PcapFileLoader.filename,errbuf);
		   	 	while (!p1done){}
				//pcap.loop(1, pcapPacketHandler, new IntHolder(0));
		   	 	PcapPacket p = new PcapPacket(JMemory.POINTER);
		   	 	pcap.nextEx(p);
		   	 	p0=p;
					
				Log.d("r0","done");
			}};
			
			
			if (!hasrun0){
				Thread thread = new Thread(r0);
				thread.start();
				hasrun0=true;
			}
			
			if (p1done && p0!=null){
				return packetListFragment.summarizePacket(p0, 0);
			} else {
				return PacketListItem.loading();
			}
		}
			
		else if (position == 1){
			Runnable r1 = new Runnable(){

				@Override
				public void run() {
					PcapPacketHandler<IntHolder> pcapPacketHandler = new PcapPacketHandler<IntHolder>() {  
			            public void nextPacket(PcapPacket packet, IntHolder current) { 

			            	p1=packet;
			            	++current.value;
			            }
				 };

				final StringBuilder errbuf = new StringBuilder();
		   	 	Pcap pcap = Pcap.openOffline(PcapFileLoader.filename,errbuf);
				//pcap.loop(1, pcapPacketHandler, new IntHolder(0));
		   	 	PcapPacket p = new PcapPacket(JMemory.POINTER);
		   	 	pcap.nextEx(p);
		   	 	p1=p;
				p1done=true;
				Log.d("r1","done");
				
			}};
			if (!hasrun1){
				Thread thread = new Thread(r1);
				thread.start();
				hasrun1=true;
			}
			
			if (p1done && p1!=null){
				return packetListFragment.summarizePacket(p1, 1);
			} else {
				return PacketListItem.loading();
			}
		}
		
		if (position==5){
			if (p0!=null){
				PacketListItem pl0 = packetListFragment.summarizePacket(p0, 0);
				Log.d("p0",pl0.getTimeSinceReference());
			} else { Log.d("p0","null"); }
			if (p1!=null){
				PacketListItem pl1 = packetListFragment.summarizePacket(p1, 0);
				Log.d("p1",pl1.getTimeSinceReference());
			} else { Log.d("p1","null"); }
		}
			
			*/
			/*
			final StringBuilder errbuf = new StringBuilder();
	   	 	Pcap pcap = Pcap.openOffline(PcapFileLoader.filename,errbuf);
	   	 	if (pcap==null){
	   	 		Log.d("getItem_0","pcap==null");
	   	 	}
	   	 	
	   	 	PcapPacket pc = new PcapPacket(JMemory.POINTER);
	   	 	pcap.nextEx(pc);
	   	 	if (position==1){
	   	 		pc=new PcapPacket(JMemory.POINTER);
	   	 		pcap.nextEx(pc);
	   	 	}
	   	 	PcapFileLoader.pcapPackets[0][0]=pc;
	   	 	packetListFragment.packetListAdapter.notifyDataSetChanged();
	   	 	
	   	 	Log.d("PC", Boolean.toString(pc.hasHeader(JProtocol.ETHERNET_ID)));
	   	 	return packetListFragment.summarizePacket(pc, 0);
		}*/
		
		PcapPacket pcapPacket= PcapFileLoader.getIndex(position);
		if (pcapPacket==null){
			return PacketListItem.loading();
		}
		return packetListFragment.summarizePacket(pcapPacket,position);
	}

	@Override
	public long getItemId(int position) {
		return position;
	}
	
	public void setLength(int length){
		this.length=length;
	}
}

