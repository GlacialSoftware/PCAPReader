package com.glacialsoftware.pcapreader;

import java.util.Locale;

public class PacketListItem {
	
	private String frameNumber="";
	private String highestProtocol="";
	private String length="";
	private String timeSinceReference="";
	private String source="";
	private String destination="";
	private int color= 0xFFFFFFFF;
	
	public PacketListItem(){}
	
	public String getFrameNumber(){
		return frameNumber;
	}
	
	public String getHighestProtocol(){
		return highestProtocol;
	}
	
	public String getLength(){
		return length;
	}
	
	public String getTimeSinceReference(){
		return timeSinceReference;
	}
	
	public String getSource(){
		return source;
	}
	
	public String getDestination(){
		return destination;
	}
	
	public int getColor(){
		return color;
	}
	
	public void setFrameNumber(long frameNumber){
		this.frameNumber=Long.toString(frameNumber);
	}
	
	public void setHighestProtocol(String highestProtocol){
		this.highestProtocol = highestProtocol.toUpperCase(Locale.US);
	}
	
	public void setLength(int length){
		this.length="Len: "+Integer.toString(length);
	}
	
	public void setTimeSinceReference(double timeSinceReference){
		this.timeSinceReference=String.format("Time: %1$.6f",timeSinceReference);
	}
	
	public void setSource(String source){
		this.source="S: "+source;
	}
	
	public void setDestination(String destination){
		this.destination ="D: "+destination;
	}
	
	public void setColor(int color){
		this.color=color;
	}
	
	public static PacketListItem loading(){
		PacketListItem packetListItem= new PacketListItem();
		packetListItem.source="LOADING";
		return packetListItem;
	}

}

