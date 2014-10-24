package com.glacialsoftware.pcapreader;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;

import android.os.AsyncTask;
import android.util.Log;


public class PcapFileLoader {

	private static IntHolder blockLength;
	private static int blockLower;
	private static int blockUpper;
	private static boolean lengthFound=false;
	
	public static String filename=null;
	public static IntHolder nPackets;
	public static long referenceEpochTime;
	public static PcapPacket detailsPacket=null;
	public static int detailsPacketPosition;
	public static PacketListAdapter packetListAdapter=null;
	
	private static boolean[] notify={false,false};
	public static boolean[] indeterminate={true,true};
	private static IntHolder[][] range;
	private static Pcap[] pcap = {null,null};
	public static PcapPacket[][] pcapPackets;


	private static PcapBlockLoadTask[] pcapBlockLoadTask={null,null};
	private static PcapFindLengthTask pcapFindLengthTask=null;
	
	
	public static class IntHolder{
		public Integer value;
		public IntHolder(Integer value){
			this.value=value;
		}
	}
	
	private static class PcapFindLengthTask extends AsyncTask<Void,Integer,Integer>{
		
		private Pcap pcap=null;
		private IntHolder length;
		private IntHolder blockLength;
		
		protected void onPreExecute(){
			final StringBuilder errbuf = new StringBuilder();
			pcap =  Pcap.openOffline(filename, errbuf);
			blockLength=PcapFileLoader.blockLength;
			length = new IntHolder(0);
			lengthFound=false;
			nPackets=length;
		}
		
		protected Integer doInBackground(Void...params){

			JBufferHandler<IntHolder> bufferHandler = new JBufferHandler<IntHolder>() {  
	            public void nextPacket(PcapHeader header, JBuffer buffer, IntHolder length){
	            	++length.value;
	            }
			};
			
			int expectedValue=0;
			while (true){
				if (isCancelled()){
					return -1;
				}
				if (length.value!=expectedValue){
					return 0;
				}
				pcap.loop(blockLength.value, bufferHandler,length);
				expectedValue+=blockLength.value;
				publishProgress(0);
			}
		}
		
		protected void onProgressUpdate(Integer...integers){
			if (packetListAdapter!=null){
				packetListAdapter.setLength(length.value);
				packetListAdapter.notifyDataSetChanged();
			}
		}
		
		protected void onPostExecute(Integer result){
			lengthFound=true;
			pcap.close();
			Log.d("PcapFindLengthTask","Length is: "+Integer.toString(length.value));
		}
		
		protected void onCancelled(Integer result){
			pcap.close();
		}
	}
	
	private static class PcapBlockLoadTask extends AsyncTask<Void,Void,Integer>{
		
		private Pcap pcap = null;
		private IntHolder currentPacket;
		private IntHolder lowerBound;
		private IntHolder blockLength;
		private int block;
		private int targetPacket;
		private PcapPacket[] pcapPackets=null;
		
		public PcapBlockLoadTask(int block, int targetPacket){
			this.block=block;
			this.targetPacket=targetPacket;
		}
		
		protected void onPreExecute(){
			blockLength=PcapFileLoader.blockLength;
			pcapPackets=new PcapPacket[blockLength.value];
			PcapFileLoader.pcapPackets[block]=pcapPackets;
			lowerBound=new IntHolder(targetPacket);
			
			if (indeterminate[block] || targetPacket<= PcapFileLoader.range[block][1].value){
				if (!indeterminate[block]){
					PcapFileLoader.pcap[block].close();
				}
				JScanner.getThreadLocal().setFrameNumber(0);
				final StringBuilder errbuf=new StringBuilder();
				pcap =  Pcap.openOffline(filename, errbuf);
				currentPacket=new IntHolder(0);
				PcapFileLoader.pcap[block]=pcap;
				PcapFileLoader.range[block][1]=currentPacket;
			} else {
				pcap=PcapFileLoader.pcap[block];
				currentPacket=PcapFileLoader.range[block][1];
			}
			PcapFileLoader.range[block][0]=lowerBound;
			indeterminate[block]=true;
			Log.d("PcapBlockLoadTask", "loading block: "+Integer.toString(block)+"|"+Integer.toString(lowerBound.value));
		}
			
		protected void onPostExecute(Integer result){
			if (result==-1){
				pcap.close();
				reset(blockLength.value/2);
				if (packetListAdapter!=null){
					packetListAdapter.notifyDataSetChanged();
				}
			}
			else{
				indeterminate[block]=false;
				if (notify[block]){
					notify[block]=false;
					if (packetListAdapter!=null){
						packetListAdapter.notifyDataSetChanged();
					}
				}
			}
		}
		
		protected void onCancelled(Integer result){
			pcap.close();
		}
		
		protected Integer doInBackground(Void...params){
			if (seekToOffset(targetPacket-currentPacket.value)==-1){
				return -1;
			}
			
			return loadBlock();
		}
		
		private int loadBlock(){
			/*
			PcapPacketHandler<IntHolder> pcapPacketHandler = new PcapPacketHandler<IntHolder>() {

		            public void nextPacket(PcapPacket packet, IntHolder current) { 
		            	if (isCancelled()){
		            		pcap.breakloop();
		            	}
		            	pcapPackets[current.value%blockLength.value]=packet;
		            	++current.value;
		            }
			 };
			 */
			
			 try{
				 //pcap.loop(blockLength.value, pcapPacketHandler, currentPacket);

				 PcapPacket packet = new PcapPacket(JMemory.POINTER);
				 
				 for (int i=0;i<blockLength.value;++i){
			 		int code = pcap.nextEx(packet);
			 		if (code!=Pcap.NEXT_EX_OK){
			 			break;
			 		}
			 		pcapPackets[i]=new PcapPacket(packet);
			 		currentPacket.value++;
			 	}
			 } catch (OutOfMemoryError e){
				 Log.d("PcapBlockLoadTask", "OutOfMemoryError: current blockLength = "+Integer.toString(blockLength.value));
				 return -1;
			 }
			 
			 return 0;
		}
		
		private int seekToOffset(int offset){
			JBufferHandler<Integer> bufferHandler = new JBufferHandler<Integer>() {  
	            public void nextPacket(PcapHeader header, JBuffer buffer, Integer user){}
			};
			
			int loopCount = offset/blockLength.value;
			int remainder = offset%blockLength.value;
			
			for (int i=0;i<loopCount;++i){
				if (isCancelled()) {
					return -1;
				}
				pcap.loop(blockLength.value, bufferHandler, 0);
				currentPacket.value+=blockLength.value;
			}
			
			if (remainder!=0){
				pcap.loop(remainder, bufferHandler, 0);
				currentPacket.value+=remainder;
			}
			
			return 0;
		}
	}
	
	public static void reset(int blockLength){
		Log.d("PcapFileLoader","resetting loader, new blockLength = "+Integer.toString(blockLength));
		PcapFileLoader.blockLength=new IntHolder(blockLength);
		PcapFileLoader.blockLower=(blockLength*65)/100;
		PcapFileLoader.blockUpper=(blockLength*70)/100;
		
		notify[0]=false;
		notify[1]=false;
		
		indeterminate[0]=true;
		indeterminate[1]=true;
		
		range[0][0]=new IntHolder(-1);
		range[1][0]=new IntHolder(-1);
		range[0][1]=new IntHolder(0);
		range[1][1]=new IntHolder(0);
		
		pcap[0]=null;
		pcap[1]=null;
		
		pcapPackets = new PcapPacket[2][blockLength];
		for (int i=0;i<blockLength;++i){
			pcapPackets[0][i]=null;
			pcapPackets[1][i]=null;
		}
	}
	
	public static boolean setup(String filename, int blockLength){
		cancel(0);
		cancel(1);
		
		if (filename==null){
			return false;
		}
		
   	 	final StringBuilder errbuf = new StringBuilder();
   	 	Pcap pcap = Pcap.openOffline(filename,errbuf);
   	 	if (pcap==null){
   	 		return false;
   	 	}
   	 	
   	 	detailsPacketPosition=0;
   	 	
   	 	detailsPacket = new PcapPacket(JMemory.POINTER);
   	 	pcap.nextEx(detailsPacket);

		referenceEpochTime=detailsPacket.getCaptureHeader().timestampInNanos();
		pcap.close();
		
		PcapFileLoader.blockLength=new IntHolder(blockLength);
		PcapFileLoader.blockLower=(blockLength*65)/100;
		PcapFileLoader.blockUpper=(blockLength*70)/100;
		
		PcapFileLoader.filename=filename;

		findLength();
		
		packetListAdapter=null;
		
		pcapPackets = new PcapPacket[2][blockLength];
		for (int i=0;i<blockLength;++i){
			pcapPackets[0][i]=null;
			pcapPackets[1][i]=null;
		}
		
		PcapFileLoader.pcap[0]=null;
		PcapFileLoader.pcap[1]=null;
		
		notify[0]=false;
		notify[1]=false;

		indeterminate[0]=true;
		indeterminate[1]=true;
		
		range= new IntHolder[2][2];
		range[0][0]=new IntHolder(-1);
		range[1][0]=new IntHolder(-1);
		range[0][1]=new IntHolder(0);
		range[1][1]=new IntHolder(0);

		Log.d("setup","true");
		return true;
	}
	
	public static PcapPacket getIndex(int index){
		int lowerBound = (index/blockLength.value)*blockLength.value;
		int relativeIndex=index%blockLength.value;
		int currBlock;
		int altBlock;
		
		if (lowerBound==range[0][0].value){
			currBlock=0;
			altBlock=1;
		}
		else if (lowerBound==range[1][0].value){
			currBlock=1;
			altBlock=0;
		}
		else{
			currBlock=0;
			altBlock=1;
			loadBlock(currBlock, lowerBound);
		}
		
		if (indeterminate[currBlock]){
			notify[currBlock]=true;
		}
		
		if (relativeIndex<blockLower){
			int prevBlock=lowerBound-blockLength.value;
			if (range[altBlock][0].value!=prevBlock && prevBlock>=0){
				loadBlock(altBlock,prevBlock);
			}
		} 
		else if (relativeIndex > blockUpper){
			int nextBlock=lowerBound+blockLength.value;
			if (range[altBlock][0].value!=nextBlock && nextBlock<nPackets.value){
				loadBlock(altBlock,nextBlock);
			}
		}
		
		if (index<range[currBlock][1].value){
			return pcapPackets[currBlock][relativeIndex];
		} else {
			return null;
		}
	}
	
	public static void loadBlock(int block, int targetPacket){
		cancel(block);
		pcapBlockLoadTask[block]=new PcapBlockLoadTask(block, targetPacket);
		pcapBlockLoadTask[block].executeOnExecutor(AsyncTask.SERIAL_EXECUTOR);
	}
	
	private static void findLength(){
		try{
			pcapFindLengthTask.cancel(true);
		} catch (Exception e){}
		
		pcapFindLengthTask=new PcapFindLengthTask();
		pcapFindLengthTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
	}
	
	public static void cancel(int block){
		try{
			pcapBlockLoadTask[block].cancel(true);
		} catch (Exception e){}
	}
}
