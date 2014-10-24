package com.glacialsoftware.pcapreader;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.PcapPacket;

import pl.polidea.treeview.InMemoryTreeStateManager;
import pl.polidea.treeview.TreeBuilder;
import pl.polidea.treeview.TreeStateManager;
import pl.polidea.treeview.TreeViewList;
import android.app.Activity;
import android.app.Fragment;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;


public class PacketDetailsFragment extends Fragment {

	TreeViewList treeViewList = null;
	private AnalyzePacketTask analyzePacketTask=null;
	
	private long referenceEpochTime=0;
	
	private class AnalyzePacketTask extends AsyncTask<Void,Void,Integer>{
		
		private Activity activity=null;
		private int frameNumber;
		private PcapPacket pcapPacket;
		PacketTreeAdapter packetTreeAdapter;
		
		public AnalyzePacketTask(Activity activity, PcapPacket pcapPacket, int frameNumber){
			this.activity=activity;
			this.pcapPacket=pcapPacket;
			this.frameNumber=frameNumber;
		}
		
		protected Integer doInBackground(Void...params){
			try{
				List<String> lines = new ArrayList<String>();
				TreeStateManager<Integer> treeStateManager=new InMemoryTreeStateManager<Integer>();
				TreeBuilder<Integer> treeBuilder = new TreeBuilder<Integer>(treeStateManager);
	
				PacketFormatter packetFormatter = new PacketFormatter(new StringBuilder(),treeBuilder,lines);
				int maxLevel=packetFormatter.analyzePacket(pcapPacket, referenceEpochTime);
				
				packetTreeAdapter= new PacketTreeAdapter(activity, treeStateManager,maxLevel+1,R.layout.item_packet_tree,lines);
			} catch (Exception e){
				e.printStackTrace();
				return -1;
			}
			return 0;
		}
		
		protected void onPostExecute(Integer code){
			if (code==-1){
				return;
			}
			treeViewList.setAdapter(packetTreeAdapter);
		}
}
	
	
	@Override
	public void onCreate (Bundle savedInstanceState){
		super.onCreate(savedInstanceState);
		
	}

	@Override
	public View onCreateView(LayoutInflater inflater,ViewGroup container, Bundle savedInstanceState){
		View view = inflater.inflate(R.layout.fragment_packet_details, container,false);
	
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
	   
       treeViewList = (TreeViewList) getView().findViewById(R.id.packetTreeView);
	}
	
	public void setReferenceEpochTime(long time){
		referenceEpochTime=time;
	}
	
	public void analyzePacket(PcapPacket pcapPacket, int position){
		if (pcapPacket==null){
			return;
		}
		
		try{
			analyzePacketTask.cancel(true);
		} catch (Exception e){}
		
		PcapFileLoader.detailsPacketPosition=position;
		PcapFileLoader.detailsPacket=pcapPacket;
		
		analyzePacketTask = new AnalyzePacketTask(getActivity(), pcapPacket, position+1);
		analyzePacketTask.executeOnExecutor(AsyncTask.SERIAL_EXECUTOR);
	}
	
	
}
