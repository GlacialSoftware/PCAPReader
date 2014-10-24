package com.glacialsoftware.pcapreader;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import android.app.Activity;
import android.app.Fragment;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.TextView;

public class PcapOpenFragment extends Fragment {
	
	private static ScanListAdapter scanListAdapter=null;
	private static TextView scanning;
	private ListView listView;
	
	public interface PcapOpenCallbacks{
		public void openFile(String path);
		public boolean getFirstScan();
		public void setFirstScan(boolean firstScan);
		public int getFirstVisiblePosition();
	}
	
	private PcapOpenCallbacks pcapOpenCallbacks;
	
	private static List<PcapScanTask> pcapScanTasks= new ArrayList<PcapScanTask>();
	private static int nScanTasksFinished=0;
	
	private class PcapScanTask extends AsyncTask<File,File,Boolean>{
	
		private String pcapExtension=".pcap";

		protected void onProgressUpdate(File... files){
			if (!isCancelled()){
				if (!PcapOpenActivity.scanResults.contains(files[0])){
					PcapOpenActivity.scanResults.add(files[0]);
					PcapOpenFragment.scanListAdapter.notifyDataSetChanged();
				}
			}
		}

		protected Boolean doInBackground(File...files){	
			try{
				recursiveScan(files[0]);
			} catch (Exception e){}
			
			return true;
		}
		
		protected void onPreExecute(){
			scanning.setText("Sanning for network capture files...");
			PcapOpenActivity.isScanning=true;
		}
		
		protected void onPostExecute(Boolean code){
			++nScanTasksFinished;
			
			if (nScanTasksFinished>=pcapScanTasks.size()){
				PcapOpenFragment.scanning.setText("Capture files found:");
				PcapOpenActivity.isScanning=false;
			}
		}
		
		private boolean recursiveScan(File directory){
			if (isCancelled()){
				return false;
			}

			ArrayList<File> subDirectories=new ArrayList<File>();
			File[] files=directory.listFiles();
			
			if (files !=null){
				for (File file : files){
					if (isCancelled()){
						return false;
					}
					if (file.isDirectory()){
						subDirectories.add(file);
					}
					else if (file.getName().endsWith(pcapExtension)){
						publishProgress(file);
					}
				}
			} 
			
			for (File file : subDirectories){
				try{
					if (!recursiveScan(file)){
						return false;
					}
				} catch (Exception e){}
			}
			
			return true;
		}
	}
	
	@Override
	public void onAttach(Activity activity) {
		super.onAttach(activity);
		
		pcapOpenCallbacks = (PcapOpenCallbacks) activity;
	}
	
	@Override
	public void onCreate (Bundle savedInstanceState){
		super.onCreate(savedInstanceState);
		
		scanListAdapter=new ScanListAdapter(getActivity(),R.layout.item_scan_list,PcapOpenActivity.scanResults);
	}

	@Override
	public View onCreateView(LayoutInflater inflater,ViewGroup container, Bundle savedInstanceState){
		View view = inflater.inflate(R.layout.fragment_pcap_open, container,false);
		
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
		
		scanning=(TextView)getActivity().findViewById(R.id.scanning);
		if (PcapOpenActivity.isScanning){
			scanning.setText("Sanning for network capture files...");
		} else {
			scanning.setText("Capture files found:");
		}
		
        listView = (ListView) getView().findViewById(R.id.scanListView);
        
        //listView.setBackgroundColor(0xFFFFFFFF);
        
        listView.setAdapter(scanListAdapter);
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {

    	     public void onItemClick(AdapterView<?> parentAdapter, View view, int position,
    	                             long id) {
    	    	 
    	    	 pcapOpenCallbacks.openFile(((File)scanListAdapter.getItem(position)).getPath());
    	     }
    	});
        listView.setSelection(pcapOpenCallbacks.getFirstVisiblePosition());
        
        if (!pcapOpenCallbacks.getFirstScan()){
        	pcapScan(Environment.getExternalStorageDirectory());
        	pcapOpenCallbacks.setFirstScan(true);
        }
	}
	
	public void pcapScanCancel(int task){
		if (task==-1){
			int count=pcapScanTasks.size();
			for (int i=0;i<count;++i)
				pcapScanCancel(i);
		} else {
			try{
				pcapScanTasks.get(task).cancel(true);
			} catch (Exception e){}
		}
	}
	
	public int getFirstVisiblePosition(){
		return listView.getFirstVisiblePosition();
	}
	
	public void pcapScan(File directory){
		
		PcapScanTask pcapScanTask=new PcapScanTask();
		pcapScanTasks.add(pcapScanTask);

		pcapScanTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, directory);
	}
	
}
