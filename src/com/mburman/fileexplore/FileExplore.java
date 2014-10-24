package com.mburman.fileexplore;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import com.glacialsoftware.pcapreader.R;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Dialog;
import android.app.DialogFragment;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

/*
>   Copyright 2011 Manish Burman

>  Licensed under the Apache License, Version 2.0 (the "License");
>  you may not use this file except in compliance with the License.
>  You may obtain a copy of the License at

>      http://www.apache.org/licenses/LICENSE-2.0

>   Unless required by applicable law or agreed to in writing, software
>   distributed under the License is distributed on an "AS IS" BASIS,
>   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
>   See the License for the specific language governing permissions and
>   limitations under the License.

 */

/* This file has been modified:
 * 		>The original code has been adapted from an Activity with a Dialog to a DialogFragment.
 * 		    Various structural changes have been made to accommodate this change, including, but
 *   		not limited to: changing 'adapter' variable to be modified in place rather than being replaced,
 *   		changing onCreateDialog(int) to onCreateDialog(Bundle), removing removeDialog and showDialog
 *   		calls from click listener code, creating ListView and setting as dialog's View instead of calling setAdapter
 *   		with DialogInterface and moving on click code to the ListView's click listener.
 *   	> A callback interface has been added for communication with parent activity.
 *   	> Code has been added to handle file selection event.
 *    	> FilenameFilter has been modified to accept only files with '.pcap' extension
 *    	> Code has been added to force directories to display above files
 *    	> Call to Arrays.sort() added so dirs/files display in alphabetical order
 */


public class FileExplore extends DialogFragment {

	// Stores names of traversed directories
	ArrayList<String> str = new ArrayList<String>();

	// Check if the first level of the directory structure is the one showing
	private Boolean firstLvl = true;

	private static final String TAG = "F_PATH";

	private Item[] fileList;
	private File path = new File(Environment.getExternalStorageDirectory() + "");
	private String chosenFile;
	
	public interface FileExploreCallbacks{
		public void fileSelected(File path, FileExplore fileExplore);
	}
	
	private FileExploreCallbacks fileExploreCallbacks;
	private FileExplore fileExplore;
	
	ArrayAdapter<Item> adapter;
	
	public FileExplore(){}
	
	@Override
	public void onAttach(Activity activity) {
		super.onAttach(activity);
		
		fileExploreCallbacks = (FileExploreCallbacks) activity;
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {

		super.onCreate(savedInstanceState);
		
		fileExplore=this;
		
		adapter = new ArrayAdapter<Item>(getActivity(),
				android.R.layout.select_dialog_item, android.R.id.text1) {
			@Override
			public View getView(int position, View convertView, ViewGroup parent) {
				// creates view
				View view = super.getView(position, convertView, parent);
				TextView textView = (TextView) view
						.findViewById(android.R.id.text1);

				// put the image on the text view
				textView.setCompoundDrawablesWithIntrinsicBounds(
						fileList[position].icon, 0, 0, 0);

				// add margin between image and text (support various screen
				// densities)
				int dp5 = (int) (5 * getResources().getDisplayMetrics().density + 0.5f);
				textView.setCompoundDrawablePadding(dp5);

				return view;
			}
		};
		
		loadFileList();

		Log.d(TAG, path.getAbsolutePath());
	}

	public void loadFileList() {
		try {
			path.mkdirs();
		} catch (SecurityException e) {
			Log.e(TAG, "unable to write on the sd card ");
		}

		// Checks whether path exists
		if (path.exists()) {
			FilenameFilter filter = new FilenameFilter() {
				@Override
				public boolean accept(File dir, String filename) {
					File sel = new File(dir, filename);
					// Filters based on whether the file is hidden or not
					boolean pcapFile=false;
					if (sel.isFile() && sel.getPath().toLowerCase(Locale.US).endsWith(".pcap")){
						pcapFile=true;
					}
					return (pcapFile || sel.isDirectory())
							&& !sel.isHidden();

				}
			};

			String[] fList = path.list(filter);
			if (fList==null){
				fList=new String[0];
			}
			Arrays.sort(fList);
			fileList = new Item[fList.length];
			
			List<Item> dirsOnly = new ArrayList<Item>();
			List<Item> filesOnly = new ArrayList<Item>();
			
			for (int i = 0; i < fList.length; i++) {
				Item item = new Item(fList[i], R.drawable.file_icon);

				// Convert into file path
				File sel = new File(path, fList[i]);

				// Set drawables
				if (sel.isDirectory()) {
					item.icon = R.drawable.directory_icon;
					dirsOnly.add(item);
					Log.d("DIRECTORY", item.file);
				} else {
					filesOnly.add(item);
					Log.d("FILE", item.file);
				}
			}
			
			for (int i=0;i<dirsOnly.size();++i){
				fileList[i]=dirsOnly.get(i);
			}
			
			int offset = dirsOnly.size();
			for (int i=0;i<filesOnly.size();++i){
				fileList[i+offset]=filesOnly.get(i);
			}		

			if (!firstLvl) {
				Item temp[] = new Item[fileList.length + 1];
				for (int i = 0; i < fileList.length; i++) {
					temp[i + 1] = fileList[i];
				}
				temp[0] = new Item("Up", R.drawable.directory_up);
				fileList = temp;
			}
		} else {
			Log.e(TAG, "path does not exist");
		}
		
		adapter.clear();
		adapter.addAll(fileList);
	}

	private class Item {
		public String file;
		public int icon;

		public Item(String file, Integer icon) {
			this.file = file;
			this.icon = icon;
		}

		@Override
		public String toString() {
			return file;
		}
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState) {
		Dialog dialog = null;
		AlertDialog.Builder builder = new Builder(getActivity());

		if (fileList == null) {
			Log.e(TAG, "No files loaded");
			dialog = builder.create();
			return dialog;
		}

		ListView listView = new ListView(getActivity());
		listView.setAdapter(adapter);
		listView.setOnItemClickListener(new ListView.OnItemClickListener(){
			public void onItemClick(AdapterView<?> listView, View itemView, int which, long itemId) {
				chosenFile = fileList[which].file;
				File sel = new File(path + "/" + chosenFile);
				if (sel.isDirectory()) {
					firstLvl = false;

					// Adds chosen directory to list
					str.add(chosenFile);
					fileList = null;
					path = new File(sel + "");

					loadFileList();
					
					Log.d(TAG, path.getAbsolutePath());

				}

				// Checks if 'up' was clicked
				else if (chosenFile.equalsIgnoreCase("up") && !sel.exists()) {

					// present directory removed from list
					String s = str.remove(str.size() - 1);

					// path modified to exclude present directory
					path = new File(path.toString().substring(0,
							path.toString().lastIndexOf(s)));
					fileList = null;

					// if there are no more directories in the list, then
					// its the first level
					if (str.isEmpty()) {
						firstLvl = true;
					}
					
					loadFileList();
					
					Log.d(TAG, path.getAbsolutePath());

				}
				// File picked
				else {
					// Perform action with file picked
					fileExploreCallbacks.fileSelected(sel, fileExplore);
					
				}
			}
		});
		
		builder.setTitle("Choose your file");
		builder.setView(listView);

		dialog = builder.show();
		return dialog;
	}

}