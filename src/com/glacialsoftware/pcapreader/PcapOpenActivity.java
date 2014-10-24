package com.glacialsoftware.pcapreader;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.mburman.fileexplore.FileExplore;

import android.app.Activity;
import android.app.FragmentTransaction;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.net.Uri;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;



public class PcapOpenActivity extends Activity implements FileExplore.FileExploreCallbacks, 
																										   	PcapOpenFragment.PcapOpenCallbacks,
																										   	PcapReaderPreferenceFragment.PreferenceCallbacks,
																										   	InvalidFileDialogFragment.InvalidFileDialogCallbacks {
	
	private PcapOpenFragment pcapOpenFragment=null;
	private LicenseFragment licenseFragment=null;
	private PcapReaderPreferenceFragment pcapReaderPreferenceFragment=null;
	
	public static List<File> scanResults=new ArrayList<File>();
	public static boolean isScanning=false;
	
	private boolean invalidActivity=false;
	//private boolean created=false;
	private boolean firstScan=false;
	private boolean preferencesShowing=false;
	private boolean licensesShowing=false;
	private int firstVisiblePosition=0;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		//created=true;
		invalidActivity=false;
		
		if (PreferenceManager.getDefaultSharedPreferences(this).getBoolean("tilt_lock", false)){
			setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
		} else {
			setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED);
		}
		
		setContentView(R.layout.activity_pcap_open);

	    Intent intent = getIntent();
	    if (Intent.ACTION_VIEW.equals(intent.getAction())){
	    	Uri data = intent.getData();
	    	
	 		if (PcapFileLoader.setup(data.getPath(),10000)){
				Intent displayPcapIntent = new Intent(this,PcapDisplayActivity.class);
				startActivity(displayPcapIntent); 
				
				setResult(RESULT_OK);
				finish();
			}
	 		else {
	 			invalidActivity=true;
	 			
				InvalidFileDialogFragment invalidFileDialogFragment = InvalidFileDialogFragment.newInstance((new File(data.getPath())).getName());
				invalidFileDialogFragment.show(getFragmentManager(),"invalidFileDialogFragment");
				
	 			setResult(RESULT_CANCELED);
	 			return;
	 		}
	    }
	    
		firstVisiblePosition=0;
		firstScan=false;
		preferencesShowing=false;
		licensesShowing=false;
		if (savedInstanceState!=null){
			firstScan=savedInstanceState.getBoolean("firstScan");
			firstVisiblePosition=savedInstanceState.getInt("firstVisiblePosition");
			preferencesShowing=savedInstanceState.getBoolean("preferencesShowing");
			licensesShowing=savedInstanceState.getBoolean("licensesShowing");
		}
		
		if (findViewById(R.id.pcap_open_frame) !=null){
			
		    pcapOpenFragment=new PcapOpenFragment();
		    pcapReaderPreferenceFragment=new PcapReaderPreferenceFragment();
		    licenseFragment = new LicenseFragment();
		    
		    FragmentTransaction fragmentTransaction = getFragmentManager().beginTransaction();
			fragmentTransaction.add(R.id.pcap_open_frame, pcapOpenFragment);
			fragmentTransaction.add(R.id.pcap_open_frame, pcapReaderPreferenceFragment);
			fragmentTransaction.add(R.id.pcap_open_frame, licenseFragment);
			fragmentTransaction.hide(licenseFragment);
			fragmentTransaction.hide(pcapReaderPreferenceFragment);
			fragmentTransaction.commit();
		}
		
	}
	/*
	@Override
	protected void onStart(){
		super.onStart();
		if (!invalidActivity){
			if (created){
				created=false;
			} else{
				boolean preferencesShowing=pcapReaderPreferenceFragment.isVisible();
				boolean licensesShowing=licenseFragment.isVisible();
				
				if (licensesShowing){
				    FragmentTransaction transaction0 = getFragmentManager().beginTransaction();
				    transaction0.hide(licenseFragment);
				    transaction0.commit();
					getFragmentManager().popBackStackImmediate();
				}
				
				if (preferencesShowing){
				    FragmentTransaction transaction1 = getFragmentManager().beginTransaction();
				    transaction1.hide(pcapReaderPreferenceFragment);
				    transaction1.commit();
					getFragmentManager().popBackStackImmediate();
				}
				
			    FragmentTransaction fragmentTransaction = getFragmentManager().beginTransaction();
				fragmentTransaction.remove(pcapReaderPreferenceFragment);
				pcapReaderPreferenceFragment=new PcapReaderPreferenceFragment();
				fragmentTransaction.add(R.id.pcap_open_frame, pcapReaderPreferenceFragment);
				fragmentTransaction.hide(pcapReaderPreferenceFragment);			
				fragmentTransaction.commit();
				
				
				if (preferencesShowing){
					FragmentTransaction transaction2 = getFragmentManager().beginTransaction();
					transaction2.show(pcapReaderPreferenceFragment);
					transaction2.addToBackStack(null);
					transaction2.commit();
				}
				
				if (licensesShowing){
					FragmentTransaction transaction3 = getFragmentManager().beginTransaction();
					transaction3.show(licenseFragment);
					transaction3.addToBackStack(null);
					transaction3.commit();
				}
			}
		}
		
	}
	*/
	
	@Override
	protected void onResume(){
		super.onResume();
		
		if (!invalidActivity){
			if (preferencesShowing && !pcapReaderPreferenceFragment.isVisible()){
				FragmentTransaction transaction0 = getFragmentManager().beginTransaction();
				transaction0.show(pcapReaderPreferenceFragment);
				transaction0.addToBackStack(null);
				transaction0.commit();
				preferencesShowing=false;
			}
			
			if (licensesShowing && !licenseFragment.isVisible()){
				FragmentTransaction transaction1 = getFragmentManager().beginTransaction();
				transaction1.show(licenseFragment);
				transaction1.addToBackStack(null);
				transaction1.commit();
				licensesShowing=false;
			}
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			
			if (licenseFragment.isVisible()){
			    FragmentTransaction transaction0 = getFragmentManager().beginTransaction();
			    transaction0.hide(licenseFragment);
			    transaction0.commit();
				getFragmentManager().popBackStackImmediate();
			}
			
			if (!pcapReaderPreferenceFragment.isVisible()){
			    FragmentTransaction fragmentTransaction = getFragmentManager().beginTransaction();
			    fragmentTransaction.show(pcapReaderPreferenceFragment);
			    fragmentTransaction.addToBackStack(null);
				fragmentTransaction.commit();
			}
						
			return true;
		}
		else if (id==R.id.action_licenses){
			showLicenseFragment();
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
	
	@Override
	public void onSaveInstanceState(Bundle savedInstanceState) {
		preferencesShowing=pcapReaderPreferenceFragment.isVisible();
		licensesShowing=licenseFragment.isVisible();
		
		if (licensesShowing){
			getFragmentManager().popBackStackImmediate();
		}
		
		if (preferencesShowing){
			getFragmentManager().popBackStackImmediate();
		}
		
		savedInstanceState.putBoolean("firstScan", firstScan);
		savedInstanceState.putInt("firstVisiblePosition", pcapOpenFragment.getFirstVisiblePosition());
		savedInstanceState.putBoolean("preferencesShowing", preferencesShowing);
		savedInstanceState.putBoolean("licensesShowing", licensesShowing);
		super.onSaveInstanceState(savedInstanceState);
	}
	
	public void openFile(String path){
		if (!PcapFileLoader.setup(path,10000)){
			InvalidFileDialogFragment invalidFileDialogFragment = InvalidFileDialogFragment.newInstance((new File(path)).getName());
			invalidFileDialogFragment.show(getFragmentManager(),"invalidFileDialogFragment");
			return;
		}
		
		Intent displayPcapIntent = new Intent(this,PcapDisplayActivity.class);
		startActivity(displayPcapIntent);
	}
	
	public void fileSelected(File path, FileExplore fileExplore){
		fileExplore.dismiss();
		openFile(path.getPath());
	}
	
	public void showFileExplore(View view){
		FileExplore fileExplore = new FileExplore();
		fileExplore.show(getFragmentManager(),"fileExplore");
	}
	
	public boolean getFirstScan(){
		return firstScan;
	}
	
	public void setFirstScan(boolean firstScan){
		this.firstScan=firstScan;
	}
	
	public int getFirstVisiblePosition(){
		return firstVisiblePosition;
	}

	public void showLicenseFragment() {
		if (!licenseFragment.isVisible()){
		    FragmentTransaction fragmentTransaction = getFragmentManager().beginTransaction();
		    fragmentTransaction.show(licenseFragment);
		    fragmentTransaction.addToBackStack(null);
			fragmentTransaction.commit();
		}
	}

	@Override
	public void updateOrientation(Boolean newValue) {
		if (newValue){
			setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
		} else {
			setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED);
		}	
	}

	@Override
	public void dismissAndFinish(DialogInterface dialog) {
		dialog.dismiss();
		if (invalidActivity){
			finish();
		}
	}

}