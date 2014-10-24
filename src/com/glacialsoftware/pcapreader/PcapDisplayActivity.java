package com.glacialsoftware.pcapreader;

import java.io.File;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.JProtocol;

import android.app.Activity;
import android.app.FragmentTransaction;
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;



public class PcapDisplayActivity extends Activity implements PacketListFragment.PacketListCallbacks,
																											  PcapReaderPreferenceFragment.PreferenceCallbacks {

	private PacketListFragment packetListFragment;
	private PacketDetailsFragment packetDetailsFragment;
	PcapReaderPreferenceFragment pcapReaderPreferenceFragment;
	LicenseFragment licenseFragment;
	
	private int firstVisiblePosition=0;
	private boolean preferencesShowing=false;
	private boolean detailsShowing=false;
	private boolean licensesShowing=false;
	//private boolean created=false;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		//created=true;
		
		if (PreferenceManager.getDefaultSharedPreferences(this).getBoolean("tilt_lock", false)){
			setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
		} else {
			setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED);
		}
		
		setContentView(R.layout.activity_pcap_display);
		
		if (PcapFileLoader.filename==null){
			Log.d("PcapDisplayActivity","Null filename - finishing");
			finish();
		}
		
		File file = new File(PcapFileLoader.filename);
		setTitle(file.getName());
		
		detailsShowing=false;
		firstVisiblePosition=0;
		preferencesShowing=false;
		licensesShowing=false;
		if (savedInstanceState!=null){
			detailsShowing=savedInstanceState.getBoolean("detailsShowing");
			firstVisiblePosition=savedInstanceState.getInt("firstVisiblePosition");
			preferencesShowing=savedInstanceState.getBoolean("preferencesShowing");
			licensesShowing=savedInstanceState.getBoolean("licensesShowing");
		}
		
		if (findViewById(R.id.pcap_display_frame) !=null){
			pcapReaderPreferenceFragment=new PcapReaderPreferenceFragment();
			packetListFragment = new PacketListFragment();
			packetDetailsFragment = new PacketDetailsFragment();
			licenseFragment = new LicenseFragment();
			FragmentTransaction fragmentTransaction = getFragmentManager().beginTransaction();
			fragmentTransaction.add(R.id.pcap_display_frame, packetListFragment);
			fragmentTransaction.add(R.id.pcap_display_frame, packetDetailsFragment);
			fragmentTransaction.add(R.id.pcap_display_frame, pcapReaderPreferenceFragment);
			fragmentTransaction.add(R.id.pcap_display_frame, licenseFragment);
			fragmentTransaction.hide(packetDetailsFragment);
			fragmentTransaction.hide(pcapReaderPreferenceFragment);
			fragmentTransaction.hide(licenseFragment);
			fragmentTransaction.commit();
		}
	}
	
	@Override
	protected void onStart (){
		super.onStart();
		/*
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
			fragmentTransaction.add(R.id.pcap_display_frame, pcapReaderPreferenceFragment);
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
		 */
		 packetListFragment.setReferenceEpochTime(PcapFileLoader.referenceEpochTime);
		 packetDetailsFragment.setReferenceEpochTime(PcapFileLoader.referenceEpochTime);
		 packetListFragment.setFirstVisiblePosition(firstVisiblePosition);
		 packetDetailsFragment.analyzePacket(PcapFileLoader.detailsPacket, PcapFileLoader.detailsPacketPosition);
	}
	
	@Override
	protected void onResume(){
		super.onResume();
		
		if (detailsShowing && !packetDetailsFragment.isVisible()){
			FragmentTransaction transaction0 = getFragmentManager().beginTransaction();
			transaction0.show(packetDetailsFragment);
			transaction0.addToBackStack(null);
			transaction0.commit();
		}
		
		if (preferencesShowing && !pcapReaderPreferenceFragment.isVisible()){
			FragmentTransaction transaction1 = getFragmentManager().beginTransaction();
			transaction1.show(pcapReaderPreferenceFragment);
			transaction1.addToBackStack(null);
			transaction1.commit();
		}
		
		if (licensesShowing && !licenseFragment.isVisible()){
			FragmentTransaction transaction2 = getFragmentManager().beginTransaction();
			transaction2.show(licenseFragment);
			transaction2.addToBackStack(null);
			transaction2.commit();
		}
	}
	
	public void onPacketSelected(int position){	
		packetDetailsFragment.analyzePacket(PcapFileLoader.getIndex(position), position);
		FragmentTransaction fragmentTransaction = getFragmentManager().beginTransaction();
		fragmentTransaction.show(packetDetailsFragment);
		fragmentTransaction.addToBackStack(null);
		fragmentTransaction.commit();
		
	}
	
	public boolean filteredOut(PcapPacket packet){
		//Not implemented yet - display filter
		//Returns true if packet is filtered out, else return false
		return false;
	}
	
	@Override
	public void onSaveInstanceState(Bundle savedInstanceState) {
		
		if (packetDetailsFragment!=null){
			detailsShowing=packetDetailsFragment.isVisible();
		} else {
			detailsShowing=false;
		}
		if (pcapReaderPreferenceFragment!=null){
			preferencesShowing=pcapReaderPreferenceFragment.isVisible();
		} else {
			preferencesShowing=false;
		}
		if (licenseFragment!=null){
			licensesShowing=licenseFragment.isVisible();
		} else {
			licensesShowing=false;
		}
		
		if (licensesShowing){
			getFragmentManager().popBackStackImmediate();
		}
		
		if (preferencesShowing){
			getFragmentManager().popBackStackImmediate();
		}
		
		if (detailsShowing){
			getFragmentManager().popBackStackImmediate();
		}
		
		savedInstanceState.putBoolean("detailsShowing", detailsShowing);
		savedInstanceState.putInt("firstVisiblePosition", packetListFragment.getFirstVisiblePosition());
		savedInstanceState.putBoolean("preferencesShowing", preferencesShowing);
		savedInstanceState.putBoolean("licensesShowing", licensesShowing);
		super.onSaveInstanceState(savedInstanceState);
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

}