package com.glacialsoftware.pcapreader;

import android.app.Activity;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

public class PcapReaderPreferenceFragment extends PreferenceFragment implements OnSharedPreferenceChangeListener{
	
	public interface PreferenceCallbacks{
		public void showLicenseFragment();
		public void updateOrientation(Boolean newValue);
	}
	
	private PreferenceCallbacks preferenceCallbacks;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        addPreferencesFromResource(R.xml.preferences);
        
        Preference licenseButton = (Preference)getPreferenceManager().findPreference("licenses");      
        licenseButton.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
        	
            @Override
            public boolean onPreferenceClick(Preference preference) {  
        		preferenceCallbacks.showLicenseFragment();
        		return true;
            }
        });     

    }
    
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = super.onCreateView(inflater, container, savedInstanceState);
        
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
	public void onAttach(Activity activity) {
		super.onAttach(activity);
		
		preferenceCallbacks = (PreferenceCallbacks) activity;
	}

	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
			String key) {

		preferenceCallbacks.updateOrientation(sharedPreferences.getBoolean("tilt_lock", false));

	}
	
	@Override
	public void onResume() {
	    super.onResume();
	    getPreferenceManager().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);

	}

	@Override
	public void onPause() {
	    getPreferenceManager().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(this);
	    super.onPause();
	}
	
}
