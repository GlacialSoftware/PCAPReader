package com.glacialsoftware.pcapreader;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.AlertDialog.Builder;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;

public class LicenseDialogFragment extends DialogFragment{
	
	private LicenseListItem licenseListItem=null;

	public void setLicenseListItem(LicenseListItem licenseListItem){
		this.licenseListItem=licenseListItem;
	}
	
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        AlertDialog.Builder builder = new Builder(getActivity());
        
        ScrollView scrollView = new ScrollView(getActivity());
        TextView textView=new TextView(getActivity());
        
        if (licenseListItem!=null){
        	builder.setTitle(licenseListItem.license);
        	textView.setText(licenseListItem.extra+licenseListItem.licenseContent);
        }
        
        scrollView.addView(textView);
        
        builder.setView(scrollView);
        return builder.create();
    }
    
    @Override
    public void onDestroyView() {
      if (getDialog() != null && getRetainInstance())
        getDialog().setDismissMessage(null);
      super.onDestroyView();
    }
}
