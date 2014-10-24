package com.glacialsoftware.pcapreader;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

public class LicenseListAdapter extends ArrayAdapter<LicenseListItem> {
	
	Context context; 
	int resource;

	public LicenseListAdapter(Context context, int resource) {
		super(context, resource);
		
		this.context=context;
		this.resource=resource;
	}

	@Override
	public View getView(int position, View convertView, ViewGroup parent){
		convertView= LayoutInflater.from(context).inflate(resource, parent, false);
		
		LicenseListItem licenseListItem=(LicenseListItem) getItem(position);
		((TextView) convertView.findViewById(R.id.project)).setText(licenseListItem.project);
		((TextView) convertView.findViewById(R.id.license)).setText(licenseListItem.license);
		
		return convertView;
	}

}
