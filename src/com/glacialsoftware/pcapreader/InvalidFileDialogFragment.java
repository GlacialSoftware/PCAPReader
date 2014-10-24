package com.glacialsoftware.pcapreader;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.os.Bundle;

public class InvalidFileDialogFragment extends DialogFragment{
	
	public interface InvalidFileDialogCallbacks{
		public void dismissAndFinish(DialogInterface dialog);
	}
	
	
	public static InvalidFileDialogFragment newInstance(String filename){
			InvalidFileDialogFragment invalidFileDialogFragment = new InvalidFileDialogFragment();
	        Bundle args = new Bundle();
	        args.putString("filename", filename);
	        invalidFileDialogFragment.setArguments(args);
	        return invalidFileDialogFragment;
	}
	
	   @Override
	    public Dialog onCreateDialog(Bundle savedInstanceState) {
		   	String filename= getArguments().getString("filename");
		   	String message="Unable to open file "+filename+". Verify this is a valid PCAP file.";
		    AlertDialog.Builder builder = new Builder(getActivity());
		    builder.setIconAttribute(android.R.attr.alertDialogIcon);
		    builder.setTitle("Problem");
		    builder.setMessage(message);
		    builder.setNegativeButton(R.string.invalid_file_dialog_dismiss,
                    new DialogInterface.OnClickListener() {
		                public void onClick(DialogInterface dialog, int whichButton) {
		                	InvalidFileDialogCallbacks invalidFileDialogCallbacks = (InvalidFileDialogCallbacks)getActivity();
		                   	invalidFileDialogCallbacks.dismissAndFinish(dialog);
		                }
            });
        
		   return builder.create();
	    }
	
	
}
