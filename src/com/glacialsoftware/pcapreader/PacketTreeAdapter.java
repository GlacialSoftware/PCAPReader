package com.glacialsoftware.pcapreader;

import java.util.List;

import android.app.Activity;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;
import pl.polidea.treeview.AbstractTreeViewAdapter;
import pl.polidea.treeview.TreeNodeInfo;
import pl.polidea.treeview.TreeStateManager;

public class PacketTreeAdapter extends AbstractTreeViewAdapter<Integer> {

	private int resource;
	private List<String> lines;
	
	public PacketTreeAdapter(Activity activity, TreeStateManager<Integer> treeStateManager, 
												   int numberOfLevels, int resource, List<String> lines) {
		super(activity, treeStateManager, numberOfLevels);
		this.lines=lines;
		this.resource=resource;
	}
	
	@Override
	public View getNewChildView(TreeNodeInfo<Integer> treeNodeInfo) {
		View view = LayoutInflater.from(getActivity()).inflate(resource,null);
		return updateView(view, treeNodeInfo);
	}
	
    @Override
    public View updateView(final View view, final TreeNodeInfo<Integer> treeNodeInfo) {
    	
        TextView field = (TextView) view.findViewById(R.id.field);
        field.setText(lines.get(treeNodeInfo.getId()));
       
        return view;
    }

	@Override
	public long getItemId(int position) {
		return position;
	}
	
	@Override
	public Drawable getDrawableOrDefaultBackground(final Drawable drawable) {
		return getActivity().getResources().getDrawable(R.drawable.item_packet_tree_selector);
	}


	
}
