package com.glacialsoftware.pcapreader;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Formatter;
import java.util.List;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;

import pl.polidea.treeview.TreeBuilder;

public class PacketFormatter extends TextFormatter {
	
	private TreeBuilder<Integer> treeBuilder=null;
	private List<String> lines=null;
	private JHeaderPool headerPool = new JHeaderPool();
	
	public PacketFormatter(StringBuilder out, TreeBuilder<Integer> treeBuilder, List<String> lines){
		super(out);

		this.treeBuilder=treeBuilder;
		this.lines=lines;
	}
	
	private String getCurrentString(){
		String currentString = this.toString();
		this.reset();
		return currentString.trim();
	}
	
	private void add(String line, int level){
		lines.add(line);
		treeBuilder.sequentiallyAddNextNode(lines.size()-1, level);
	}
	
	public int analyzePacket(JPacket packet, long referenceEpochTime){
		int maxLevel=analyzeFrame(packet, referenceEpochTime);
		
		final int headerCount = packet.getHeaderCount();
		for (int i=0;i<headerCount;++i){ 
			final int id = packet.getHeaderIdByIndex(i);
			final JHeader header = headerPool.getHeader(id);
			packet.getHeaderByIndex(i, header);
			
			int depth;
			if (id==JProtocol.PAYLOAD_ID){
				depth=analyzePayload(header);
			} else {
				depth=analyzeHeader(header);
			}
			
			if (depth>maxLevel){
				maxLevel=depth;
			}
		}
		
		return maxLevel;
	}
	
	public int analyzeFrame(JPacket packet, long referenceEpochTime){
		add("Frame "+Long.toString(packet.getFrameNumber()), 0);
		
		JCaptureHeader captureHeader = packet.getCaptureHeader();
		
		add("arrival time = "+new Timestamp(captureHeader.timestampInMillis()).toString(),1);
		
		double time= (double)(captureHeader.timestampInNanos())/1000000000.0;
		double timeSinceReference= (double)(captureHeader.timestampInNanos()-referenceEpochTime)/1000000000.0;
		add(String.format("epoch time = %1$.9f seconds",time),1);
		add(String.format("time since first frame = %1$.9f seconds",timeSinceReference),1);
	
		add("wire length = "+Integer.toString(captureHeader.wirelen()),1);
		add("capture length = "+Integer.toString(captureHeader.caplen()),1);
		
		return 1;
	}
	
	public int analyzePayload(JHeader header){
		if (header==null){
			return 0;
		}
		try {
			format(header);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		add(getCurrentString().replace('*',' ').trim(), 0);
		
		String[] payload = FormatUtils.hexdump(header.getByteArray(0, header.size()), header.getOffset(), 0, true, true, true);
		
		for (String payloadLine : payload){
			add(payloadLine,1);
		}
		
		return 1;
	}
	
	public int analyzeHeader(JHeader header){
		if (header==null){
			return 0;
		}
		try {
			format(header);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		add(getCurrentString().replace('*',' ').trim(), 0);
		
		int maxLevel=analyzeFields(header, header.getFields(), 1);
		
		if (header.hasSubHeaders()){
			int depth = analyzeSubHeaders(header,header.getSubHeaders(),1);
			if (depth>maxLevel){
				maxLevel=depth;
			}
		}
		return maxLevel;		
	}
	
	public int analyzeSubHeaders(JHeader header, JHeader[] subHeaders, int level){
		if (subHeaders==null){
			return 0;
		}
		
		int maxLevel=level;
		int actualSubHeadersCount=0;
		for (JHeader subHeader : subHeaders){
			if (subHeader==null){
				continue;
			}
			
			try {
				format(header,subHeader,Detail.MULTI_LINE_FULL_DETAIL);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			add(getCurrentString().replace('+',' ').trim(),level);
			actualSubHeadersCount++;
			
			int depth=analyzeFields(subHeader,subHeader.getFields(),level+1);
			if (depth>maxLevel){
				maxLevel=depth;
			}
			
			if (subHeader.hasSubHeaders()){
				depth = analyzeSubHeaders(subHeader,subHeader.getSubHeaders(),level+1);
				if (depth>maxLevel){
					maxLevel=depth;
				}
			}
		}
		if (actualSubHeadersCount==0){
			return 0;
		}
		return maxLevel;
	}
	
	public int analyzeFields(JHeader header, JField[] fields, int level){
		if (fields==null){
			return 0;
		}
		
		int maxLevel=level;
		int actualFieldsCount=0;
		for (JField field : fields){
			if (field==null){
				continue;
			}
			
			try {
				format(header,field);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			String line = getCurrentString();
			if (line=="" || line==null){
				continue;
			}
			add(line,level);
			actualFieldsCount++;
			
			if (field.hasSubFields()){
				int depth=analyzeFields(header, field.getSubFields(), level+1);
				if (depth>maxLevel){
					maxLevel=depth;
				}
			}
		}
		if (actualFieldsCount==0){
			return 0;
		}
		return maxLevel;
	}
	
	@Override
	public void format(JHeader header, JField field, Detail detail)
			throws IOException {

		fieldBefore(header, field, detail);
		fieldAfter(header, field, detail);
	}

	@Override
	public void format(JHeader header, Detail detail) 
			throws IOException {

		headerBefore(header, detail);
		headerAfter(header, detail);
	}
	
	@Override
	public void format(JHeader header, JHeader subHeader, Detail detail)
			throws IOException {

		subHeaderBefore(header, subHeader, detail);
		subHeaderAfter(header, subHeader, detail);
	}
	
	@Override
	protected Formatter pad() {

		this.out.format("\n");
		return this.out;
	}
}
