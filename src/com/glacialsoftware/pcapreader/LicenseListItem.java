package com.glacialsoftware.pcapreader;


public class LicenseListItem {
	public String project;
	public String license;
	public String licenseContent;
	public String extra;
	
	public LicenseListItem(String project, String license, String licenseContent,String extra){
		this.project=project;
		this.license=license;
		this.licenseContent=licenseContent;
		this.extra=extra;
	}
}
