/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet.structure;

import java.util.Arrays;
import java.util.Comparator;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

// TODO: Auto-generated Javadoc
/**
 * A field within a header. Field objects are used to describe the structure of
 * a header to a formatter. The formatter iterates through all the fields it
 * receives from a header and using formatting information stored in these
 * fields, creates formatted output.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JField {

	/**
	 * The Class JFieldComp.
	 */
	private static class JFieldComp implements Comparator<JField> {

		/** The header. */
		private JHeader header;

		/** The ascending. */
		private boolean ascending = true;

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		/**
		 * Compare.
		 * 
		 * @param o1
		 *          the o1
		 * @param o2
		 *          the o2
		 * @return the int
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		public int compare(JField o1, JField o2) {
			if (ascending) {
				return o1.getOffset(header) - o2.getOffset(header);
			} else {
				return o2.getOffset(header) - o1.getOffset(header);
			}
		}

		/**
		 * Sets the header.
		 * 
		 * @param header
		 *          the new header
		 */
		public void setHeader(JHeader header) {
			this.header = header;
		}

		/**
		 * Sets the ascending.
		 * 
		 * @param ascending
		 *          the new ascending
		 */
		public void setAscending(boolean ascending) {
			this.ascending = ascending;
		}

	}

	/**
	 * Sort field by offset.
	 * 
	 * @param fields
	 *          the fields
	 * @param header
	 *          the header
	 * @param ascending
	 *          the ascending
	 */
	public static void sortFieldByOffset(
	    JField[] fields,
	    JHeader header,
	    boolean ascending) {

		SORT_BY_OFFSET.setAscending(ascending);
		SORT_BY_OFFSET.setHeader(header);
		Arrays.sort(fields, SORT_BY_OFFSET);
	}

	/** The Constant SORT_BY_OFFSET. */
	private final static JFieldComp SORT_BY_OFFSET = new JFieldComp();

	/** The sub fields. */
	protected JField[] subFields;

	/** Name of the field which is also its ID. */
	private final String name;

	/** The nicname. */
	private final String nicname;

	/** The parent. */
	private JField parent;

	/** The priority. */
	private final Priority priority;

	/** The style. */
	protected Style style;

	/** The value. */
	private final AnnotatedFieldMethod value;

	/** The offset. */
	private final AnnotatedFieldMethod offset;

	/** The length. */
	private final AnnotatedFieldMethod length;

	/** The display. */
	private final AnnotatedFieldMethod display;

	/** The description. */
	private final AnnotatedFieldMethod description;

	/** The mask. */
	private final AnnotatedFieldMethod mask;

	/** The check. */
	private final AnnotatedFieldMethod check;

	/** The units. */
	private AnnotatedFieldMethod units;

	/**
	 * To string.
	 * 
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		StringBuilder b = new StringBuilder();

		b.append("name=").append(name);
		b.append(", nicname=").append(nicname);
		b.append(", parent=").append(parent);
		b.append(", priority=").append(priority);
		b.append(", style=").append(style);

		return b.toString();
	}

	/**
	 * Instantiates a new j field.
	 * 
	 * @param afield
	 *          the afield
	 * @param children
	 *          the children
	 */
	public JField(AnnotatedField afield, JField[] children) {
		this.subFields = children;
		this.priority = afield.getPriority();
		this.name = afield.getName();
		this.nicname = afield.getNicname();
		afield.getDisplay();
		afield.getUnits();
		this.style = afield.getStyle();
		
		value = afield.getRuntime().getFunctionMap().get(Field.Property.VALUE);
		offset = afield.getRuntime().getFunctionMap().get(Field.Property.OFFSET);
		length = afield.getRuntime().getFunctionMap().get(Field.Property.LENGTH);
		display = afield.getRuntime().getFunctionMap().get(Field.Property.DISPLAY);
		description = afield.getRuntime().getFunctionMap().get(Field.Property.DESCRIPTION);
		mask = afield.getRuntime().getFunctionMap().get(Field.Property.MASK);
		check = afield.getRuntime().getFunctionMap().get(Field.Property.CHECK);
		units = afield.getRuntime().getFunctionMap().get(Field.Property.UNITS);

		for (JField f : subFields) {
			f.setParent(this);
		}
	}

	/**
	 * Gets the sub-fields.
	 * 
	 * @return array of subfields
	 */
	public JField[] getSubFields() {
		return subFields;
	}

	/**
	 * Gets the full name of this field
	 * 
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * Gets the nicname of this field.
	 * 
	 * @return the nicname
	 */
	public String getNicname() {
		return nicname;
	}

	/**
	 * If this field is a sub-field, this method returns a reference to the parent
	 * field.
	 * 
	 * @return the parent
	 */
	public final JField getParent() {
		return this.parent;
	}

	/**
	 * Gets the current field's priority. Formatters determine if fields should be
	 * included in the output based on priorities
	 * 
	 * @return the priority
	 */
	public Priority getPriority() {
		return priority;
	}

	/**
	 * Formatting style for this field.
	 * 
	 * @return the style
	 */
	public Style getStyle() {
		return style;
	}

	/**
	 * Does this field have subfields.
	 * 
	 * @return true means has sub-fields, otherwise false
	 */
	public boolean hasSubFields() {
		return subFields.length != 0;
	}

	/**
	 * Sets the parent of this sub-field and only when this field is a sub-field.
	 * 
	 * @param parent
	 *          the parent to set
	 */
	public final void setParent(JField parent) {
		this.parent = parent;
	}

	/**
	 * Sets the style.
	 * 
	 * @param style
	 *          the new style
	 */
	public void setStyle(Style style) {
		this.style = style;
	}

	/**
	 * Gets the units.
	 * 
	 * @param header
	 *          the header
	 * @return the units
	 */
	public String getUnits(JHeader header) {
		return units.stringMethod(header, name);
	}
	
	/**
	 * Checks for field.
	 * 
	 * @param header
	 *          the header
	 * @return true, if successful
	 */
	public boolean hasField(JHeader header) {
		return check.booleanMethod(header, name);
	}


	/**
	 * Gets the display.
	 * 
	 * @param header
	 *          the header
	 * @return the display
	 */
	public String getDisplay(JHeader header) {
		return display.stringMethod(header, name);
	}

	/**
	 * Gets the length.
	 * 
	 * @param header
	 *          the header
	 * @return the length
	 */
	public int getLength(JHeader header) {
		return length.intMethod(header, name);
	}
	
	/**
	 * Gets the mask.
	 * 
	 * @param header
	 *          the header
	 * @return the mask
	 */
	public long getMask(JHeader header) {
		return mask.longMethod(header, name);
	}


	/**
	 * Gets the offset.
	 * 
	 * @param header
	 *          the header
	 * @return the offset
	 */
	public int getOffset(JHeader header) {
		return offset.intMethod(header, name);
	}

	/**
	 * Gets the value description.
	 * 
	 * @param header
	 *          the header
	 * @return the value description
	 */
	public String getValueDescription(JHeader header) {
		return description.stringMethod(header, name);
	}
	
	/**
	 * Gets the value.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param c
	 *          the c
	 * @param header
	 *          the header
	 * @return the value
	 */
	@SuppressWarnings("unchecked")
  public <T> T getValue(Class<T> c, JHeader header) {
		return (T) value.objectMethod(header, name);
	}

	/**
	 * Gets the value.
	 * 
	 * @param header
	 *          the header
	 * @return the value
	 */
	public Object getValue(JHeader header) {
		return value.objectMethod(header, name);
	}

	/**
	 * Long value.
	 * 
	 * @param header
	 *          the header
	 * @return the long
	 */
  public long longValue(JHeader header) {
  	Object o = getValue(header);
  	if (o instanceof Number) {
  		return ((Number) o).longValue();
  	} else if (o instanceof Boolean) {
  		return ((Boolean)o).booleanValue()?1L:0L;
  	} else if (o instanceof String) {
  		return Long.parseLong(o.toString());
  	} else {
  		throw new IllegalStateException("unknown format encountered");
  	}
  }

}