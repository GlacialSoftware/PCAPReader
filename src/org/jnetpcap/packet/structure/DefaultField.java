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


// TODO: Auto-generated Javadoc
/**
 * The Class DefaultField.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class DefaultField
    extends JField {

	/**
	 * Instantiates a new default field.
	 * 
	 * @param field
	 *          the field
	 * @param children
	 *          the children
	 */
	private DefaultField(AnnotatedField field, DefaultField[] children) {
		super(field, children);
	}

	/**
	 * From annotated field.
	 * 
	 * @param field
	 *          the field
	 * @return the default field
	 */
	public static DefaultField fromAnnotatedField(AnnotatedField field) {

		DefaultField[] children = new DefaultField[field.getSubFields().size()];
		int i = 0;
		for (AnnotatedField f : field.getSubFields()) {
			children[i++] = fromAnnotatedField(f);
		}

		JField.sortFieldByOffset(children, null, false);

		return new DefaultField(field, children);
	}

	/**
	 * From annotated fields.
	 * 
	 * @param fields
	 *          the fields
	 * @return the j field[]
	 */
	public static JField[] fromAnnotatedFields(AnnotatedField[] fields) {
		JField[] f = new JField[fields.length];

		for (int i = 0; i < fields.length; i++) {
			f[i] = fromAnnotatedField(fields[i]);
		}

		return f;
	}
}
