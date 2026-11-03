/*
 * Copyright (C) 2008 Steve Ratcliffe
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 or
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package uk.me.parabola.imgfmt.app.net;

import uk.me.parabola.imgfmt.app.BitWriter;

/**
 * A bit writer that can be configured with different bit width and sign properties.
 *
 * The sign choices are:
 * negative: all numbers are negative and so can be represented without a sign bit. (or all positive
 * if this is false).
 * signed: numbers are positive and negative, and so have sign bit.
 *
 * The bit width is composed of two parts since it is represented as a difference between
 * a well known minimum value and the actual value.
 */
class VarBitWriter {
	private final BitWriter bw;
	private final int minWidth;
	int bitWidth;
	boolean negative;
	boolean signed;

	VarBitWriter(BitWriter bw, int minWidth) {
		this.bw = bw;
		this.minWidth = minWidth;
	}

	public VarBitWriter(BitWriter bw, int minWidth, boolean negative, boolean signed, int width) {
		this(bw, minWidth);
		this.negative = negative;
		this.signed = signed;
		if (width > minWidth)
			this.bitWidth = width - minWidth;
	}

	/**
	 * Write the number to the bit stream. If the number cannot be written
	 * correctly with this bit writer then an exception is thrown. This shouldn't
	 * happen since we check before hand and create a new writer if the numbers are not
	 * going to fit.
	 *
	 * @param n The number to be written.
	 */
	public void write(int n) {
		if (!checkFit(n))
			throw new Abandon("number does not fit bit space available");

		if (n < 0 && negative)
			n = -n;

		if (signed) {
			int mask = (1 << (minWidth + bitWidth+2)) - 1;
			n &= mask;
		}

		bw.putn(n, minWidth+bitWidth + ((signed)?1:0));
	}

	/**
	 * Checks to see if the number that we want to write can be written by this writer.
	 * @param n The number we would like to write.
	 * @return True if all is OK for writing it.
	 */
	boolean checkFit(int n) {
		if (negative) {
			if (n > 0) {
				return false;
			} else {
				n = -n;
			}
		} else if (signed && n < 0) {
			n = -1 - n;
		}

		int mask = (1 << minWidth + bitWidth) - 1;

		return n == (n & mask);
	}

	/**
	 * Write the format of this bit writer to the output stream. Used at the beginning and
	 * when changing the bit widths.
	 */
	public void writeFormat() {
		bw.put1(negative);
		bw.put1(signed);
		bw.putn(bitWidth, 4);
	}
}