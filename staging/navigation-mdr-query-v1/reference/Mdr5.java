/*
 * Copyright (C) 2009.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 or
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
package uk.me.parabola.imgfmt.app.mdr;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import uk.me.parabola.imgfmt.Utils;
import uk.me.parabola.imgfmt.app.ImgFileWriter;
import uk.me.parabola.imgfmt.app.srt.MultiSortKey;
import uk.me.parabola.imgfmt.app.srt.Sort;
import uk.me.parabola.imgfmt.app.srt.SortKey;

/**
 * Section containing cities.
 *
 * We need: map number, city index in map, offset in LBL, flags
 * and pointer into MDR 15 for the string name.
 * 
 * @author Steve Ratcliffe
 */
public class Mdr5 extends MdrMapSection {
	private ArrayList<Mdr5Record> allCities = new ArrayList<>();
	private ArrayList<Mdr5Record> cities;
	private int maxCityIndex;
	private int localCitySize;
	private int mdr20PointerSize = 0; // bytes for mdr20 pointer, or 0 if no mdr20

	// We need a common area to save the mdr20 values, since there can be multiple
	// city records with the same global city index
	private int[] mdr20s;

	public Mdr5(MdrConfig config) {
		setConfig(config);
	}

	public void addCity(Mdr5Record record) {
		assert record.getMapIndex() != 0;
		allCities.add(record);
		if (record.getCityIndex() > maxCityIndex)
			maxCityIndex = record.getCityIndex();
	}

	/**
	 * Called after all cities to sort and number them.
	 */
	@Override
	public void preWriteImpl() {
		allCities.trimToSize();
		localCitySize = Utils.numberToPointerSize(maxCityIndex + 1);
		Sort sort = getConfig().getSort();
		genCitiesAndMdr20s(sort);
		// calculate positions for the different road indexes
		calcMdr20SortPos(sort);
		calcMdr21SortPos(sort);
		calcMdr22SortPos(sort);
	}

	private void genCitiesAndMdr20s(Sort sort) {
		List<SortKey<Mdr5Record>> sortKeys = new ArrayList<>(allCities.size());
		Map<String, byte[]> regionCache = new HashMap<>();
		Map<String, byte[]> countryCache = new HashMap<>();
		for (Mdr5Record m : allCities) {
			if (m.getName() == null)
				continue;

			// Sort by city name, region name, country name and map index.
			SortKey<Mdr5Record> sortKey = sort.createSortKey(m, m.getName());
			SortKey<Mdr5Record> regionKey = sort.createSortKey(null, m.getRegionName(), 0, regionCache);
			SortKey<Mdr5Record> countryKey = sort.createSortKey(null, m.getCountryName(), m.getMapIndex(), countryCache);
			sortKey = new MultiSortKey<>(sortKey, regionKey, countryKey);
			sortKeys.add(sortKey);
		}
		regionCache = null;
		countryCache = null;
		sortKeys.sort(null);

		cities = new ArrayList<>(sortKeys.size());
		Collator collator = sort.getCollator();

		int count = 0;
		Mdr5Record lastCity = null;

		mdr20s = new int[sortKeys.size()+1];
		int mdr20count = 0;

		for (SortKey<Mdr5Record> key : sortKeys) {
			Mdr5Record c = key.getObject();
			c.setMdr20set(mdr20s);

			if (!c.isSameByName(collator, lastCity))
				mdr20count++;
			c.setMdr20Index(mdr20count);

			if (c.isSameByMapAndName(collator, lastCity)) {
				c.setGlobalCityIndex(count);
			} else {
				count++;
				c.setGlobalCityIndex(count);
				cities.add(c);

				lastCity = c;
			}
		}
		//cities.trimToSize();  // it might be a fraction smaller than allocated, but not worth the cost of reallocation
	}

	/**
	 * Calculate a position when sorting by name, region, and country- This is used for MDR20. 
	 */
	private void calcMdr20SortPos(Sort sort) {
		List<SortKey<Mdr5Record>> sortKeys = new ArrayList<>(allCities.size());
		Map<String, byte[]> regionCache = new HashMap<>();
		Map<String, byte[]> countryCache = new HashMap<>();
		for (Mdr5Record m : allCities) {
			if (m.getName() == null)
				continue;

			// Sort by city name, region name, and country name .
			SortKey<Mdr5Record> sortKey = sort.createSortKey(m, m.getName());
			SortKey<Mdr5Record> regionKey = sort.createSortKey(null, m.getRegionName(), 0, regionCache);
			SortKey<Mdr5Record> countryKey = sort.createSortKey(null, m.getCountryName(), 0, countryCache);
			sortKey = new MultiSortKey<>(sortKey, regionKey, countryKey);
			sortKeys.add(sortKey);
		}
		regionCache = null;
		countryCache = null;
		sortKeys.sort(null);

		SortKey<Mdr5Record> lastKey = null;
		int pos = 0;
		for (SortKey<Mdr5Record> key : sortKeys) {
			Mdr5Record c = key.getObject();
			if (lastKey == null || key.compareTo(lastKey) != 0)
				pos++;
			c.setMdr20SortPos(pos);
			lastKey = key;
		}
	}

	/**
	 * Calculate a position when sorting by region- This is used for MDR21. 
	 */
	private void calcMdr21SortPos(Sort sort) {
		List<SortKey<Mdr5Record>> sortKeys = new ArrayList<>(allCities.size());
		for (Mdr5Record m : allCities) {
			if (m.getRegionName() == null) 
				continue;

			// Sort by region name.
			sortKeys.add(sort.createSortKey(m, m.getRegionName()));
		}
		sortKeys.sort(null);

		SortKey<Mdr5Record> lastKey = null;
		int pos = 0;
		for (SortKey<Mdr5Record> key : sortKeys) {
			Mdr5Record c = key.getObject();
			if (lastKey == null || key.compareTo(lastKey) != 0)
				pos++;
			c.setMdr21SortPos(pos);
			lastKey = key;
		}
	}

	/**
	 * Calculate a position when sorting by country- This is used for MDR22. 
	 */

	private void calcMdr22SortPos(Sort sort) {
		List<SortKey<Mdr5Record>> sortKeys = new ArrayList<>(allCities.size());
		for (Mdr5Record m : allCities) {
			if (m.getCountryName() == null)
				continue;

			// Sort by country name .
			SortKey<Mdr5Record> countryKey = sort.createSortKey(m, m.getCountryName());
			sortKeys.add(countryKey);
		}
		sortKeys.sort(null);

		SortKey<Mdr5Record> lastKey = null;
		int pos = 0;
		for (SortKey<Mdr5Record> key : sortKeys) {
			Mdr5Record c = key.getObject();
			if (lastKey == null || key.compareTo(lastKey) != 0)
				pos++;
			c.setMdr22SortPos(pos);
			lastKey = key;
		}
	}

	public void writeSectData(ImgFileWriter writer) {
		Mdr5Record lastCity = null;
		boolean hasString = hasFlag(0x8);
		boolean hasRegion = hasFlag(0x4);
		Collator collator = getConfig().getSort().getCollator();
		for (Mdr5Record city : cities) {
			int gci = city.getGlobalCityIndex();
			addIndexPointer(city.getMapIndex(), gci);

			// Work out if the name is the same as the previous one and set
			// the flag if so.
			int flag = 0;
			int mapIndex = city.getMapIndex();
			int region = city.getRegionIndex();

			// Set the no-repeat flag if the name/region is different
			if (!city.isSameByName(collator, lastCity)) {
				flag = 0x800000;
				lastCity = city;
			}

			// Write out the record
			putMapIndex(writer, mapIndex);
			putLocalCityIndex(writer, city.getCityIndex());
			writer.put3u(flag | city.getLblOffset());
			if (hasRegion)
				writer.put2u(region);
			if (hasString)
				putStringOffset(writer, city.getStringOffset());
			if (mdr20PointerSize > 0)
				writer.putNu(mdr20PointerSize, city.getMdr20());
		}
	}

	/**
	 * Put the map city index.  This is the index within the individual map
	 * and not the global city index used in mdr11.
	 */
	private void putLocalCityIndex(ImgFileWriter writer, int cityIndex) {
		writer.putNu(localCitySize, cityIndex);
	}

	/**
	 * Base size of 8, plus enough bytes to represent the map number
	 * and the city number.
	 * @return The size of a record in this section.
	 */
	public int getItemSize() {
		PointerSizes sizes = getSizes();
		int size = sizes.getMapSize()
				+ localCitySize
				+ 3
				+ mdr20PointerSize;
		if (hasFlag(0x4))
			size += 2;
		if (hasFlag(0x8))
			size += sizes.getStrOffSize();
		return size;
	}

	protected int numberOfItems() {
		return cities.size();
	}

	/**
	 * Known structure bits/masks:
	 * 0x0003 size of local city index - 1 (all values appear to work)
	 * 0x0004 has region/country
	 * 0x0008 has string
	 * 0x0010 ? set unconditionally ?
	 * 0x0040 mdr17 sub section
	 * 0x0100 mdr20 present
	 * 0x0400 28_29 offset
	 * 0x0800 mdr20 offset
	 * @return The value to be placed in the header.
	 */
	public int getExtraValue() {
		int val = (localCitySize - 1);
		// String offset is only included for a mapsource index.
		if (isForDevice() ) {
			if (!getConfig().getSort().isMulti())
				val |= 0x40; // mdr17 sub section present (not with unicode)
		} else {
			val |= 0x04;  // region
			val |= 0x08; // string
		}
		val |= 0x10;
		if (getSizes().getNumberOfItems(20) > 0) { 
			mdr20PointerSize = getSizes().getMdr20Size();
			val |= 0x100; // mdr20 present
		}
		return val;
	}

	@Override
	protected void releaseMemory() {
		allCities = null;
		cities = null;
		mdr20s = null;
	}

	/**
	 * Get a list of all the cities, including duplicate named ones.
	 * @return All cities.
	 */
	public List<Mdr5Record> getCities() {
		return Collections.unmodifiableList(allCities);
	}

	public List<Mdr5Record> getSortedCities() {
		return Collections.unmodifiableList(cities);
	}
}
