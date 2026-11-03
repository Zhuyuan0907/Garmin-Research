/*
 * Copyright (C) 2007 Steve Ratcliffe
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 * 
 * Author: Steve Ratcliffe
 * Create date: Feb 17, 2008
 */
package uk.me.parabola.mkgmap.osmstyle;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Level;

import it.unimi.dsi.fastutil.longs.Long2ObjectOpenHashMap;
import uk.me.parabola.imgfmt.ExitException;
import uk.me.parabola.imgfmt.Utils;
import uk.me.parabola.imgfmt.app.Area;
import uk.me.parabola.imgfmt.app.Coord;
import uk.me.parabola.imgfmt.app.CoordNode;
import uk.me.parabola.imgfmt.app.Exit;
import uk.me.parabola.imgfmt.app.Label;
import uk.me.parabola.imgfmt.app.net.AccessTagsAndBits;
import uk.me.parabola.imgfmt.app.net.GeneralRouteRestriction;
import uk.me.parabola.imgfmt.app.net.RoadDef;
import uk.me.parabola.imgfmt.app.trergn.ExtTypeAttributes;
import uk.me.parabola.imgfmt.app.trergn.MapObject;
import uk.me.parabola.log.Logger;
import uk.me.parabola.mkgmap.CommandArgs;
import uk.me.parabola.mkgmap.build.LocatorConfig;
import uk.me.parabola.mkgmap.filters.LineSizeSplitterFilter;
import uk.me.parabola.mkgmap.filters.LineSplitterFilter;
import uk.me.parabola.mkgmap.general.AreaClipper;
import uk.me.parabola.mkgmap.general.Clipper;
import uk.me.parabola.mkgmap.general.LineAdder;
import uk.me.parabola.mkgmap.general.LineClipper;
import uk.me.parabola.mkgmap.general.MapCollector;
import uk.me.parabola.mkgmap.general.MapElement;
import uk.me.parabola.mkgmap.general.MapExitPoint;
import uk.me.parabola.mkgmap.general.MapLine;
import uk.me.parabola.mkgmap.general.MapPoint;
import uk.me.parabola.mkgmap.general.MapRoad;
import uk.me.parabola.mkgmap.general.MapShape;
import uk.me.parabola.mkgmap.osmstyle.housenumber.HousenumberGenerator;
import uk.me.parabola.mkgmap.reader.osm.CoordPOI;
import uk.me.parabola.mkgmap.reader.osm.Element;
import uk.me.parabola.mkgmap.reader.osm.FakeIdGenerator;
import uk.me.parabola.mkgmap.reader.osm.FeatureKind;
import uk.me.parabola.mkgmap.reader.osm.GType;
import uk.me.parabola.mkgmap.reader.osm.MultiPolygonRelation;
import uk.me.parabola.mkgmap.reader.osm.Node;
import uk.me.parabola.mkgmap.reader.osm.OsmConverter;
import uk.me.parabola.mkgmap.reader.osm.Relation;
import uk.me.parabola.mkgmap.reader.osm.RestrictionRelation;
import uk.me.parabola.mkgmap.reader.osm.Rule;
import uk.me.parabola.mkgmap.reader.osm.Style;
import uk.me.parabola.mkgmap.reader.osm.TagDict;
import uk.me.parabola.mkgmap.reader.osm.Tags;
import uk.me.parabola.mkgmap.reader.osm.TypeResult;
import uk.me.parabola.mkgmap.reader.osm.Way;
import uk.me.parabola.util.ElementQuadTree;
import uk.me.parabola.util.EnhancedProperties;
import uk.me.parabola.util.MultiHashMap;

/**
 * Convert from OSM to the mkgmap intermediate format using a style.
 * A style is a collection of files that describe the mappings to be used
 * when converting.
 *
 * @author Steve Ratcliffe
 */
public class StyledConverter implements OsmConverter {
	private static final Logger log = Logger.getLogger(StyledConverter.class);
	private static final Logger roadLog = Logger.getLogger(StyledConverter.class.getName()+".roads");

	private final NameFinder nameFinder; 

	private final MapCollector collector;

	private Clipper clipper = Clipper.NULL_CLIPPER;
	private Area bbox = Area.PLANET;

	private final List<RestrictionRelation> restrictions = new ArrayList<>();
	private final MultiHashMap<Long, RestrictionRelation> wayRelMap = new MultiHashMap<>();
	
	private Map<Node, List<Way>> poiRestrictions = new LinkedHashMap<>();
	private Map<Node, CoordNode> replacedCoordPoi = new HashMap<>();
	 
	// limit line length to avoid problems with portions of really
	// long lines being assigned to the wrong subdivision
	private static final int MAX_LINE_LENGTH = 40000;

	// limit arc lengths to what can be handled by RouteArc
	private static final int MAX_ARC_LENGTH = 20450000; // (1 << 22) * 16 / 3.2808 ~ 20455030*/
	
	// limit number of points so that a single road doesn't have too many polylines 
	private static final int MAX_ROAD_POINTS = (RoadDef.MAX_NUMBER_POLYLINES - 2) * LineSplitterFilter.MAX_POINTS_IN_LINE; 
	

	/** Number of routing nodes in way, possibly could be increased, not a hard limit in IMG format.
	 * See also RoadDef.MAX_NUMBER_NODES. 
	 */
	private static final int MAX_NODES_IN_WAY = 64;  

	// nodeIdMap maps a Coord into a CoordNode
	private IdentityHashMap<Coord, CoordNode> nodeIdMap = new IdentityHashMap<>();

	public static final String WAY_POI_NODE_IDS = "mkgmap:way-poi-node-ids";
	private static final short TKM_HAS_DIRECTION = TagDict.getInstance().xlate("mkgmap:has-direction");
	
	/** boundary ways with admin_level=2 */
	private final Set<Way> borders = new LinkedHashSet<>();
	private boolean addBoundaryNodesAtAdminBoundaries;
	private int admLevelNod3;
	
	private List<ConvertedWay> roads = new ArrayList<>();
	private List<ConvertedWay> lines = new ArrayList<>();

	private int nextRoadId = 1;
	
	private HousenumberGenerator housenumberGenerator;
	
	private final Rule wayRules;
	private final Rule nodeRules;
	private final Rule lineRules;
	private final Rule polygonRules;
	private Style style;

	private String driveOn;
	private Boolean driveOnLeft;
	private int numDriveOnLeftRoads;
	private int numDriveOnRightRoads;
	private int numDriveOnSideUnknown;
	private int numRoads;
	
	private String countryAbbr;

	private final boolean checkRoundaboutDirections;
	private final boolean fixRoundaboutDirections;
	private final int reportDeadEnds; 
	private final boolean linkPOIsToWays;
	private final boolean mergeRoads;
	private final boolean allowReverseMerge;
	private final Set<Integer> lineTypesWithDirection = new HashSet<>();

	private final boolean routable;
	private boolean forceEndNodesRoutingNodes; 
	private final Tags styleOptionTags;
	private static final String STYLE_OPTION_PREF = "mkgmap:option:";
	private final PrefixSuffixFilter prefixSuffixFilter;
	private final boolean keepBlanks;
	
	private LineAdder lineAdder;
	private NearbyPoiHandler nearbyPoiHandler;

	static List<String> unusedStyleOptions = new ArrayList<>();
	static List<String> duplicateKeys = new ArrayList<>();
	static List<String> unspecifiedStyleOptions = new ArrayList<>();
	
	public StyledConverter(Style style, MapCollector collector, EnhancedProperties props) {
		this.collector = collector;

		nameFinder = new NameFinder(props);
		this.style = style;
		wayRules = style.getWayRules();
		nodeRules = style.getNodeRules();
		lineRules = style.getLineRules();
		polygonRules = style.getPolygonRules();
		// perform legacy test, older versions of mkgmap used to set mkgmap:dest_hint=true
		// newer version will set it to a reasonable destination string
		if (lineRules.containsExpression("$mkgmap:dest_hint='true'")){
			log.error("At least one 'lines' rule in the style contains the expression mkgmap:dest_hint=true, it should be changed to mkgmap:dest_hint=*");
		}
		housenumberGenerator = new HousenumberGenerator(props);
		
		driveOn = props.getProperty("drive-on", null);
		if (driveOn == null)
			driveOn = "detect,right";
		switch (driveOn) {
		case "left":
			driveOnLeft = true; 
			break;
		case "right":
			driveOnLeft = false; 
			break;
		case "detect":
		case "detect,left":
		case "detect,right":
			break;
		default:
			throw new ExitException("invalid parameters for option drive-on:" + driveOn);
		}
		countryAbbr = props.getProperty("country-abbr", null);
		if (countryAbbr != null)
			countryAbbr = countryAbbr.toUpperCase();

		if (props.getProperty("check-roundabouts", false)) {//deprecated
			checkRoundaboutDirections = log.isLoggable(Level.WARNING);
			fixRoundaboutDirections = true;
		} else {
			String checkRoundaboutsOption = props.getProperty("report-roundabout-issues");
			boolean check = false;
			if (checkRoundaboutsOption != null) {
				if ("".equals(checkRoundaboutsOption))
					check = true;
				for (String option : checkRoundaboutsOption.split(",")) {
					if ("all".equals(option) || "direction".equals(option))
						check = true;
				}
			}
			checkRoundaboutDirections = check;
			fixRoundaboutDirections = props.getProperty("fix-roundabout-direction",false);
		}
		reportDeadEnds = (props.getProperty("report-dead-ends") != null) ? props.getProperty("report-dead-ends", 1) : 0;  
		prefixSuffixFilter = new PrefixSuffixFilter(props);

		lineAdder = line -> {
			if (line instanceof MapRoad) {
				prefixSuffixFilter.filter((MapRoad) line);
				collector.addRoad((MapRoad) line);
			} else {
				collector.addLine(line);
			}
		};
		LineAdder overlayAdder = style.getOverlays(lineAdder);
		if (overlayAdder != null)
			lineAdder = overlayAdder;
		linkPOIsToWays = props.getProperty("link-pois-to-ways", false);
		nearbyPoiHandler = new NearbyPoiHandler(props);
		
		// undocumented option - usually used for debugging only
		mergeRoads = !props.getProperty("no-mergeroads", false);
		allowReverseMerge = props.getProperty("allow-reverse-merge", false);
		final String typesOption = "line-types-with-direction";
		String typeList = props.getProperty(typesOption, "");
		if (typeList.isEmpty())
			typeList = style.getOption(typesOption);
		List<String> types = CommandArgs.stringToList(typeList, typesOption);
		for (String type :types) {
			if (!type.isEmpty()) {
				lineTypesWithDirection.add(Integer.decode(type));
			}
		}
		routable = props.containsKey("route");
		String styleOption= props.getProperty("style-option",null);
		styleOptionTags = parseStyleOption(styleOption);
		
		// control calculation of extra nodes in NOD3 / NOD4
		admLevelNod3 = props.getProperty("add-boundary-nodes-at-admin-boundaries", 2);
		addBoundaryNodesAtAdminBoundaries = routable && admLevelNod3 > 0;
		keepBlanks = props.containsKey("keep-blanks");
		forceEndNodesRoutingNodes = !props.getProperty("no-force-end-nodes-routing-nodes", false);
	}

	/**
	 * Handle style option parameter. Create tags which are added to each element
	 * before style processing starts. Cross-check usage of the options with the style.
	 * @param styleOption the user option 
	 * @return Tags instance created from the option.
	 */
	private Tags parseStyleOption(String styleOption) {
		Tags styleTags = new Tags();
		if (styleOption != null) {
			// expected: --style-option=car;farms=more;admin5=10
			String[] tags = styleOption.split(";");
			for (String t : tags) {
				String[] pair = t.split("=");
				String optionKey = pair[0];
				String tagKey = STYLE_OPTION_PREF + optionKey;
				if (!style.getUsedTags().contains(tagKey)) {
					synchronized(unusedStyleOptions) {
						if (!unusedStyleOptions.contains(optionKey)) {
							unusedStyleOptions.add(optionKey);
							Logger.defaultLogger.warn("Option style-options sets tag not used in style: '" 
									+ optionKey + "' (gives " + tagKey + ")");
						}
					}
				}
				String val = (pair.length == 1) ? "true" : pair[1];
				String old = styleTags.put(tagKey, val);
				if (old != null) {
					synchronized(duplicateKeys) {
						if (!duplicateKeys.contains(optionKey)) {
							duplicateKeys.add(optionKey);
							Logger.defaultLogger.error("duplicate tag key", optionKey, "in style option", styleOption);
						}
					}
				}
			}
		}
		// flag options used in style but not specified in --style-option
		if (style.getUsedTags() != null) {
			for (String s : style.getUsedTags()) {
				if (s != null && s.startsWith(STYLE_OPTION_PREF) && styleTags.get(s) == null) {
					synchronized(unspecifiedStyleOptions) {
						if (!unspecifiedStyleOptions.contains(s)) {
							unspecifiedStyleOptions.add(s);
							Logger.defaultLogger.warn("Option style-options doesn't specify '"
									+ s.replaceFirst(STYLE_OPTION_PREF, "") + "' (for " + s + ")");
						}
					}
				}
			}
		}
		return styleTags;
	}	

	/** One type result for ways to avoid recreating one for each way. */ 
	private final WayTypeResult wayTypeResult = new WayTypeResult();

	private class WayTypeResult implements TypeResult {
		private Way way;
		/** flag if the rule was fired */
		private boolean matched;
		
		public void setWay(Way way) {
			this.way = way;
			this.matched = false;
		}
		
		public void add(Element el, GType type) {
			this.matched = true;
			if (type.isContinueSearch() && el == way) {
				// If not already copied, do so now
				el = way.copy();
			}
			postConvertRules(el, type);
			if (!type.isRoad())
				housenumberGenerator.addWay((Way) el);
			addConvertedWay((Way) el, type);
		}

		private void addConvertedWay(Way way, GType foundType) {
			if (foundType.getFeatureKind() == FeatureKind.POLYGON){ 
				addShape(way, foundType);
				return;
			}
			
			boolean wasReversed = false;
			String oneWay = way.getTag(TK_ONEWAY);
			if (oneWay != null){
				if("-1".equals(oneWay)) {
					// it's a oneway street in the reverse direction
					// so reverse the order of the nodes and change
					// the oneway tag to "yes"
					way.reverse();
					wasReversed = true;
					way.addTag(TK_ONEWAY, "yes");
				}
				if (way.tagIsLikeYes(TK_ONEWAY)) {
					way.addTag(TK_ONEWAY, "yes");
					if (foundType.isRoad() && hasSkipDeadEndCheckNode(way))
						way.addTag("mkgmap:dead-end-check", "false");
				} else { 
					way.deleteTag(TK_ONEWAY);
				}
			}
			ConvertedWay cw = new ConvertedWay(way, foundType);
			cw.setReversed(wasReversed);

			boolean hasDirection = cw.isOneway(); // overwritten if not road
			if (way.tagIsLikeYes(TKM_HAS_DIRECTION))
				hasDirection = true;
			else if (way.tagIsLikeNo(TKM_HAS_DIRECTION))
				hasDirection = false;
			else if (lineTypesWithDirection.contains(foundType.getType()))
				hasDirection = true;
			else if (!cw.isRoad()) // ignore oneway setting
				hasDirection = false;
			cw.setHasDirection(hasDirection);

			if (cw.isRoad()) {
				if (way.getId() == lastRoadId) {
					for (int i = roads.size() - 1; i >= 0; i--) {
						ConvertedWay prevRoad = roads.get(i);
						if (prevRoad.getWay().getId() != lastRoadId)
							break;
						if (RoadMerger.isMergeable(way.getFirstPoint(), prevRoad, cw, true)) {
							log.warn("Ignoring duplicate road", foundType, "for", way.getBasicLogInformation());
							return;
						}
					}
				}

				roads.add(cw);
				numRoads++;
				// ignore driving side for oneway roads, ferries and roads that
				// don't allow motor vehicles
				if (!cw.isOneway() && !cw.isFerry()
						&& (cw.getAccess() & ~(AccessTagsAndBits.FOOT | AccessTagsAndBits.BIKE)) != 0) {
					String countryIso = LocatorConfig.get().getCountryISOCode(way.getTag(TKM_COUNTRY));
					if (countryIso != null) {
						boolean drivingSideIsLeft = LocatorConfig.get().getDriveOnLeftFlag(countryIso);
						if (drivingSideIsLeft)
							numDriveOnLeftRoads++;
						else
							numDriveOnRightRoads++;
						if (driveOnLeft != null && drivingSideIsLeft != driveOnLeft)
							log.warn("wrong driving side", way.toBrowseURL());
						if (log.isDebugEnabled())
							log.debug("assumed driving side is", (drivingSideIsLeft ? "left" : "right"),
									way.toBrowseURL());
					} else {
						numDriveOnSideUnknown++;
					}
				}
				if (cw.isRoundabout() && wasReversed && checkRoundaboutDirections) {
					log.diagnostic("Roundabout " + way.getId() +
							" has reverse oneway tag (" + way.getFirstPoint().toOSMURL() + ")");
				}
				lastRoadId = way.getId();
			} else {
				lines.add(cw);
			}
		}

		private void addShape(Way way, GType gt) {
			// This is deceptively simple. At the time of writing, splitter only retains points that are within
			// the tile and some distance around it.  Therefore a way that is closed in reality may not be closed
			// as we see it in its incomplete state.
			//
			if (!way.hasIdenticalEndPoints() && way.hasEqualEndPoints())
				log.error("shape is not closed with identical points " + way.getId());
			if (!way.hasIdenticalEndPoints())
				return;
			// TODO: split self intersecting polygons?
			final MapShape shape = new MapShape(way.getId());
			elementSetup(shape, gt, way);
			shape.setPoints(way.getPoints());

			long areaVal = 0;
			String tagStringVal = way.getTag(TKM_DRAW_LEVEL);
			if (tagStringVal != null) {
				try {
					areaVal = Integer.parseInt(tagStringVal);
					if (areaVal < 1 || areaVal > 100) {
						log.error("mkgmap:drawLevel must be in range 1..100, not", areaVal);
						areaVal = 0;
					} else if (areaVal <= 50) {
						areaVal = Long.MAX_VALUE - areaVal; // 1 => MAX_VALUE-1, 50 => MAX_VALUE-50
					} else {
						areaVal = 101 - areaVal; // 51 => 50, 100 => 1
					}
				} catch (NumberFormatException e) {
					log.error("mkgmap:drawLevel invalid integer:", tagStringVal);
				}
			}
			if (areaVal == 0)
				areaVal = way.getFullArea();
			shape.setFullArea(areaVal);
			shape.setMpRel(way.getMpRel());
			clipper.clipShape(shape, collector);
		}

		/**
		 * Check if the first or last of the coords of the way has a flag set for skipping dead end check
		 * @param way the way to check 
		 * @return true if flag was found
		 */
		private boolean hasSkipDeadEndCheckNode(Way way) {
			return way.getFirstPoint().isSkipDeadEndCheck() || way.getLastPoint().isSkipDeadEndCheck();
		}


		/**
		 * Retrieves if a rule of the style matched and the way is converted.
		 * @return {@code true} way is converted; {@code false} way is not converted
		 */
		public boolean isMatched() {
			return matched;
		}
	}
	
	
	/**
	 * This takes the way and works out what kind of map feature it is and makes
	 * the relevant call to the mapper callback.
	 * <p>
	 * As a few examples we might want to check for the 'highway' tag, work out
	 * if it is an area of a park etc.
	 *
	 * @param way The OSM way.
	 */
	private static final short TKM_STYLEFILTER = TagDict.getInstance().xlate("mkgmap:stylefilter");
	private static final short TKM_MAKE_CYCLE_WAY = TagDict.getInstance().xlate("mkgmap:make-cycle-way");
	private long lastRoadId = 0; 
	private int lineCacheId = 0;
	private BitSet routingWarningWasPrinted = new BitSet();
	
	@Override
	public void convertWay(final Way way) {
		if (way.getPoints().size() < 2 || way.getTagCount() == 0){
			// no tags or no points => nothing to convert
			removeRestrictionsWithWay(Level.WARNING, way, "is ignored");
			return;
		}
		if (addBoundaryNodesAtAdminBoundaries) {
			// is this a country border ? 
			if (!FakeIdGenerator.isFakeId(way.getId()) && isNod3Border(way)) {
				borders.add(way);
			}
		}

		preConvertRules(way);

		String styleFilterTag = way.getTag(TKM_STYLEFILTER);
		Rule rules;
		if ("polyline".equals(styleFilterTag))
			rules = lineRules;
		else if ("polygon".equals(styleFilterTag))
			rules = polygonRules;
		else {
			if (way.isClosedInOSM() && !way.isComplete() && !way.hasIdenticalEndPoints())
				way.getPoints().add(way.getFirstPoint());
			
			if (!way.hasIdenticalEndPoints() || way.getPoints().size() < 4)
				rules = lineRules;
			else
				rules = wayRules;
		}
		Way cycleWay = null;
		String cycleWayTag = way.getTag(TKM_MAKE_CYCLE_WAY);
		if ("yes".equals(cycleWayTag)){
			way.deleteTag(TKM_MAKE_CYCLE_WAY);
			cycleWay = makeCycleWay(way);
			way.addTag("bicycle", "no"); // make sure that bicycles are using the added bicycle way 
		}
		wayTypeResult.setWay(way);
		lineCacheId = rules.resolveType(lineCacheId, way, wayTypeResult);
		if (!wayTypeResult.isMatched()) {
			// no match found but we have to keep it for house number processing
			housenumberGenerator.addWay(way);
			if (way.getMpRel() != null) {
				// not all polygons for the multipolygon are rendered
				way.getMpRel().setNoRecalc(true);
			}
		}
		if (cycleWay != null){
			wayTypeResult.setWay(cycleWay);
			lineCacheId = rules.resolveType(lineCacheId, cycleWay, wayTypeResult);
			if (!wayTypeResult.isMatched()) {
				// no match found but we have to keep it for house number processing
				housenumberGenerator.addWay(cycleWay);
			}
		}
		if (lastRoadId != way.getId()){
			// this way was not added to the roads list
			removeRestrictionsWithWay(Level.WARNING, way, "is not routable");
		} else {
			// way was added as road, check if we also have non-routable lines for the way
			// which have to be skipped by WrongAngleFixer
			for (int i = lines.size() - 1; i >= 0; --i) {
				ConvertedWay cw = lines.get(i);
				if (cw.getWay().getId() == way.getId()) {
					cw.setOverlay(true);
					int lineType = cw.getGType().getType();
					if (GType.isSpecialRoutableLineType(lineType) && cw.getGType().getMinLevel() == 0
							&& !routingWarningWasPrinted.get(lineType)) {
						log.error("routable type", GType.formatType(cw.getGType().getType()),
								"is used with a non-routable way which was also added as a routable way. This leads to routing errors.",
								"Try --check-styles to check the style.");
						routingWarningWasPrinted.set(lineType);
					}
				} else {
					break;
				}
			}
		}
	}

	private boolean isNod3Border(Element el) {
		if ("administrative".equals(el.getTag("boundary"))) {
			String admLevelString = el.getTag("admin_level");
			if (admLevelString != null) {
				try {
					int al = Integer.parseInt(admLevelString);
					return al <= admLevelNod3;
				} catch (NumberFormatException e) {
					// ignore invalid osm data
				}
			}
		}
		return false;
	}

	private static final short TK_ONEWAY = TagDict.getInstance().xlate("oneway"); 

	/** One type result for nodes to avoid recreating one for each node. */ 
	private NodeTypeResult nodeTypeResult = new NodeTypeResult();
	
	
	private class NodeTypeResult implements TypeResult {
		private Node node;
		/** flag if the rule was fired */
		private boolean matched;
		
		public void setNode(Node node) {
			this.node = node;
			this.matched = false;
		}
		
		public void add(Element el, GType type) {
			this.matched = true;
			if (type.isContinueSearch() && el == node) {
				// If not already copied, do so now
				el = node.copy();
			}

			postConvertRules(el, type);
			housenumberGenerator.addNode((Node) el);
			addPoint((Node) el, type);
		}

		private void addPoint(Node node, GType gt) {
			if (!clipper.contains(node.getLocation()))
				return;

			// to handle exit points we use a subclass of MapPoint
			// to carry some extra info (a reference to the
			// motorway associated with the exit)
			MapPoint mp;
			int type = gt.getType();
			if (type >= 0x2000 && type < 0x2800) {
				String ref = node.getTag(Exit.TAG_ROAD_REF);
				String id = node.getTag("mkgmap:osmid");
				if (ref != null) {
					String to = node.getTag(Exit.TAG_TO);
					MapExitPoint mep = new MapExitPoint(ref, to);
					String fd = node.getTag(Exit.TAG_FACILITY);
					if (fd != null)
						mep.setFacilityDescription(fd);
					if (id != null)
						mep.setOSMId(id);
					mp = mep;
				} else {
					mp = new MapPoint();
					if ("motorway_junction".equals(node.getTag("highway")))
						log.warn("Motorway exit", node.getName(), "(" + node.toBrowseURL()
								+ ") has no (motorway) ref! (either make the exit share a node with the motorway or specify the motorway ref with a",
								Exit.TAG_ROAD_REF, "tag)");
				}
			} else {
				mp = new MapPoint();
			}
			elementSetup(mp, gt, node);
			mp.setLocation(node.getLocation());
			nearbyPoiHandler.add(mp, node);
		}

		/**
		 * Retrieves if a rule of the style matched and the node is converted.
		 * @return {@code true} node is converted; {@code false} node is not converted
		 */
		public boolean isMatched() {
			return matched;
		}
	}

	/**
	 * Takes a node (that has its own identity) and converts it from the OSM
	 * type to the Garmin map type.
	 *
	 * @param node The node to convert.
	 */
	@Override
	public void convertNode(final Node node) {
		if (node.getTagCount() == 0) {
			// no tags => nothing to convert
			return;
		}

		preConvertRules(node);

		nodeTypeResult.setNode(node);
		nodeRules.resolveType(node, nodeTypeResult);
		if (!nodeTypeResult.isMatched()) {
			// no match found but we have to keep it for house number processing
			housenumberGenerator.addNode(node);
		}
	}
	

	/**
	 * Rules to run before converting the element.
	 */
	private void preConvertRules(Element el) {
		// add tags given with --style-option
		if (styleOptionTags != null && styleOptionTags.size() > 0) {
			Iterator<Entry<Short, String>> iter = styleOptionTags.entryShortIterator();
			while (iter.hasNext()) {
				Entry<Short, String> tag = iter.next();
				el.addTag(tag.getKey(), tag.getValue());
			}
		}
		
		nameFinder.setNameWithNameTagList(el);
	}

	/**
	 * Construct a cycleway that has the same points as an existing way.  Used for separate
	 * cycle lanes.
	 * @param way The original way.
	 * @return The new way, which will have the same points and have suitable cycle tags.
	 */
	private static Way makeCycleWay(Way way) {
		Way cycleWay = new Way(way.getId(), way.getPoints());
		cycleWay.copyTags(way);

		cycleWay.addTag("access", "no");
		cycleWay.addTag("bicycle", "yes");
		cycleWay.addTag("mkgmap:synthesised", "yes");
		cycleWay.addTag(TK_ONEWAY, "no");
		// remove explicit access tags 
		cycleWay.deleteTag("foot");
		cycleWay.deleteTag("motorcar");
		cycleWay.deleteTag("goods");
		cycleWay.deleteTag("hgv");
		cycleWay.deleteTag("bus");
		cycleWay.deleteTag("taxi");
		cycleWay.deleteTag("emergency");
		cycleWay.deleteTag("vehicle");
		cycleWay.deleteTag("motor_vehicle");
		cycleWay.deleteTag("carpool");
		cycleWay.deleteTag("motorcycle");
		cycleWay.deleteTag("psv");
		cycleWay.deleteTag("truck");
		return cycleWay;
	}
	
	/**
	 * Invoked after the raw OSM data has been read and hooks run, but before any of the convertXxx() calls
	 *
	 * @param elementSaver Gives access to the pre-converted OSM data
	 */
	@Override
	public void augmentWith(uk.me.parabola.mkgmap.reader.osm.ElementSaver elementSaver) {
		// wayRules doesn't need to be done (or must be done first) because is concat. of line & polygon rules
		nodeRules.augmentWith(elementSaver);
		lineRules.augmentWith(elementSaver);
		polygonRules.augmentWith(elementSaver);
	}

	/**
	 * Built in rules to run after converting the element.
	 */
	private static void postConvertRules(Element el, GType type) {
		// Set the default_name if no name is set
		if (type.getDefaultName() != null && el.getName() == null)
			el.addTag("mkgmap:label:1", type.getDefaultName());
	}

	/**
	 * Set the bounding box for this map.  This should be set before any other
	 * elements are converted if you want to use it. All elements that are added
	 * are clipped to this box, new points are added as needed at the boundary.
	 *
	 * If a node or a way falls completely outside the boundary then it would be
	 * omitted.  This would not normally happen in the way this option is typically
	 * used however.
	 *
	 * @param bbox The bounding area, must not be null.
	 */
	@Override
	public void setBoundingBox(Area bbox) {
		this.clipper = new AreaClipper(bbox);
		this.bbox = bbox;

		// we calculate our own bounding box, now let the collector know about it.
		collector.addToBounds(new Coord(bbox.getMinLat(), bbox.getMinLong()));
		collector.addToBounds(new Coord(bbox.getMaxLat(), bbox.getMaxLong()));
	}

	/**
	 * Remove all restriction relations that are invalid if the way will not appear
	 * in the NOD file.
	 * @param logLevel 
	 * @param way the way that was removed
	 * @param reason explanation for the removal
	 */
	private void removeRestrictionsWithWay(Level logLevel, Way way, String reason){
		List<RestrictionRelation> rrList = wayRelMap.get(way.getId());
		for (RestrictionRelation rr : rrList) {
			if (!rr.isValidWithoutWay(way.getId())) {
				if (log.isLoggable(logLevel)) {
					log.log(logLevel, "restriction", rr.toBrowseURL(), "is ignored because referenced way",
							way.toBrowseURL(), reason);
				}
				rr.setInvalid();
				restrictions.remove(rr);
			}
		}
	}

	/**
	 * Find all intersections of roads with country borders.
	 * If a node exists close to the intersection, use the existing node, else add one. The nodes will be 
	 * written as external nodes to NOD file (NOD3 + NOD4)
	 */
	private void checkRoutingNodesAtAdminBoundaries() {
		if (!addBoundaryNodesAtAdminBoundaries || borders.isEmpty())
			return;
		long t1 = System.currentTimeMillis();

		// prepare boundary ways so that we can search them
		List<Element> clippedBorders = new ArrayList<>();
		for (Way b : borders) {
			List<List<Coord>> clipped = LineClipper.clip(bbox, b.getPoints());
			if (clipped == null) {
				splitBoundary(clippedBorders, b, b.getPoints());
			} else {
				for (List<Coord> lco : clipped) {
					splitBoundary(clippedBorders, b, lco);
				}
			}
		}
		ElementQuadTree qt = new ElementQuadTree(bbox, clippedBorders);

		long countChg = 0;
		Long2ObjectOpenHashMap<Coord> commonCoordMap = new Long2ObjectOpenHashMap<>();
		for (ConvertedWay r : roads) {
			if (!r.isValid())
				continue;
			Way way = r.getWay();
			Area searchRect = Area.getBBox(way.getPoints());
			Set<Element> boundaries = qt.get(searchRect);
			if (boundaries.isEmpty())
				continue;
			
			// the bounding box of the road intersects with one or more bounding boxes of borders
			Coord pw1 = way.getFirstPoint();
			int pos = 1;
			while (pos < way.getPoints().size()) {
				boolean changed = false;
				Coord pw2 = way.getPoints().get(pos);
				for (Element el : boundaries) {
					List<Coord> b = ((Way) el).getPoints();
					for (int i = 0; i < b.size() - 1; i++) {
						Coord pb1 = b.get(i);
						Coord pb2 = b.get(i + 1);
						Coord is = Utils.getSegmentSegmentIntersection(pw1, pw2, pb1, pb2);
						if (is != null) {
							// intersection can be equal to given nodes on road or close to it
							double dist1 = is.distance(pw1);
							double dist2 = is.distance(pw2);
							if (dist1 < dist2 && dist1 < 1) {
								if (!pw1.getOnCountryBorder()) {
									++countChg;
									if (!pw1.getOnBoundary())
										log.info("road intersects admin boundary, changing existing node to external routing node at", pw1);
								}
								pw1.setOnCountryBorder(true);
							} else if (dist2 < dist1 && dist2 < 1) {
								if (!pw2.getOnCountryBorder()) {
									++countChg;
									if (!pw2.getOnBoundary())
										log.info("road intersects admin boundary, changing existing node to external routing node at", pw2);
								}
								pw2.setOnCountryBorder(true);
							} else {
								long key = Utils.coord2Long(is);
								Coord replacement = commonCoordMap.get(key);
								if (replacement == null) {
									commonCoordMap.put(key, is);
								} else {
									assert is.highPrecEquals(replacement);
									is = replacement;
								}
								is.setOnCountryBorder(true);
								log.info("road intersects admin boundary, adding external routing node at", is);
								
								way.getPoints().add(pos, is);
								changed = true;
								pw2 = is;
							}
						}
					}
				}
				if (!changed) {
					++pos;
					pw1 = pw2;
				}
			}
		}
		long t2 = System.currentTimeMillis() - t1;
		log.info("added",commonCoordMap.size(),"new nodes at country borders");
		log.info("marked",countChg,"existing nodes at country borders");
		log.info("adding country border routing nodes took " + t2 + " ms");

	}
	
	/**
	 * Split complex border ways into smaller portions.
	 * @param clippedBorders
	 * @param orig
	 * @param points
	 */
	private static void splitBoundary(List<Element> clippedBorders, Way orig, List<Coord> points) {
		int pos = 0;
		final int max = 20; // seems to be a good compromise
		while (pos < points.size()) {
			int right = Math.min(points.size(), pos + max);
			Way w = new Way(orig.getId(), points.subList(pos, right));
			w.markAsGeneratedFrom(orig);
			clippedBorders.add(w);
			pos += max - 1;
			if (pos + 1 == points.size())
				pos--;
		}
	}


	/**
	 * Merges roads with identical attributes (GType, OSM tags) to reduce the size of the 
	 * road network.
	 */
	private void mergeRoads() {
		if (mergeRoads) {
			roads = new RoadMerger(allowReverseMerge).merge(roads, restrictions);
		} else {
			log.info("Merging roads is disabled");
		}
	}
	
	@Override
	public void end() {
		style.reportStats();
		driveOnLeft = calcDrivingSide();
		
		checkRoutingNodesAtAdminBoundaries();
		borders.clear();
		
		setHighwayCounts();
		HashMap<Long, ConvertedWay> modifiedRoads = new HashMap<>();
		findUnconnectedRoads();
		rotateClosedWaysToFirstNode(modifiedRoads);
		filterCoordPOI();

		HashSet<Long> deletedRoads = new HashSet<>();
		WrongAngleFixer wrongAngleFixer = new WrongAngleFixer(bbox);
		
		Set<MapPoint> allPOI = nearbyPoiHandler.getAllPOI();
		wrongAngleFixer.optimizeWays(roads, lines, modifiedRoads, deletedRoads, restrictions, allPOI);
		nearbyPoiHandler.deDuplicate().forEach(collector::addPoint);
		nearbyPoiHandler = null;
		
		// make sure that copies of modified roads have equal points 
		for (ConvertedWay line : lines){
			if (!line.isValid())
				continue; 
			Way way = line.getWay();
			if (deletedRoads.contains(way.getId())){
				line.getPoints().clear();
				continue;
			}
			if (!line.isOverlay())
				continue;
			ConvertedWay modWay = modifiedRoads.get(way.getId());
			if (modWay != null){
				List<Coord> points = line.getPoints();
				points.clear();
				points.addAll(modWay.getPoints());
				if (modWay.isReversed() != line.isReversed())
					Collections.reverse(points);
			} 
		}
		for (Long wayId: deletedRoads){
			if (wayRelMap.containsKey(wayId)){
				// may happen e.g. when very short way is leading to nowhere 
				log.warn("Way that is used in valid restriction relation was removed, id:",wayId);
			}
		}
		deletedRoads.clear();
		modifiedRoads.clear(); 
		mergeRoads();
		
		resetHighwayCounts();
		setHighwayCounts();
		
		for (ConvertedWay cw : lines) {
			if (cw.isValid())
				addLine(cw);
		}
		lines = null;
		if (roadLog.isInfoEnabled()) {
			roadLog.info("Flags: oneway,no-emergency, no-delivery, no-throughroute, no-truck, no-bike, no-foot, carpool, no-taxi, no-bus, no-car");
			roadLog.info(String.format("%19s %4s %11s %6s %6s %6s %s", "Road-OSM-Id","Type","Flags", "Class", "Speed", "Points", "Labels"));
		}
		// add the roads after the other lines
		for (ConvertedWay cw : roads){
			if (cw.isValid())
				addRoad(cw);
		}
		housenumberGenerator.generate(lineAdder);
		housenumberGenerator = null;
		
		if (routable)
			poiRestrictions.entrySet().forEach(e -> createRouteRestrictionsFromPOI(e.getKey(), e.getValue()));
		poiRestrictions = null;
		replacedCoordPoi = null;
		if (routable){
			for (RestrictionRelation rr : restrictions) {
				rr.addRestriction(collector, nodeIdMap);
			}
		}
		// return memory to GC
		roads = null;
		nodeIdMap = null;
		restrictions.clear();
	}

	/**
	 * Check the counters and verify the driveOn value to calculate
	 * the drive on left flag. 
	 */
	private Boolean calcDrivingSide() {
		Boolean dol = null;
		log.info("Found", numRoads, "roads",
				numDriveOnLeftRoads, "in drive-on-left country,",
				numDriveOnRightRoads, "in drive-on-right country, and",
				numDriveOnSideUnknown, "with unknown country");
		if (numDriveOnLeftRoads> 0 &&  numDriveOnRightRoads > 0)
			log.error("Attention: Tile contains both drive-on-left (" + numDriveOnLeftRoads + 
					") and drive-on-right roads (" + numDriveOnRightRoads + ")");
		if (driveOn.startsWith("detect")) {
			if (numDriveOnSideUnknown > numRoads * 0.05){
				// warn if more than 5% of the roads are in unknown area
				log.warn("Found", numDriveOnSideUnknown, "roads with unknown country and driving side");
			}
			if (numDriveOnLeftRoads > numDriveOnRightRoads + numDriveOnSideUnknown) {
				dol = true;
			} else if (numDriveOnRightRoads > numDriveOnLeftRoads + numDriveOnSideUnknown) {
				dol = false;
			} else {
				if (driveOn.endsWith("left"))
					dol = true;
				else 
					dol = false;
			}
			log.info("detected value for driving on left flag is:",dol);			
		} else {
			dol = ("left".equals(driveOn));
			// warn if user given flag is obviously wrong
			if ("left".equals(driveOn) && numDriveOnLeftRoads == 0 && numDriveOnRightRoads > 0)
				log.warn("The drive-on-left flag is set but tile contains only drive-on-right roads");
			if ("right".equals(driveOn) && numDriveOnRightRoads == 0 && numDriveOnLeftRoads > 0)
				log.warn("The drive-on-left flag is NOT set but tile contains only drive-on-left roads");
		}		
		assert dol != null;
		return dol;
	}

	/**
	 * Try to make sure that closed ways start with a point that is 
	 * also part of another road. This reduces the number of nodes
	 * a little bit.
	 * @param modifiedRoads Will contain roads modified by this routine  
	 * 
	 */
	private void rotateClosedWaysToFirstNode(HashMap<Long, ConvertedWay> modifiedRoads ) {
		for (ConvertedWay cw: roads){
			if (!cw.isValid())
				continue;
			Way way = cw.getWay();
			List<Coord> points = way.getPoints();
			if (points.size() < 3)
				continue;
			if (points.get(0) != points.get(points.size()-1))
				continue;
			// this is a closed way 
			Coord p0 = points.get(0);
			if (p0.getHighwayCount() > 2)
				continue;
			
			for (int i = 1; i < points.size() - 1;i++){
				Coord p = points.get(i);
				if (p.getHighwayCount() > 1){
					p.incHighwayCount(); // this will be the new first + last point
					// first point connects only last point, remove last
					points.remove(points.size()-1);
					p0.decHighwayCount();
					Collections.rotate(points, -i);
					points.add(points.get(0)); // close again
					modifiedRoads.put(way.getId(), cw); 
					break;
				}
			}
		}
	}

	/**
	 * Check if roundabout has correct direction. Set driveOnRight or
	 * driveOnLeft is not yet set.
	 * 
	 */
	private void checkRoundabout(ConvertedWay cw) {
		if (!cw.isRoundabout())
			return;
		Way way = cw.getWay();
		List<Coord> points = way.getPoints();
		// if roundabout checking is enabled and roundabout has at
		// least 3 points and it has not been marked as "don't
		// check", check its direction
		if ((checkRoundaboutDirections || fixRoundaboutDirections) && points.size() > 2
				&& !way.tagIsLikeYes("mkgmap:no-dir-check")
				&& !way.tagIsLikeNo("mkgmap:dir-check")) {
			Coord centre = way.getCofG();
			int dir = 0;
			// check every third segment
			for (int i = 0; (i + 1) < points.size(); i += 3) {
				Coord pi = points.get(i);
				Coord pi1 = points.get(i + 1);
				// TODO: check if high prec coords allow to use smaller
				// distance
				// don't check segments that are very short
				if (pi.distance(centre) > 2.5 && pi.distance(pi1) > 2.5) {
					// determine bearing from segment that starts with
					// point i to centre of roundabout
					double a = pi.bearingTo(pi1);
					double b = pi.bearingTo(centre) - a;
					while (b > 180)
						b -= 360;
					while (b < -180)
						b += 360;
					// if bearing to centre is between 15 and 165
					// degrees consider it trustworthy
					if (b >= 15 && b < 165)
						++dir;
					else if (b <= -15 && b > -165)
						--dir;
				}
			}
			if (dir == 0)
				log.info("Roundabout segment " + way.getId()
						+ " direction unknown (see "
						+ points.get(0).toOSMURL() + ")");
			else {
				boolean clockwise = dir > 0;
				boolean dirIsWrong = (Boolean.TRUE.equals(driveOnLeft) && !clockwise || Boolean.FALSE.equals(driveOnLeft) && clockwise);
				if (points.get(0) == points.get(points.size() - 1)) {
					// roundabout is a loop
					if (dirIsWrong) {
						if (checkRoundaboutDirections)
							log.diagnostic("Roundabout " + way.getId() + " direction is wrong " + (fixRoundaboutDirections ? "- reversing it " : "") +
								"(see " + centre.toOSMURL() + ")");
						if (fixRoundaboutDirections)
							way.reverse();
					}
				} else if (dirIsWrong) {
					// roundabout is a line
					if (checkRoundaboutDirections)
						log.diagnostic("Roundabout segment " + way.getId() + " direction looks wrong (see "
							+ points.get(0).toOSMURL() + ")");
				}
			}
		}
	}
	
	/**
	 * If POI changes access restrictions (e.g. bollards), create corresponding
	 * route restrictions so that only allowed vehicles/pedestrians are routed
	 * through this point.
	 * @param node the node with a CoordPOI
	 * @param wayList the list of ways in which this node appears
	 */
	private void createRouteRestrictionsFromPOI(Node node, List<Way> wayList) {
		Coord p = node.getLocation(); 
		// list of ways that are connected to the poi

		byte exceptMask = AccessTagsAndBits.evalAccessTags(node);
		Map<Integer,CoordNode> otherNodeIds = new LinkedHashMap<>();
		CoordNode viaNode = null;
		CoordNode neededNode = nodeIdMap.get(p);
		if (neededNode == null) {
			neededNode = replacedCoordPoi.get(node);
		}
		if (neededNode == null) {
			log.error("link-pois-to-ways: Internal error: Did not find CoordPOI node at", p.toOSMURL(), "in ways",
					wayList);
			return;
		}
		for (Way way : wayList) {
			CoordNode lastNode = null;
			for (Coord co : way.getPoints()) {
				if (!(co instanceof CoordNode))
					continue;
				CoordNode cn = (CoordNode) co;
				if (co == neededNode) {
					viaNode = cn;
					if (lastNode != null)
						otherNodeIds.put(lastNode.getId(), lastNode);
				} else if (lastNode == neededNode) {
					otherNodeIds.put(cn.getId(), cn);
				}
				lastNode = cn;
			}
		}
		if (otherNodeIds.size() < 2) {
			log.info("link-pois-to-ways: Access restriction in POI node", node.toBrowseURL(),
					"was ignored, has no effect on any connected way");
			return;
		}
		GeneralRouteRestriction rr = new GeneralRouteRestriction("no_through", exceptMask, "link-pois-to-ways: CoordPOI at " + p.toOSMURL());
		rr.setViaNodes(Arrays.asList(viaNode));
		int added = collector.addRestriction(rr);
		log.info("link-pois-to-ways: Access restriction in POI node", node.toBrowseURL(),
		 ((added == 0) ? " was ignored, has no effect on any connected way"
				: "was translated to " + added + " route restriction(s)"));

		if (wayList.size() > 1 && added > 2){
			log.warn("link-pois-to-ways: Access restriction in POI node", node.toBrowseURL(), "affects routing on multiple ways");
		}
	}

 	
	/**
	 * Run the rules for this relation.  As this is not an end object, then
	 * the only useful rules are action rules that set tags on the contained
	 * ways or nodes.  Every rule should probably start with 'type=".."'.
	 *
	 * @param relation The relation to convert.
	 */
	@Override
	public void convertRelation(Relation relation) {
		if (relation.getTagCount() == 0) {
			// no tags => nothing to convert
			return;
		}

		housenumberGenerator.addRelation(relation);

		// relation rules are not applied here because they are applied
		// earlier by the RelationStyleHook
		if(relation instanceof RestrictionRelation) {
			RestrictionRelation rr = (RestrictionRelation)relation;
			if(rr.isValid()) {
				restrictions.add(rr);
				for (long id : rr.getWayIds())
					wayRelMap.add(id, rr);
			}
		} else if (addBoundaryNodesAtAdminBoundaries
				&& (relation instanceof MultiPolygonRelation || "boundary".equals(relation.getTag("type")))
				&& isNod3Border(relation)) {
			for (Entry<String, Element> e : relation.getElements()) {
				if (FakeIdGenerator.isFakeId(e.getValue().getId()))
					continue;
				if (e.getValue() instanceof Way)
					borders.add((Way) e.getValue());
			}
		}
	}
	
	private void addLine(ConvertedWay cw) {
		addLine(cw, -1);
	}
	
	private void addLine(ConvertedWay cw, int replType) {
		List<Coord> wayPoints = cw.getPoints();
		List<Coord> points = new ArrayList<>(wayPoints.size());
		double lineLength = 0;
		Coord lastP = null;
		for (Coord p : wayPoints) {
			if (p.highPrecEquals(lastP))
				continue;
			
			points.add(p);
			if(lastP != null) {
				lineLength += p.distance(lastP);
				if(lineLength >= MAX_LINE_LENGTH) {
					if (log.isInfoEnabled())
						log.info("Splitting line", cw.getWay().toBrowseURL(), "at", p.toOSMURL(), "to limit its length to", (long)lineLength + "m");
					addLine(cw, replType, points);
					points = new ArrayList<>(wayPoints.size() - points.size() + 1);
					points.add(p);
					lineLength = 0;
				}
			}
			lastP = p;
		}

		if(points.size() > 1)
			addLine(cw, replType, points);
	}

	private void addLine(ConvertedWay cw, int replType, List<Coord> points) {
		MapLine line = new MapLine();
		elementSetup(line, cw.getGType(), cw.getWay());
		if (replType >= 0)
			line.setType(replType);
		line.setPoints(points);

		line.setDirection(cw.hasDirection());

		clipper.clipLine(line, lineAdder);
	}

	private static final short[] labelTagKeys = {
		TagDict.getInstance().xlate("mkgmap:label:1"),
		TagDict.getInstance().xlate("mkgmap:label:2"),
		TagDict.getInstance().xlate("mkgmap:label:3"),
		TagDict.getInstance().xlate("mkgmap:label:4"),
	};
	private static final short TKM_HIGHEST_RES_ONLY = TagDict.getInstance().xlate("mkgmap:highest-resolution-only");
	private static final short TKM_SKIP_SIZE_FILTER = TagDict.getInstance().xlate("mkgmap:skipSizeFilter");
	private static final short TKM_DRAW_LEVEL = TagDict.getInstance().xlate("mkgmap:drawLevel");

	private static final short TKM_COUNTRY = TagDict.getInstance().xlate("mkgmap:country");
	private static final short TKM_REGION = TagDict.getInstance().xlate("mkgmap:region");
	private static final short TKM_CITY = TagDict.getInstance().xlate("mkgmap:city");
	private static final short TKM_POSTAL_CODE = TagDict.getInstance().xlate("mkgmap:postal_code");
	private static final short TKM_STREET = TagDict.getInstance().xlate("mkgmap:street");
	private static final short TKM_HOUSENUMBER = TagDict.getInstance().xlate("mkgmap:housenumber");
	private static final short TKM_PHONE = TagDict.getInstance().xlate("mkgmap:phone");
	private static final short TKM_IS_IN = TagDict.getInstance().xlate("mkgmap:is_in");
	
	private void elementSetup(MapElement ms, GType gt, Element element) {
		String[] labels = new String[4];
		int numLabels = 0;
		for (int labelNo = 0; labelNo < 4; labelNo++) {
			String label1 = element.getTag(labelTagKeys[labelNo]);
			String label = keepBlanks ? label1 : Label.squashSpaces(label1);
			if (label != null) {
				labels[numLabels] = label;
				numLabels++;
			} 
		}

		if (labels[0] != null) {
			ms.setLabels(labels);
		}
		ms.setType(gt.getType());
		ms.setMinResolution(gt.getMinResolution());
		ms.setMaxResolution(gt.getMaxResolution());

		if (element.tagIsLikeYes(TKM_HIGHEST_RES_ONLY)){
			ms.setMinResolution(ms.getMaxResolution());
		}
		
		if (ms instanceof MapLine && element.tagIsLikeYes(TKM_SKIP_SIZE_FILTER)){
			((MapLine)ms).setSkipSizeFilter(true);
		}
		
		// Now try to get some address info for POIs
		
		String country      = element.getTag(TKM_COUNTRY);
		String region       = element.getTag(TKM_REGION);
		String city         = element.getTag(TKM_CITY);
		String zip          = element.getTag(TKM_POSTAL_CODE);
		String street 	    = element.getTag(TKM_STREET);
		String houseNumber  = element.getTag(TKM_HOUSENUMBER);
		String phone        = element.getTag(TKM_PHONE);
		String isIn         = element.getTag(TKM_IS_IN);

		if(country != null)
			ms.setCountry(country);

		if(region != null)
			ms.setRegion(region);
		
		if(city != null)
			ms.setCity(city);
		  
		if(zip != null)
			ms.setZip(zip);

		if (street == null)  
			street = element.getTag("addr:place");
		
		if(street != null)
			ms.setStreet(street);

		if(houseNumber != null)
			ms.setHouseNumber(houseNumber);
		  
		if(isIn != null)
			ms.setIsIn(isIn);
			
		if(phone != null)
			ms.setPhone(phone);


		
		if(MapObject.hasExtendedType(gt.getType())) {
			// pass attributes with mkgmap:xt- prefix (strip prefix)
			Map<String,String> xta = element.getTagsWithPrefix("mkgmap:xt-", true);
			// also pass all attributes with seamark: prefix (no strip prefix)
			xta.putAll(element.getTagsWithPrefix("seamark:", false));
			ms.setExtTypeAttributes(new ExtTypeAttributes(xta, "OSM id " + element.getId()));
		}
	}

	/**
	 * Add a way to the road network. May call itself recursively and
	 * might truncate the way if splitting is required. 
	 * @param cw the converted way
	 */
	private void addRoad(ConvertedWay cw) {
		Way way = cw.getWay();
		if (way.getPoints().size() < 2){
			log.warn("road has < 2 points",way.getId(),"(discarding)");
			return;
		}

		
		checkRoundabout(cw);

		// process any Coords that have a POI associated with them
		final double stubSegmentLength = 25; // metres
		String wayPOI = way.getTag(WAY_POI_NODE_IDS);
		if (wayPOI != null) {
			List<Coord> points = way.getPoints();
			
			// look for POIs that modify the way's road class or speed
			// or contain access restrictions
			// This could be e.g. highway=traffic_signals that reduces the
			// road speed to cause a short increase of travelling time
			// or a barrier
			for(int i = 0; i < points.size(); ++i) {
				Coord p = points.get(i);
				if (p instanceof CoordPOI && ((CoordPOI) p).isUsed()) {
					CoordPOI cp = (CoordPOI) p;
					Node node = cp.getNode();
					if (wayPOI.contains("["+node.getId()+"]")){
						log.debug("POI",node.getId(),"changes way",way.getId());

						// make sure that we create nodes for all POI that 
						// are converted to RouteRestrictions
						if(p.getHighwayCount() < 2 && cp.getConvertToViaInRouteRestriction() && (i != 0 && i != points.size()-1))
							p.incHighwayCount();
						
						String roadClass = node.getTag("mkgmap:road-class");
						String roadSpeed = node.getTag("mkgmap:road-speed");
						if(roadClass != null || roadSpeed != null) {
							if (!way.isViaWay()) {
								// find good split point after POI
								Coord splitPoint;
								double segmentLength = 0;
								int splitPos = i + 1;
								while (splitPos + 1 < points.size()) {
									splitPoint = points.get(splitPos);
									segmentLength += splitPoint.distance(points.get(splitPos - 1));
									if (splitPoint.getHighwayCount() > 1 || segmentLength > stubSegmentLength - 5)
										break;
									splitPos++;
								}
								if (segmentLength > stubSegmentLength + 10) {
									// insert a new point after the POI to
									// make a short stub segment
									splitPoint = points.get(splitPos);
									Coord prev = points.get(splitPos - 1);
									double dist = splitPoint.distance(prev);
									double neededLength = stubSegmentLength - (segmentLength - dist);

									splitPoint = prev.makeBetweenPoint(splitPoint, neededLength / dist);
									double newDist = splitPoint.distance(prev);
									segmentLength += newDist - dist;
									points.add(splitPos, splitPoint);
									splitPoint.incHighwayCount(); // new point is on highway
								}
								if ((splitPos + 1) < points.size()
										&& safeToSplitWay(points, splitPos, i, points.size() - 1)) {
									Way tail = splitWayAt(way, splitPos);
									// recursively process tail of way
									addRoad(new ConvertedWay(cw, tail));
								}
							}
							boolean classChanged = cw.recalcRoadClass(node);
							if (classChanged && log.isInfoEnabled()) {
								log.info("link-pois-to-ways: POI is changing road class of", way.toBrowseURL(), "to", cw.getRoadClass(), "at",
										points.get(0).toOSMURL());
							}
							boolean speedChanged = cw.recalcRoadSpeed(node);
							if (speedChanged && log.isInfoEnabled()) {
								log.info("link-pois-to-ways: POI is changing road speed of", way.toBrowseURL(), "to", cw.getRoadSpeed(), "at",
										points.get(0).toOSMURL());
							}
						}
					}
				}

				// if this isn't the last point in the way
				// and the next point modifies the way's speed/class,
				// split the way at this point to limit the size of
				// the affected region
				if (!way.isViaWay() && i + 1 < points.size()
						&& points.get(i + 1) instanceof CoordPOI) {
					CoordPOI cp = (CoordPOI) points.get(i + 1);
					Node node = cp.getNode();
					if (cp.isUsed() && wayPOI.contains("[" + node.getId() + "]")
							&& (node.getTag("mkgmap:road-class") != null || node.getTag("mkgmap:road-speed") != null)) {
						// find good split point before POI
						double segmentLength = 0;
						int splitPos = i;
						Coord splitPoint;
						while (splitPos >= 0) {
							splitPoint = points.get(splitPos);
							segmentLength += splitPoint.distance(points.get(splitPos + 1));
							if (splitPoint.getHighwayCount() >= 2 || segmentLength > stubSegmentLength - 5)
								break;
							--splitPos;
						}
						if (segmentLength > stubSegmentLength + 10) {
							// insert a new point before the POI to
							// make a short stub segment
							splitPoint = points.get(splitPos);
							Coord prev = points.get(splitPos + 1);
							double dist = splitPoint.distance(prev);
							double neededLength = stubSegmentLength - (segmentLength - dist);
							splitPoint = prev.makeBetweenPoint(splitPoint, neededLength / dist);
							segmentLength += splitPoint.distance(prev) - dist;
							splitPos++;
							points.add(splitPos, splitPoint);
							splitPoint.incHighwayCount(); // new point is on highway
						}
						if (splitPos > 0 && safeToSplitWay(points, splitPos, 0, points.size() - 1)) {
							Way tail = splitWayAt(way, splitPos);
							// recursively process tail of way
							addRoad(new ConvertedWay(cw, tail));
						}
					}
				}
			}

		} 
		// if there is a bounding box, clip the way with it

		List<Way> clippedWays = null;

		if(bbox != null) {
			List<List<Coord>> lineSegs = LineClipper.clip(bbox, way.getPoints());

			if (lineSegs != null) {
				if (lineSegs.isEmpty()){
					removeRestrictionsWithWay(Level.WARNING, way, "ends on tile boundary, restriction is ignored");
				}
				clippedWays = new ArrayList<>();

				for (List<Coord> lco : lineSegs) {
					Way nWay = new Way(way.getId());
					nWay.copyTags(way);
					for(Coord co : lco) {
						nWay.addPoint(co);
						if(co.getOnBoundary() || co.getOnCountryBorder()) {
							// this point lies on a boundary
							// make sure it becomes a node
							co.incHighwayCount();
						}
					}
					clippedWays.add(nWay);
				}
			}
		}

		if(clippedWays != null) {
			for(Way clippedWay : clippedWays) {
				addRoadAfterSplittingLoops(new ConvertedWay(cw, clippedWay));
			}
		}
		else {
			// no bounding box or way was not clipped
			addRoadAfterSplittingLoops(cw);
		}
	}

	/**
	 * Split way so that it does not self intersect. 
	 * TODO: Maybe avoid if map is not routable?
	 * @param cw the converted way
	 */
	private void addRoadAfterSplittingLoops(ConvertedWay cw) {
		Way way = cw.getWay();
		
		if (routable && (forceEndNodesRoutingNodes || wayRelMap.containsKey(way.getId()))) {
			// make sure the way has nodes at each end
			way.getPoints().get(0).incHighwayCount();
			way.getPoints().get(way.getPoints().size() - 1).incHighwayCount();
		}
		
		// check if the way is a loop or intersects with itself

		boolean wayWasSplit = true; // aka rescan required

		while(wayWasSplit) {
			List<Coord> wayPoints = way.getPoints();
			int numPointsInWay = wayPoints.size();

			wayWasSplit = false; // assume way won't be split

			// check each point in the way to see if it is the same
			// point as a following point in the way (actually the
			// same object not just the same coordinates)
			for(int p1I = 0; !wayWasSplit && p1I < (numPointsInWay - 1); p1I++) {
				Coord p1 = wayPoints.get(p1I);
				if (p1.getHighwayCount() < 2)
					continue;
				int niceSplitPos = -1;
				for(int p2I = p1I + 1; !wayWasSplit && p2I < numPointsInWay; p2I++) {
					Coord p2 = wayPoints.get(p2I);
					if (p1 != p2){
						if (p2.getHighwayCount() > 1)
							niceSplitPos = p2I;
					} else {
						// way is a loop or intersects itself 
						// attempt to split it into two ways

						// start at point before intersection point
						// check that splitting there will not produce
						// a zero length arc - if it does try the
						// previous point(s)
						int splitI;
						if (niceSplitPos >= 0 && safeToSplitWay(wayPoints, niceSplitPos, p1I, p2I))
							// prefer to split at a point that is going to be a node anyway
							splitI = niceSplitPos;
						else {
							splitI = p2I - 1;
						while(splitI > p1I &&
							  !safeToSplitWay(wayPoints, splitI, p1I, p2I)) {
							if (log.isInfoEnabled())
								log.info("Looped way", way.getDebugName(), "can't safely split at point[" + splitI + "], trying the preceeding point");
							--splitI;
						}
						}
						if(splitI == p1I) {
							log.info("Splitting looped way", way.getDebugName(), "would make a zero length arc, so it will have to be pruned at", wayPoints.get(p2I).toOSMURL());
							do {
								log.info("  Pruning point[" + p2I + "]");
								wayPoints.remove(p2I);
								// next point to inspect has same index
								--p2I;
								// but number of points has reduced
								--numPointsInWay;

								if (p2I + 1 == numPointsInWay) 
									wayPoints.get(p2I).incHighwayCount();
								// if wayPoints[p2I] is the last point
								// in the way and it is so close to p1
								// that a short arc would be produced,
								// loop back and prune it
							} while(p2I > p1I &&
									(p2I + 1) == numPointsInWay &&
									p1.equals(wayPoints.get(p2I)));
						}
						else {
							// split the way before the second point
							if (log.isInfoEnabled())
								log.info("Splitting looped way", way.getDebugName(), "at", wayPoints.get(splitI).toOSMURL(), "- it has", (numPointsInWay - splitI - 1 ), "following segment(s).");
							Way loopTail = splitWayAt(way, splitI);
							
							ConvertedWay next = new ConvertedWay(cw, loopTail);
							
							// recursively check (shortened) head for
							// more loops
							addRoadAfterSplittingLoops(cw);
							// now process the tail of the way
							cw = next;
							way = loopTail;
							wayWasSplit = true;
						}
					}
				}
			}

			if(!wayWasSplit) {
				// no split required so make road from way
				addRoadWithoutLoops(cw);
			}
		}
	}

	
	/**
	 * safeToSplitWay() returns true if it is safe (no short arcs will be
	 * created) to split a way at a given position - assumes that the
	 * floor and ceiling points will become nodes even if they are not
	 * yet.
	 * @param points	the way's points
	 * @param pos	the position we are testing
	 * @param floor lower limit of points to test (inclusive)
	 * @param ceiling upper limit of points to test (inclusive)
	 * @return true if is OK to split as pos
	 */
	private static boolean safeToSplitWay(List<Coord> points, int pos, int floor, int ceiling) {
		Coord candidate = points.get(pos);
		// avoid running off the ends of the list
		if(floor < 0)
			floor = 0;
		if(ceiling >= points.size())
			ceiling = points.size() - 1;
		// test points after pos
		for(int i = pos + 1; i <= ceiling; ++i) {
			Coord p = points.get(i);
			if(i == ceiling || p.getHighwayCount() > 1) {
				// point is going to be a node
				if(candidate.equals(p)) {
					// coordinates are equal, that's too close
					return false;
				}
				// no need to test further
				break;
			}
		}
		// test points before pos
		for(int i = pos - 1; i >= floor; --i) {
			Coord p = points.get(i);
			if(i == floor || p.getHighwayCount() > 1) {
				// point is going to be a node
				if(candidate.equals(p)) {
					// coordinates are equal, that's too close
					return false;
				}
				// no need to test further
				break;
			}
		}

		return true;
	}

	private void addRoadWithoutLoops(ConvertedWay cw) {
		Way way = cw.getWay();
		List<Integer> nodeIndices = new ArrayList<>();
		List<Coord> points = way.getPoints();
		if (points.size() < 2){
			log.warn("road has < 2 points",way.getId(),"(discarding)");
			return;
		}
		Way trailingWay = null;
		String debugWayName = way.getDebugName();

		// collect the Way's nodes and also split the way if any
		// inter-node arc length becomes excessive
		double arcLength = 0;
		// track the dimensions of the way's bbox so that we can
		// detect if it would be split by the LineSizeSplitterFilter
		class WayBBox {
			int minLat = Integer.MAX_VALUE;
			int maxLat = Integer.MIN_VALUE;
			int minLon = Integer.MAX_VALUE;
			int maxLon = Integer.MIN_VALUE;

			void addPoint(Coord co) {
				int lat = co.getLatitude();
				if(lat < minLat)
					minLat = lat;
				if(lat > maxLat)
					maxLat = lat;
				int lon = co.getLongitude();
				if(lon < minLon)
					minLon = lon;
				if(lon > maxLon)
					maxLon = lon;
			}

			boolean tooBig() {
				return LineSizeSplitterFilter.testDims(maxLat - minLat,
													   maxLon - minLon) >= 1.0;
			}
		}

		WayBBox wayBBox = new WayBBox();
		
		for(int i = 0; i < points.size(); ++i) {
			Coord p = points.get(i);

			wayBBox.addPoint(p);

			// check if we should split the way at this point to limit
			// the arc length between nodes
			if((i + 1) < points.size()) {
				Coord nextP = points.get(i + 1);
				double d = p.distance(nextP);
				for (;;){
					int dlat = Math.abs(nextP.getLatitude() - p.getLatitude());
					int dlon = Math.abs(nextP.getLongitude() - p.getLongitude());
					if (d > MAX_ARC_LENGTH || Math.max(dlat, dlon) >= LineSizeSplitterFilter.MAX_SIZE) {
						double frac = Math.min(0.5, 0.95 * (MAX_ARC_LENGTH / d));
						nextP = p.makeBetweenPoint(nextP, frac);
						nextP.incHighwayCount();
						points.add(i + 1, nextP);
						double newD = p.distance(nextP);
						if (log.isInfoEnabled())
							log.info("Way", debugWayName, "contains a segment that is",
									(int) d + "m long but I am adding a new point to reduce its length to",
									(int) newD + "m");
						d = newD;
					} else {
						break;
					}
				}
				
				wayBBox.addPoint(nextP);

				if (i >= MAX_ROAD_POINTS) {
					trailingWay = splitWayAt(way, i);
					// this will have truncated the current Way's
					// points so the loop will now terminate
					if (log.isInfoEnabled())
						log.info("Splitting way", debugWayName, "at", points.get(i).toOSMURL(), "to limit the total number of points");
				} else if ((arcLength + d) > MAX_ARC_LENGTH) {
					if (i <= 0)
						log.error("internal error: long arc segment was not split", debugWayName);
					assert i > 0 : "long arc segment was not split";
					assert trailingWay == null : "trailingWay not null #1";
					trailingWay = splitWayAt(way, i);
					// this will have truncated the current Way's
					// points so the loop will now terminate
					if (log.isInfoEnabled())
						log.info("Splitting way", debugWayName, "at", points.get(i).toOSMURL(), "to limit arc length to", (long)arcLength + "m");
				}
				else if(wayBBox.tooBig()) {
					if (i <= 0)
						log.error("internal error: arc segment with big bbox not split", debugWayName);
					assert i > 0 : "arc segment with big bbox not split";
					assert trailingWay == null : "trailingWay not null #2";
					trailingWay = splitWayAt(way, i);
					// this will have truncated the current Way's
					// points so the loop will now terminate
					if (log.isInfoEnabled())
						log.info("Splitting way", debugWayName, "at", points.get(i).toOSMURL(), "to limit the size of its bounding box");
				}
				else {
					if(p.getHighwayCount() > 1) {
						// point is a node so zero arc length
						arcLength = 0;
					}

					arcLength += d;
				}
			}
			if(p.getHighwayCount() > 1 || (routable && p.getOnCountryBorder())) {
				// this point is a node connecting highways
				if (p instanceof CoordPOI){
					// check if this POI should be converted to a route restriction
					CoordPOI cp = (CoordPOI) p;
					if (cp.getConvertToViaInRouteRestriction()){
						String wayPOI = way.getTag(WAY_POI_NODE_IDS);
						if (wayPOI != null && wayPOI.contains("[" + cp.getNode().getId() + "]")){
							byte nodeAccess = AccessTagsAndBits.evalAccessTags(cp.getNode());
							if (nodeAccess != cw.getAccess()){
								poiRestrictions.computeIfAbsent(cp.getNode(), k -> new ArrayList<>()).add(way);
							}
						}
					}
				}
				
				// add this index to node Indexes (should not already be there)
				assert !nodeIndices.contains(i) : debugWayName + " has multiple nodes for point " + i + " new node is " + p.toOSMURL();
				nodeIndices.add(i);

				if((i + 1) < points.size() &&
				   nodeIndices.size() == MAX_NODES_IN_WAY) {
					// this isn't the last point in the way so split
					// it here to avoid exceeding the max nodes in way
					// limit
					assert trailingWay == null : "trailingWay not null #7";
					trailingWay = splitWayAt(way, i);
					// this will have truncated the current Way's
					// points so the loop will now terminate
					if (log.isInfoEnabled())
						log.info("Splitting way", debugWayName, "at", points.get(i).toOSMURL(), "as it has at least", MAX_NODES_IN_WAY, "nodes");
				}
			}
		}

		MapLine line = new MapLine();
		elementSetup(line, cw.getGType(), way);
		line.setPoints(points);
		MapRoad road = new MapRoad(nextRoadId++, way.getId(), line);
		if (!routable) {
			road.skipAddToNOD(true);
		}
		
		boolean doFlareCheck = true;
		
		if (cw.isRoundabout()){
			road.setRoundabout(true);
			doFlareCheck = false;
		}

		if(way.tagIsLikeYes("mkgmap:synthesised")) {
			road.setSynthesised(true);
			doFlareCheck = false;
		}

		if(way.tagIsLikeNo("mkgmap:flare-check")) {
			doFlareCheck = false;
		}
		else if(way.tagIsLikeYes("mkgmap:flare-check")) {
			doFlareCheck = true;
		}
		road.doFlareCheck(doFlareCheck);

		// set road parameters 

		// copy road class and road speed
		road.setRoadClass(cw.getRoadClass());
		road.setSpeed(cw.getRoadSpeed());
		
		if (cw.isOneway()) {
			road.setOneway();
		}
		road.setDirection(cw.hasDirection());

		road.setAccess(cw.getAccess());
		
		// does the road have a carpool lane?
		if (cw.isCarpool())
			road.setCarpoolLane();

		if (!cw.isThroughroute())
			road.setNoThroughRouting();

		if (cw.isToll())
			road.setToll();

		// by default, ways are paved
		if (cw.isUnpaved())
			road.paved(false);

		// by default, way's are not ferry routes
		if (cw.isFerry())
			road.ferry(true);

		if (routable && nodeIndices.isEmpty()) {
			// this is a road not connected to other roads, make sure that its first node will be a routing node 
			nodeIndices.add(0);
		}
		
		int numNodes = nodeIndices.size();
		if (way.isViaWay() && numNodes > 2) {
			List<RestrictionRelation> rrList = wayRelMap.get(way.getId());
			for (RestrictionRelation rr : rrList) {
				rr.updateViaWay(way, nodeIndices);
			}
		}

		if(numNodes > 0) {
			// replace Coords that are nodes with CoordNodes
			for(int i = 0; i < numNodes; ++i) {
				int n = nodeIndices.get(i);
				Coord p = points.get(n);
				CoordNode coordNode = nodeIdMap.get(p);
				if(coordNode == null) {
					// assign a unique node id > 0
					int uniqueId = nodeIdMap.size() + 1;
					coordNode = new CoordNode(p, uniqueId, p.getOnBoundary(), p.getOnCountryBorder());
					nodeIdMap.put(p, coordNode);
				}
				if ((p.getOnBoundary() || p.getOnCountryBorder()) && log.isInfoEnabled()) {
					log.info("Way", debugWayName + "'s point #" + n, "at", p.toOSMURL(), "is a boundary node");
				}
				if (p instanceof CoordPOI && ((CoordPOI) p).getNode().getLocation() != p) {
					// special case: WrongAngleFixer created a new CoordPOI instance and our node still points to
					// the old instance
					replacedCoordPoi.put(((CoordPOI) p).getNode(), coordNode);
				}
				points.set(n, coordNode);
			}
		}

		if (roadLog.isInfoEnabled()) {
			// shift the bits so that they have the correct position
			int cmpAccess = (road.getRoadDef().getTabAAccess() & 0xff) + ((road.getRoadDef().getTabAAccess() & 0xc000) >> 6);
			if (road.isDirection()) {
				cmpAccess |= 1<<10;
			}
			String access = String.format("%11s",Integer.toBinaryString(cmpAccess)).replace(' ', '0');
			roadLog.info(String.format("%19d 0x%-2x %11s %6d %6d %6d %s", way.getId(), road.getType(), access, road.getRoadDef().getRoadClass(), road.getRoadDef().getRoadSpeed(), road.getPoints().size(),Arrays.toString(road.getLabels())));
		}
		
		// add the road to the housenumber generator
		// it will add the road later on to the lineAdder
		housenumberGenerator.addRoad(way, road);

		if(trailingWay != null)
			addRoadWithoutLoops(new ConvertedWay(cw, trailingWay));
	}

	/**
	 * split a Way at the specified point and return the new Way (the
	 * original Way is truncated, both ways will contain the split point)
	 * @param way the way to split
	 * @param index the split position. 
	 * @return the trailing part of the way
	 */
	private Way splitWayAt(Way way, int index) {
		if (way.isViaWay()){
			removeRestrictionsWithWay(Level.WARNING, way, "is split, restriction will be ignored");
		}
		Way trailingWay = new Way(way.getId());
		List<Coord> wayPoints = way.getPoints();
		int numPointsInWay = wayPoints.size();

		for(int i = index; i < numPointsInWay; ++i)
			trailingWay.addPoint(wayPoints.get(i));

		// ensure split point becomes a node
		wayPoints.get(index).incHighwayCount();

		// copy the way's name and tags to the new way
		trailingWay.copyTags(way);

		// remove the points after the split from the original way
		// it's probably more efficient to remove from the end first
		for(int i = numPointsInWay - 1; i > index; --i)
			wayPoints.remove(i);
		
		return trailingWay;
	}

	/**
	 * Increment the highway counter for each coord of each road.
	 * As a result, all road junctions have a count > 1. 
	 */
	private void setHighwayCounts(){
		log.debug("Maintaining highway counters");
		long lastId = 0;
		List<Way> dupIdHighways = new ArrayList<>();
		for (ConvertedWay cw :roads){
			if (!cw.isValid())
				continue;
			Way way = cw.getWay();
			if (way.getId() == lastId) {
				log.debug("Road with identical id:", way.getId());
				dupIdHighways.add(way);
				continue;
			}
			lastId = way.getId();
			way.getPoints().forEach(Coord::incHighwayCount);
		}
		
		// go through all duplicated highways and increase the highway counter of all crossroads
		
		for (Way way : dupIdHighways) {
			List<Coord> points = way.getPoints();
			// increase the highway counter of the first and last point
			points.get(0).incHighwayCount();
			points.get(points.size()-1).incHighwayCount();
			
			// for all other points increase the counter only if other roads are connected
			for (int i = 1; i <  points.size()-1; i++) {
				Coord p = points.get(i);
				if (p.getHighwayCount() > 1) {
					// this is a crossroads - mark that the duplicated way is also part of it 
					p.incHighwayCount();
				}
			}
		}
	}

	
	/**
	 * Increment the highway counter for each coord of each road.
	 * As a result, all road junctions have a count > 1. 
	 */
	private void resetHighwayCounts(){
		log.debug("Resetting highway counters");
		long lastId = 0;
		for (ConvertedWay cw :roads){
			Way way = cw.getWay();
			if (!cw.isValid() || way.getId() == lastId) 
				continue;
			
			lastId = way.getId();
			way.getPoints().forEach(Coord::resetHighwayCount);
		}
	}

	private static final String[] CONNECTION_TAGS = { "mkgmap:set_unconnected_type", "mkgmap:set_semi_connected_type" };

	/**
	 * Detect roads that do not share any node with another road.
	 * If such a road has the mkgmap:set_unconnected_type tag, add it as line, not as a road. 
	 * Detect also roads which are only connected in one point, so that they don't lead to other roads.
	 * If such a road has the mkgmap:set_semi_connected_type tag, add it as line, not as a road. 
	 */
	private void findUnconnectedRoads() {
		Map<Coord, HashSet<Way>> connectors = new IdentityHashMap<>(roads.size() * 2);

		// for dead-end-check only: will contain ways with loops (also simply closed ways)
		HashSet<Way> selfConnectors = new HashSet<>();

		// collect nodes that might connect roads
		long lastId = 0;
		for (ConvertedWay cw : roads) {
			Way way = cw.getWay();
			if (way.getId() == lastId)
				continue;
			lastId = way.getId();
			for (Coord p : way.getPoints()) {
				if (p.getHighwayCount() > 1) {
					HashSet<Way> ways = connectors.get(p);
					if (ways == null) {
						ways = new HashSet<>();
						connectors.put(p, ways);
					}
					boolean wasNew = ways.add(way);
					if (!wasNew && reportDeadEnds > 0)
						selfConnectors.add(way);
				}
			}
		}

		/** roads with 0 .. 1 connections to other roads */
		Map<Long,Integer> poorlyConnectedRoads= new HashMap<>();
		
		Iterator<ConvertedWay> iter = roads.iterator();
		while (iter.hasNext()) {
			ConvertedWay cw = iter.next();
			if (!cw.isValid())
				continue;
			Way way = cw.getWay();
			if (reportDeadEnds > 0) {
				reportDeadEnds(cw, connectors, selfConnectors);
			}
			boolean onBoundary = false;
			int countCon = 0;
			for (Coord p : way.getPoints()) {
				if (p.getOnBoundary()) {
					onBoundary = true;
					break;
				}
				if (p.getHighwayCount() > 1) {
					HashSet<Way> ways = connectors.get(p);
					if (ways != null && ways.size() > 1) {
						++countCon;
					}
				}
			}
			boolean remove = false;
			if (countCon <= 1) {
				remove = handlePoorConnection(countCon, cw, onBoundary);
				if (remove) 
					iter.remove();
				if (!onBoundary) 
					poorlyConnectedRoads.put(way.getId(), countCon);
			} 
		}

		// now check if we have to remove overlay lines
		Iterator<ConvertedWay> linesIter = lines.iterator();
		while (linesIter.hasNext()) {
			ConvertedWay cw = linesIter.next();
			if (cw.isOverlay()) {
				Way way = cw.getWay();
				Integer countCon = poorlyConnectedRoads.get(way.getId());
				if (countCon != null) {
					boolean remove = handlePoorConnection(countCon, cw, false);
					if (remove) {
						linesIter.remove();
					}
				}
			}
		}
	}

	/**
	 * When called, the way is either not connected to other roads or it is
	 * only connected in one point. Check if special tags exist which changes the
	 * type or tells mkgmap to remove the line.
	 * 
	 * @param tagKey     the tag key to check
	 * @param cw         the converted way (either a road or an overlay line for the road)
	 * @param onBoundary if true, don't change anything
	 * @return true if the road should not be added to the map
	 */
	private boolean handlePoorConnection(int count, ConvertedWay cw, boolean onBoundary) {
		Way way = cw.getWay();
		String tagKey = CONNECTION_TAGS[count];
		String replTypeString = way.getTag(tagKey);
		if (replTypeString == null) 
			return false;
		StringBuilder sb = new StringBuilder(100);
		sb.append(way.toBrowseURL()).append(' ').append(GType.formatType(cw.getGType().getType()));
		if (cw.isOverlay())
			sb.append("(Overlay)");
		sb.append(": ").append(count == 0 ? "road not connected" : "road doesn't go").append(" to other roads");
		if (onBoundary) {
			log.info(sb.toString(), "but is on boundary");
			return false;
		} 
		sb.append(',');
		if ("none".equals(replTypeString)) {
			log.info(sb.toString(), "is ignored because of", tagKey + "=none");
			return true;
		}
		int replType = -1;
		try {
			replType = Integer.decode(replTypeString);
			if (GType.isSpecialRoutableLineType(replType)) {
				replType = -1;
				log.error("type value in", tagKey, "should not be a routable type:" + replTypeString);
			}
			if (!GType.checkType(FeatureKind.POLYLINE, replType)) {
				replType = -1;
				log.error("type value in", tagKey, "is not a valid line type:" + replTypeString);
			}
		} catch (NumberFormatException e) {
			throw new ExitException("invalid type value in style" + tagKey + "=" + replTypeString);
		}
		if (replType != -1) {
			log.info(sb.toString(), "added as line with type", replTypeString);
			addLine(cw, replType);
		} else {
			log.info(sb.toString(), "but replacement type is invalid. Was dropped");
		}
		return true; // don't add road or line to map
	}

	/**
	 * Check if oneway roads don't allow to continue at the end.
	 * 
	 * @param cw             the converted way
	 * @param connectors     set of nodes where roads are connected
	 * @param selfConnectors set of nodes where roads have loops (rings or p-shapes)
	 */
	private void reportDeadEnds(ConvertedWay cw, Map<Coord, HashSet<Way>> connectors, HashSet<Way> selfConnectors) {
		Way way = cw.getWay();
		// report dead ends of oneway roads if check is not disabled
		if (cw.isOneway() && !way.tagIsLikeNo("mkgmap:dead-end-check")) {
			List<Coord> points = way.getPoints();
			int[] pointsToCheck = { 0, points.size() - 1 };
			if (points.get(pointsToCheck[0]) == points.get(pointsToCheck[1]))
				return; // skip closed way
			for (int pos : pointsToCheck) {
				boolean isDeadEnd = true;
				boolean isDeadEndOfMultipleWays = true;
				Coord p = points.get(pos);
				if (!bbox.contains(p) || p.getOnBoundary())
					isDeadEnd = false; // we don't know enough about possible connections
				else if (p.getHighwayCount() < 2) {
					isDeadEndOfMultipleWays = false;
				} else {
					HashSet<Way> ways = connectors.get(p);
					if (ways.size() <= 1)
						isDeadEndOfMultipleWays = false;
					for (Way connectedWay : ways) {
						if (!isDeadEnd)
							break;
						if (way == connectedWay) {
							if (selfConnectors.contains(way)) {
								// this might be a P-shaped oneway,
								// check if it has other exists in the loop part
								if (pos == 0) {
									for (int k = pos + 1; k < points.size() - 1; k++) {
										Coord pTest = points.get(k);
										if (pTest == p)
											break; // found no other exit
										if (pTest.getHighwayCount() > 1) {
											isDeadEnd = false;
											break;
										}
									}
								} else {
									for (int k = pos - 1; k >= 0; k--) {
										Coord pTest = points.get(k);
										if (pTest == p)
											break; // found no other exit
										if (pTest.getHighwayCount() > 1) {
											isDeadEnd = false;
											break;
										}
									}
								}
							}
							continue;
						}
						List<Coord> otherPoints = connectedWay.getPoints();
						Coord otherFirst = otherPoints.get(0);
						Coord otherLast = otherPoints.get(otherPoints.size() - 1);
						if (otherFirst == otherLast || !connectedWay.tagIsLikeYes(TK_ONEWAY))
							isDeadEnd = false;
						else {
							Coord pOther;
							if (pos != 0)
								pOther = otherLast;
							else
								pOther = otherFirst;
							if (p != pOther) {
								// way is connected to a point on a oneway which allows going on
								isDeadEnd = false;
							}
						}
					}
				}

				if (isDeadEnd && (isDeadEndOfMultipleWays || reportDeadEnds > 1)) {
					log.diagnostic("Oneway road " + way.getId() + " with tags " + way.toTagString()
							+ ((pos == 0) ? " comes from" : " goes to") + " nowhere at " + p.toOSMURL());
				}
			}
		}
	}

	/**
	 * Make sure that only CoordPOI which affect routing will be treated as
	 * nodes in the following routines.
	 */
	private void filterCoordPOI() {
		if (!linkPOIsToWays)
			return;
		log.debug("translating CoordPOI");
		for (ConvertedWay cw: roads) {
			if (!cw.isValid())
				continue;
			Way way = cw.getWay();
			if ("true".equals(way.getTag("mkgmap:way-has-pois"))) {
				StringBuilder wayPOI = new StringBuilder();

				List<Coord> points = way.getPoints();
				int numPoints = points.size();
				for (int i = 0;i < numPoints; i++) {
					Coord p = points.get(i);
					if (p instanceof CoordPOI){
						CoordPOI cp = (CoordPOI) p;
						Node node = cp.getNode();
						boolean usedInThisWay = false;
						byte wayAccess = cw.getAccess();
						if (wayAccess != AccessTagsAndBits.FOOT && (node.getTag("mkgmap:road-class") != null
								|| node.getTag("mkgmap:road-speed") != null)) {
							usedInThisWay = true;
						}
						byte nodeAccess = AccessTagsAndBits.evalAccessTags(node);
						if (nodeAccess != (byte) 0xff) {
							// barriers etc.
							if ((wayAccess & nodeAccess) != wayAccess) {
								// node is more restrictive
								if (p.getHighwayCount() >= 2 || (i != 0 && i != numPoints - 1)) {
									usedInThisWay = true;
									cp.setConvertToViaInRouteRestriction(true);
								} else {
									log.info("link-pois-to-ways: POI node at", node.toBrowseURL(),
											"with access restriction is ignored, it is not connected to other routable ways");
								}
							} else {
								log.info("link-pois-to-ways: Access restriction in POI node", node.toBrowseURL(), "was ignored for way",
										way.toBrowseURL());
							}
						}
						if (usedInThisWay) {
							cp.setUsed(true);
							wayPOI.append('[').append(node.getId()).append(']');
						}
					}
				} 
				if (wayPOI.length() == 0) {
					way.deleteTag("mkgmap:way-has-pois");
					log.info("link-pois-to-ways: ignoring CoordPOI(s) for way", way.toBrowseURL(), "because routing is not affected.");
				} else {
					way.addTag(WAY_POI_NODE_IDS, wayPOI.toString());
				}
			}
		}
	}

	@Override
	public Boolean getDriveOnLeft(){
		assert roads == null : "getDriveOnLeft() should be called after end()";
		return driveOnLeft;
	}
}

