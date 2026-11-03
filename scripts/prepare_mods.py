#!/usr/bin/env python3
"""Prepare reversible Garmin file modifications locally; never write to USB."""
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'evidence/device-research/Themes/Map/United Kingdom.kmtf'
OUT = ROOT / 'staging/Themes/Map/Pi_Contrast.kmtf'


def main():
    tree = ET.parse(SOURCE)
    root = tree.getroot()
    metadata = root.find('METADATA')
    metadata.find('TITLE').text = 'Pi Contrast'
    metadata.find('DESCRIPTION').text = 'High contrast day and night map colours, prepared from this device\'s own theme.'
    # Keep manual theme selection; do not claim a regional default.
    for locale in metadata.findall('LOCALELIST'):
        metadata.remove(locale)
    colours = {
        'MAP_LAND_CLR': ('#F5F5F5', '#101820'),
        'MAP_URBAN_LAND_CLR': ('#E4E4E4', '#17212B'),
        'MAP_WATER_CLR': ('#72B5E8', '#124064'),
        'MAP_MISC_WATER_AREA_CLR': ('#72B5E8', '#124064'),
        'MAP_PARK_CLR': ('#C5DEB0', '#183D28'),
        'MAP_WOODS_CLR': ('#C5DEB0', '#183D28'),
        'MAP_RTE_ACTV_LEG_CLR': ('#D000C4', '#FF63F5'),
        'MAP_RTE_INACTV_LEG_CLR': ('#945090', '#BD8ABB'),
    }
    changed = []
    for style in root.iter('STYLE'):
        field = style.get('field')
        if field in colours:
            for colour in style.findall('COLOR/*'):
                for mode, value in zip(('day', 'night'), colours[field]):
                    if mode in colour.attrib:
                        changed.append({'presentation': next((p.get('ID') for p in root.findall('PRESENTATION') if style in list(p.iter('STYLE'))), None), 'field': field, 'component': colour.tag, 'mode': mode, 'before': colour.get(mode), 'after': value})
                        colour.set(mode, value)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tree.write(OUT, encoding='UTF-8', xml_declaration=True)
    parsed = ET.parse(OUT).getroot()
    if parsed.tag != 'GARMIN_MAP_THEME' or not changed:
        raise RuntimeError('Invalid theme')
    for colour in parsed.findall('.//COLOR/*'):
        for value in colour.attrib.values():
            if not re.fullmatch(r'#[0-9a-fA-F]{6}', value):
                raise RuntimeError('Invalid colour value')
    if [(p.get('ID'), [s.get('field') for s in p.iter('STYLE')]) for p in parsed.findall('PRESENTATION')] != [(p.get('ID'), [s.get('field') for s in p.iter('STYLE')]) for p in ET.parse(SOURCE).getroot().findall('PRESENTATION')]:
        raise RuntimeError('Theme style structure changed')
    result = {'state': 'prepared_locally_not_installed', 'source': str(SOURCE.relative_to(ROOT)), 'file': str(OUT.relative_to(ROOT)), 'sha256': hashlib.sha256(OUT.read_bytes()).hexdigest(), 'changed_colour_attributes': len(changed), 'changes': changed, 'validation': 'XML parses; all colours are six-digit RGB; original presentation and field structure retained', 'device_ui_verification': 'pending normal mode', 'rollback': 'If installed, select an original theme and delete only Themes/Map/Pi_Contrast.kmtf.'}
    (ROOT / 'evidence/prepared-theme.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    (ROOT / 'staging/README.txt').write_text('Pi Contrast 地圖配色實驗\n\n依實機 United Kingdom.kmtf 建立，保留原有欄位與日夜模式。\n目前只在樹莓派準備，尚未安裝或在實機螢幕驗證。\n安裝位置：導航機 Themes/Map/Pi_Contrast.kmtf。\n之後切回一般模式，在地圖設定的主題選單尋找 Pi Contrast。\n還原：選回原主題，刪除新增的 Pi_Contrast.kmtf；原廠檔案不用改。\n這只改地圖顏色，不會增加 Android Auto 或藍牙音樂功能。\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('state', 'file', 'sha256', 'changed_colour_attributes')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
