#!/usr/bin/env python3
"""Compile a navigation-search candidate; does not access the navigator."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-repair-v1'
ENC = ROOT / 'staging/navigation-search-encoding-v1'
TOOL = ROOT / 'sources/maps/mkgmap-r4924'
SPLIT = ROOT / 'staging/maps/Taiwan_OSM_20261001_UTF8/tiles'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def main():
    roots_path = ROOT / 'staging/navigation-road-coverage-v1/native-taiwan-admin-roots.json'
    roots = json.loads(roots_path.read_text())
    assert roots['root_count'] == 22
    compiled = OUT / 'compiled'
    compiled.mkdir(exist_ok=False)
    state = dict(started_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                 state='preparing', family_id=7052, map_id_start=70520001,
                 tile_count=36, sort_id1=19, sort_id2=7052, code_page=65001,
                 osm_data_timestamp='2026-10-01T20:22:06Z',
                 original_split_inputs_reused=True,
                 candidate=True, device_installed=False,
                 device_search_verified=False, device_routing_verified=False,
                 stock_maps_modified=False,
                 map_description='OSM TW 2026-10-01 Search v1',
                 changes=['Serialize existing implicit BMP sort weights in SRT',
                          'Use a consistent new LBL/MDR/SRT sort identity',
                          'Assign Taiwan cities using administrative boundaries',
                          'Normalize selected administrative 台/臺 name variants',
                          'Disable nearest-place city inference'], commands=[])
    manifest = OUT / 'build-manifest.json'

    def save():
        manifest.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n')

    def run(cmd, log):
        state['commands'].append(cmd)
        save()
        with (OUT / log).open('w') as f:
            p = subprocess.run(cmd, cwd=OUT, stdout=f, stderr=subprocess.STDOUT)
        state.setdefault('command_results', []).append(dict(log=log, exit_code=p.returncode))
        save()
        if p.returncode:
            raise RuntimeError(f'{log}: exit {p.returncode}')

    save()
    try:
        pins = {
            ENC / 'writer-patch-src/uk/me/parabola/imgfmt/app/srt/SRTFile.java':
                '98b3a515c11c8eedcc3374ae5ffff56e343d856e5f615d24717bc12f40126b68',
            ENC / 'writer-patch-classes/uk/me/parabola/imgfmt/app/srt/SRTFile.class':
                '70f59492d7a3d399911454f05267cc52852762f71d1ab3531fe165c7562a5085',
            ENC / 'sort-id-resource/sort/cp65001.txt':
                '7a03161eb7b419666f5bb690e4d105d070feb447fe4c2a7a70e5d619e026a715',
        }
        for path, expected in pins.items():
            assert sha(path) == expected, str(path)
        state['pinned_compiler_inputs'] = {str(k): v for k, v in pins.items()}
        ids = OUT / 'taiwan-admin-ids.txt'
        ids.write_text(''.join('r' + str(r['id']) + '\n' for r in roots['selected_admin_relations']))
        run(['osmium', 'getid', '-r', '--id-file', str(ids),
             str(OUT / 'taiwan-admin.osm.pbf'), '-o', str(OUT / 'taiwan-only-admin.osm.pbf')],
            'taiwan-admin-selection.log')
        state['state'] = 'preprocessing_taiwan_boundaries'
        save()
        bounds = OUT / 'taiwan-bounds'
        run(['nice', '-n', '10', 'java', '-Xmx2200m', '-cp', str(TOOL / 'mkgmap.jar'),
             'uk.me.parabola.mkgmap.reader.osm.boundary.BoundaryPreprocessor',
             str(OUT / 'taiwan-only-admin.osm.pbf'), str(bounds)], 'taiwan-bounds-build.log')
        style = OUT / 'style'
        shutil.copytree(TOOL / 'examples/styles/default', style)
        names = [r['name'] for r in roots['municipality_city_roots'] + roots['county_roots']]
        assert len(set(names)) == 22
        name_regex = '^(' + '|'.join(names) + ')$'
        normalization = []
        for name in names:
            if name.startswith('臺'):
                alias = '台' + name[1:]
                for tag in ['addr:city', 'is_in:city', 'mkgmap:city']:
                    normalization.append(f"{tag}={alias} {{ set {tag}='{name}' }}")
        taiwan = '\n'.join([
            '# Taiwan search-city policy; only the 22 verified Taiwan admin4 names.',
            *normalization,
            f"mkgmap:admin_level4 ~ '{name_regex}' {{ set mkgmap:country=TWN; set mkgmap:region='${{mkgmap:admin_level4}}' }}",
            "mkgmap:country=TWN & mkgmap:admin_level4 ~ '.*市$' { set mkgmap:city='${mkgmap:admin_level4}' }",
            "mkgmap:country=TWN & mkgmap:admin_level4 ~ '.*縣$' & mkgmap:admin_level8=* { set mkgmap:city='${mkgmap:admin_level8}' }",
            "mkgmap:country=TWN & mkgmap:admin_level4 ~ '.*縣$' & mkgmap:city!=* & mkgmap:admin_level7=* { set mkgmap:city='${mkgmap:admin_level7}' }",
            '',
        ])
        address = style / 'inc/address'
        address.write_text(taiwan + address.read_text())
        args = OUT / 'tiles.args'
        args.write_text(''.join(f'mapname: {70520000+i}\ninput-file: {SPLIT / (str(70510000+i)+".osm.pbf")}\n\n'
                                for i in range(1, 37)))
        for i in range(1, 37):
            assert (SPLIT / (str(70510000+i) + '.osm.pbf')).is_file()
        old = ROOT / 'staging/maps/Taiwan_OSM_20261001_UTF8'
        for name in ['copyright.txt', 'license.txt']:
            shutil.copyfile(old / name, OUT / name)
        state['boundary_roots'] = names
        state['style_address_sha256'] = sha(address)
        state['taiwan_boundary_source_sha256'] = sha(OUT / 'taiwan-only-admin.osm.pbf')
        state['state'] = 'compiling'
        save()
        cp = ':'.join(map(str, [ENC / 'writer-patch-classes', ENC / 'sort-id-resource', TOOL / 'mkgmap.jar']))
        run(['nice', '-n', '10', 'java', '-Xmx2800m', '-cp', cp,
             'uk.me.parabola.mkgmap.main.Main', '--max-jobs=2',
             '--route', '--index', '--housenumbers', '--gmapsupp', '--code-page=65001',
             '--name-tag-list=name:zh-Hant,name:zh,name,int_name', '--drive-on=right',
             '--country-name=Taiwan', '--country-abbr=TWN', '--region-name=Taiwan',
             '--region-abbr=TW', '--location-autofill=is_in', '--bounds=' + str(bounds),
             '--style-file=' + str(style), '--family-id=7052', '--product-id=1',
             '--family-name=OSM TW 2026-10-01 Search v1', '--series-name=OSM Taiwan Search v1',
             '--description=' + state['map_description'],
             '--copyright-file=' + str(OUT / 'copyright.txt'), '--license-file=' + str(OUT / 'license.txt'),
             '--output-dir=' + str(compiled), '-c', str(args)], 'mkgmap-build.log')
        image = compiled / 'gmapsupp.img'
        state.update(state='compiled_candidate_not_device_verified', image=str(image),
                     image_bytes=image.stat().st_size, image_sha256=sha(image),
                     finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        save()
        print(json.dumps({k: state[k] for k in ['state', 'image_bytes', 'image_sha256']}, ensure_ascii=False))
    except Exception as e:
        state.update(state='failed', error=str(e), finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        save()
        raise


if __name__ == '__main__':
    main()
