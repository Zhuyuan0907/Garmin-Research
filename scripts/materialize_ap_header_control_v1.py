#!/usr/bin/env python3
"""Materialize one fixed closed AP header control locally as .img.disabled.

No device discovery, installation or user-supplied manifest. No arguments and
--list are metadata only. Production control identities are fixed below.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import argparse
import hashlib
import json
import os
import secrets
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
STAGING=ROOT/'staging'
EVIDENCE=STAGING/'navigation-AP-coherent-geometry-virtual-controls-v2'
CATALOG_PINS={
 'prepared-control-plan.json':'dc636ce504acb7ef3a8b0980d4f91b796f05fc6f07dcbb52aed9d73c6740f655',
 'proof.json':'dace2db29b3a7d36dc74e775b78501bbe0d9673da77e8f524a05fe7b662e7683',
 'sealed-files.json':'b3365a9aa57c0181adcbebf80ce3ac3c58463706b9e773280db3433e9eba67da'}
CONTROL_OFFSETS={'eightK_end_mirror':(452,), 'expanded_fourK_geometry':(24,95,451,452,453)}
CHUNK_BYTES=1048576


class ControlError(Exception):
    def __init__(self,message,receipt=None):
        super().__init__(message);self.receipt=receipt or {}


def _require(value,message):
    if not value:raise ControlError(message)


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _snapshot(s):
    return {'dev':s.st_dev,'ino':s.st_ino,'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,
            'ctime_ns':s.st_ctime_ns,'mode':stat.S_IMODE(s.st_mode),'nlink':s.st_nlink}


def _pin5(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


@dataclass(frozen=True)
class _Control:
    name:str
    source:Path
    size:int
    source_sha256:str
    virtual_sha256:str
    source_stat:tuple[int,int,int,int,int]
    original_header:bytes
    corrected_header:bytes
    corrected_header_sha256:str
    changed_offsets:tuple[int,...]


def _validate_control(c):
    _require(c.name in CONTROL_OFFSETS,'Unknown control name')
    _require(c.changed_offsets==CONTROL_OFFSETS[c.name],'Exact supported control byte offsets')
    _require(isinstance(c.size,int) and not isinstance(c.size,bool) and c.size>=512,'Pinned source size')
    _require(len(c.source_stat)==5 and all(isinstance(v,int) and not isinstance(v,bool) and v>=0 for v in c.source_stat)
             and c.source_stat[2]==c.size,'Pinned source stat/size shape')
    for digest in (c.source_sha256,c.virtual_sha256,c.corrected_header_sha256):
        _require(len(digest)==64 and all(x in '0123456789abcdef' for x in digest),'Exact SHA256 shape')
    _require(len(c.original_header)==len(c.corrected_header)==512,'Complete512byte header controls')
    _require(_sha(c.corrected_header)==c.corrected_header_sha256,'Corrected header exact SHA')
    _require(tuple(i for i,(a,b) in enumerate(zip(c.original_header,c.corrected_header)) if a!=b)==c.changed_offsets,
             'Only specified header bytes change')
    _require(c.original_header[15]==c.corrected_header[15],'Opaque checksum byte must remain untouched')


def _read_small_pinned(path,digest,receipts):
    before=path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size<=65536,'Small fixed regular catalog artifact')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        _require(_pin5(os.fstat(f.fileno()))==_pin5(before),'Catalog descriptor identity')
        raw=f.read(65537);_require(f.read(1)==b'','Catalog complete EOF')
    after=path.lstat()
    _require(_pin5(before)==_pin5(after) and len(raw)==before.st_size and _sha(raw)==digest,
             'Fixed catalog SHA/size/stat pin')
    receipts.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':digest,
                     'stat_before':list(_pin5(before)),'stat_after':list(_pin5(after))})
    _require(sum(r['bytes'] for r in receipts)<=262144,'Small fixed catalog read budget')
    return raw


def load_catalog():
    """Only fixed small evidence; does not open or stat any source IMG."""
    receipts=[]
    docs={name:json.loads(_read_small_pinned(EVIDENCE/name,pin,receipts)) for name,pin in CATALOG_PINS.items()}
    plan,proof,seal=(docs[n] for n in ('prepared-control-plan.json','proof.json','sealed-files.json'))
    _require(set(plan)==set(CONTROL_OFFSETS) and set(proof['controls'])==set(CONTROL_OFFSETS),
             'Exactly the two closed production controls')
    _require(proof['all_assigned_checks_completed'] and proof['no_new_full_IMG_saved'] and
             proof['installable'] is False and proof['checksum_algorithm_verified'] is False,
             'Closed virtual evidence retains acceptance/checksum limitations')
    sealed={r['path']:r for r in seal['files']};result={}
    for name,offsets in CONTROL_OFFSETS.items():
        p=plan[name];v=proof['controls'][name]
        _require(tuple(p['changed_byte_offsets'])==offsets==tuple(v['changed_byte_offsets']),
                 'Pinned intended change list')
        _require(p['path']==v['source_path'] and p['bytes']==v['bytes_read'] and
                 p['sha256']==v['source_actual_full_SHA256'] and
                 v['source_stat_before']==v['source_stat_after'] and v['source_handle_closed'] and
                 v['all_nonheader_output_bytes_source_identical'],'Closed source/body/fullSHA identity')
        headerpath=EVIDENCE/(name+'-header.bin');row=sealed[str(headerpath.relative_to(ROOT))]
        _require(row['bytes']==512 and row['sha256']==p['corrected_header_sha256'],'Sealed complete corrected header binding')
        new=_read_small_pinned(headerpath,row['sha256'],receipts);old=bytearray(new)
        _require(len(p['original_byte_values'])==len(p['new_byte_values'])==len(offsets),'Exact patch value arrays')
        for offset,original,corrected in zip(offsets,p['original_byte_values'],p['new_byte_values']):
            _require(new[offset]==corrected,'Corrected byte matches closed plan');old[offset]=original
        _require(_sha(old)==p['source_header_sha256'],'Reconstructed original full512header pin')
        source=ROOT/p['path']
        _require(source.is_absolute() and source.parent.is_relative_to(STAGING),'Fixed staging source only')
        c=_Control(name,source,p['bytes'],p['sha256'],v['virtual_full_SHA256'],tuple(v['source_stat_before']),
                   bytes(old),new,p['corrected_header_sha256'],offsets)
        _validate_control(c);result[name]=c
    return result,receipts


def _open_output_parent(output,staging):
    output=Path(os.path.abspath(os.fspath(output)));staging=Path(os.path.abspath(os.fspath(staging)))
    _require(output.name.endswith('.img.disabled'),'Output must end exactly .img.disabled')
    try:relative=output.relative_to(staging)
    except ValueError:raise ControlError('Output must be below the staging directory')
    _require(len(relative.parts)>=1 and all(p not in ('','.', '..') for p in relative.parts),'Normal staging output path')
    fd=os.open(staging,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            newfd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=newfd
        try:os.stat(relative.name,dir_fd=fd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ControlError('Existing output or symlink cannot be overwritten')
        return output,fd,relative.name
    except BaseException:
        os.close(fd);raise


def _owned_partial(parentfd,name,identity):
    s=os.stat(name,dir_fd=parentfd,follow_symlinks=False)
    _require(stat.S_ISREG(s.st_mode) and (s.st_dev,s.st_ino)==identity,'Partial inode ownership changed')
    return s


def _publish_owned_no_replace(parentfd,partial,output,identity):
    _owned_partial(parentfd,partial,identity)
    # linkat is atomic and fails EEXIST; rename could overwrite a racing file.
    os.link(partial,output,src_dir_fd=parentfd,dst_dir_fd=parentfd,follow_symlinks=False)


def _write_all(fd,data):
    view=memoryview(data)
    while view:
        n=os.write(fd,view);_require(n>0,'Short output write made no progress');view=view[n:]


def _readback_owned_partial(parentfd,name,identity,expected_size,state):
    """Read the saved, fsynced inode through a separate read-only descriptor."""
    before=_owned_partial(parentfd,name,identity)
    fd=None;digest=hashlib.sha256();state['saved_output_bytes_read']=0
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parentfd)
        state['readback_handle_closed']=False
        _require(_snapshot(os.fstat(fd))==_snapshot(before),'Saved partial opened inode identity/stat')
        while True:
            b=os.read(fd,min(CHUNK_BYTES,expected_size-state['saved_output_bytes_read']+1))
            if not b:break
            state['saved_output_bytes_read']+=len(b)
            _require(state['saved_output_bytes_read']<=expected_size,'Saved partial exceeds pinned length')
            digest.update(b)
        state['actual_saved_output_sha256']=digest.hexdigest()
        after=_owned_partial(parentfd,name,identity)
        _require(_snapshot(os.fstat(fd))==_snapshot(after)==_snapshot(before),'Saved partial changed during readback')
        _require(state['saved_output_bytes_read']==after.st_size==expected_size,'Saved partial exact length and EOF')
        state['saved_output_stat_after_readback']=_snapshot(after)
    finally:
        if fd is not None:
            os.close(fd);state['readback_handle_closed']=True


def _materialize_control(control,output,*,staging_root=STAGING):
    """Private engine. Synthetic tests supply their own <=8KiB fixture specs.

    Production CLI always obtains its spec from load_catalog; no fixture or
    user manifest CLI exists. Publication requires source, computed virtual,
    and actual saved-output full hashes and exact EOF/length.
    """
    _validate_control(control)
    state={'control':control.name,'source':str(control.source),'output':str(output),'expected_bytes':control.size,
           'source_bytes_read':0,'generated_bytes_written':0,'partial_created':False,'published':False,
           'partial_cleanup':'not_created','source_unchanged':None,'source_handle_closed':True,
           'output_handle_closed':True,'readback_handle_closed':True,'all_handles_closed':False,'installable':False,
           'checksum_policy_or_UI_or_renderer_rootcause_verified':False}
    parentfd=sourcefd=partialfd=None;partial=None;identity=None;error=None;source_before=None
    try:
        actual,parentfd,outname=_open_output_parent(output,staging_root);state['output']=str(actual)
        before=control.source.lstat()
        _require(stat.S_ISREG(before.st_mode) and _pin5(before)==control.source_stat,'Source regular file and exact pinned stat required')
        sourcefd=os.open(control.source,os.O_RDONLY|os.O_NOFOLLOW);state['source_handle_closed']=False
        source_before=os.fstat(sourcefd)
        _require(stat.S_ISREG(source_before.st_mode) and _pin5(source_before)==control.source_stat,'Pinned opened source inode')
        state['source_stat_before']=_snapshot(source_before)
        old=os.read(sourcefd,512);state['source_bytes_read']=len(old)
        _require(old==control.original_header,'Actual source first512bytes mismatch; no partial created')
        _require(_snapshot(os.fstat(sourcefd))==state['source_stat_before'],'Source changed while validating header')
        for _ in range(16):
            candidate='.ap-header-control-'+secrets.token_hex(16)+'.partial'
            try:partialfd=os.open(candidate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parentfd)
            except FileExistsError:continue
            partial=candidate;break
        _require(partialfd is not None,'Could not create a uniquely owned partial')
        s=os.fstat(partialfd);identity=(s.st_dev,s.st_ino)
        state.update(partial_created=True,partial_name=partial,partial_inode=list(identity),output_handle_closed=False)
        sourcehash=hashlib.sha256(old);virtualhash=hashlib.sha256(control.corrected_header)
        _write_all(partialfd,control.corrected_header);state['generated_bytes_written']=512
        while True:
            b=os.read(sourcefd,min(CHUNK_BYTES,control.size-state['source_bytes_read']+1))
            if not b:break
            state['source_bytes_read']+=len(b)
            _require(state['source_bytes_read']<=control.size,'Source larger than pinned length')
            sourcehash.update(b);virtualhash.update(b);_write_all(partialfd,b);state['generated_bytes_written']+=len(b)
        state['source_actual_full_sha256']=sourcehash.hexdigest();state['generated_computed_full_sha256']=virtualhash.hexdigest()
        _require(state['source_bytes_read']==state['generated_bytes_written']==control.size,'Exact source/output full length and EOF')
        _require(state['source_actual_full_sha256']==control.source_sha256,'Actual complete source SHA mismatch')
        _require(state['generated_computed_full_sha256']==control.virtual_sha256,'Computed virtual complete SHA mismatch')
        state['source_stat_after']=_snapshot(os.fstat(sourcefd))
        _require(state['source_stat_after']==state['source_stat_before'] and
                 _snapshot(control.source.lstat())==state['source_stat_before'],'Source changed during complete stream')
        state['source_unchanged']=True;state['source_and_computed_hashes_and_length_verified']=True
        _require(os.fstat(partialfd).st_size==control.size,'Actual partial file length')
        os.fchmod(partialfd,0o444);os.fsync(partialfd);state['output_fsync_before_publish']=True
        _readback_owned_partial(parentfd,partial,identity,control.size,state)
        _require(state['actual_saved_output_sha256']==control.virtual_sha256,'Actual saved output complete SHA mismatch')
        state['actual_saved_output_fullhash_verified']=True
        _require(_snapshot(os.fstat(sourcefd))==_snapshot(control.source.lstat())==state['source_stat_before'],
                 'Source changed during saved-output readback')
        _require(_snapshot(_owned_partial(parentfd,partial,identity))==state['saved_output_stat_after_readback'],
                 'Saved partial changed before publication')
        state['full_hashes_and_length_verified']=True
        _publish_owned_no_replace(parentfd,partial,outname,identity);state['published']=True
        _require(_owned_partial(parentfd,outname,identity).st_size==control.size,'Published output exact owned inode/length')
        os.fsync(parentfd);state['directory_fsync_after_publish']=True
    except BaseException as exc:error=exc
    finally:
        if partialfd is not None:
            try:os.close(partialfd);state['output_handle_closed']=True
            except BaseException as close_error:
                state['output_close_error']=str(close_error)
                if error is None:error=close_error
        if sourcefd is not None:
            try:
                if source_before is not None:
                    after=os.fstat(sourcefd);state['source_stat_final_close']=_snapshot(after)
                    path_after=control.source.lstat();state['source_stat_final_path']=_snapshot(path_after)
                    state['source_unchanged']=_snapshot(after)==_snapshot(path_after)==_snapshot(source_before)
                    if not state['source_unchanged'] and error is None:error=ControlError('Source changed before final handle closure')
            except BaseException as stat_error:
                if error is None:error=stat_error
            finally:
                try:os.close(sourcefd);state['source_handle_closed']=True
                except BaseException as close_error:
                    state['source_close_error']=str(close_error)
                    if error is None:error=close_error
        if partial is not None and parentfd is not None:
            try:
                _owned_partial(parentfd,partial,identity);os.unlink(partial,dir_fd=parentfd)
                state['partial_cleanup']='owned_partial_removed';os.fsync(parentfd)
            except FileNotFoundError:state['partial_cleanup']='owned_name_already_absent'
            except BaseException as cleanup_error:
                state['partial_cleanup']='not_removed_ownership_or_cleanup_error';state['cleanup_error']=str(cleanup_error)
                if error is None:error=cleanup_error
        if parentfd is not None:
            try:os.close(parentfd);state['parent_handle_closed']=True
            except BaseException as close_error:
                state['parent_handle_closed']=False
                if error is None:error=close_error
        else:state['parent_handle_closed']=True
        state['all_handles_closed']=(state['source_handle_closed'] and state['output_handle_closed'] and
                                     state['readback_handle_closed'] and state['parent_handle_closed'])
    if error is not None:raise ControlError(str(error),state) from error
    return state


def catalog_metadata(controls,receipts):
    return {'schema':'fixed-closed-AP-header-control-catalog/v1','catalog_pins':CATALOG_PINS,
            'controls':[{ 'name':c.name,'source':str(c.source.relative_to(ROOT)),'bytes':c.size,
             'source_sha256':c.source_sha256,'expected_generated_sha256':c.virtual_sha256,
             'source_stat_pin':list(c.source_stat),'source_header_sha256':_sha(c.original_header),
             'corrected_header_sha256':c.corrected_header_sha256,'changed_offsets':list(c.changed_offsets)} for c in controls.values()],
            'small_catalog_input_receipts':receipts,'source_IMG_opened_or_statted':False,
            'installable':False,'checksum_policy_UI_or_rootcause_verified':False}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);mode=p.add_mutually_exclusive_group()
    mode.add_argument('--list',action='store_true');mode.add_argument('--control',choices=tuple(CONTROL_OFFSETS))
    p.add_argument('--output',type=Path);args=p.parse_args(argv)
    if args.control is None and args.output is not None:p.error('--output requires --control')
    if args.control is not None and args.output is None:p.error('--control requires explicit staging .img.disabled --output')
    try:
        controls,receipts=load_catalog()
        if args.control is None:result=catalog_metadata(controls,receipts)
        else:
            result=_materialize_control(controls[args.control],args.output)
            result['fixed_catalog_pins']=CATALOG_PINS
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0
    except (ControlError,OSError,ValueError,KeyError) as exc:
        print(json.dumps({'error':str(exc),'receipt':getattr(exc,'receipt',{}),'installable':False},ensure_ascii=False),file=sys.stderr)
        return 1


if __name__=='__main__':sys.exit(main())
