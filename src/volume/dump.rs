//! Debug dump of a volume's raw trees, for studying on-disk conventions (`apfs <image> dump`).

use super::Volume;
use crate::container::OBJ_PHYSICAL;
use crate::{btree, u32le, u64le};
use std::cmp::Ordering;
use std::fmt::Write;
use std::io;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Volume<'_> {
    #[doc(hidden)]
    pub fn dump(&self) -> io::Result<String> {
        let mut out = String::new();
        let sb = &self.superblock;
        writeln!(
            out,
            "volume {:?} fs_flags={:#x} features={:#x} ro_compat={:#x} incompat={:#x}",
            self.name,
            u64le(sb, 264),
            u64le(sb, 40),
            u64le(sb, 48),
            u64le(sb, 56)
        )
        .unwrap();
        writeln!(out, "  root_tree_type={:#x} extentref_type={:#x} snap_meta_type={:#x} next_obj_id={} files={} dirs={} symlinks={} other={} snaps={} alloc_count={} alloced={} freed={}",
            u32le(sb, 116), u32le(sb, 120), u32le(sb, 124), u64le(sb, 176), u64le(sb, 184), u64le(sb, 192), u64le(sb, 200), u64le(sb, 208), u64le(sb, 216), u64le(sb, 88), u64le(sb, 224), u64le(sb, 232)).unwrap();
        writeln!(out, "-- fs tree").unwrap();
        let resolve = |child: u64| {
            if self.physical_tree { Ok(child) } else { self.c.omap_lookup(self.omap_tree, child, self.xid) }
        };
        btree::walk(self.c, self.root_tree, &resolve, &|_| Ordering::Equal, &mut |k, v| {
            let h = u64le(k, 0);
            writeln!(out, "  oid={} type={} key+={} val={}", h & 0x0fff_ffff_ffff_ffff, h >> 60, hex(&k[8..]), hex(v))
                .unwrap();
            Ok(true)
        })?;
        let ext = u64le(sb, 144);
        if ext != 0 && u32le(sb, 120) & OBJ_PHYSICAL != 0 {
            writeln!(out, "-- extentref tree @{ext}").unwrap();
            btree::walk(self.c, ext, &|c| Ok(c), &|_| Ordering::Equal, &mut |k, v| {
                let h = u64le(k, 0);
                writeln!(out, "  paddr={} type={} val={}", h & 0x0fff_ffff_ffff_ffff, h >> 60, hex(v)).unwrap();
                Ok(true)
            })?;
        }
        writeln!(out, "-- volume omap").unwrap();
        btree::walk(self.c, self.omap_tree, &|c| Ok(c), &|_| Ordering::Equal, &mut |k, v| {
            writeln!(
                out,
                "  oid={} xid={} flags={:#x} size={} paddr={}",
                u64le(k, 0),
                u64le(k, 8),
                u32le(v, 0),
                u32le(v, 4),
                u64le(v, 8)
            )
            .unwrap();
            Ok(true)
        })?;
        Ok(out)
    }
}
