//! Which parts of a console framebuffer changed: a 32x32 tile bitset.
//!
//! One dirty rectangle cannot describe a cursor blinking in one corner and a
//! clock ticking in the other without covering the whole screen between them,
//! so `ast2100::Decoder` marks tiles instead, and a front end uploads only the
//! tiles that changed, merged into as few rectangles as cover them exactly
//! (one `texSubImage2D` or `set_partial` each, so fewer is cheaper; spike S1).
//!
//! The bitset is sized to the frame, so it cannot grow however long nobody
//! looks at it — which is what lets a hidden console tab simply stop pulling.

pub const TILE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

/// What changed since the damage was last taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Damage {
    /// Merged rectangles covering every dirty tile exactly once, inside the frame.
    pub rects: Vec<Rect>,
    /// Every tile is dirty.
    pub full: bool,
    /// The geometry changed: a client must reallocate before painting.
    pub resized: bool,
}

#[derive(Clone, Debug)]
pub struct Tiles {
    width: usize,
    height: usize,
    tiles_x: usize,
    tiles_y: usize,
    dirty: Vec<bool>,
}

impl Tiles {
    /// A clean bitset for a `width` x `height` frame.
    pub fn new(width: usize, height: usize) -> Self {
        let (tiles_x, tiles_y) = (width.div_ceil(TILE), height.div_ceil(TILE));
        Tiles { width, height, tiles_x, tiles_y, dirty: vec![false; tiles_x * tiles_y] }
    }

    pub fn size(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// Mark `w` x `h` pixels at (x, y), clipped to the frame.
    pub fn mark(&mut self, x: usize, y: usize, w: usize, h: usize) {
        if w == 0 || h == 0 || x >= self.width || y >= self.height {
            return;
        }
        let x1 = x.saturating_add(w).min(self.width).div_ceil(TILE);
        let y1 = y.saturating_add(h).min(self.height).div_ceil(TILE);
        for ty in y / TILE..y1 {
            self.dirty[ty * self.tiles_x + x / TILE..ty * self.tiles_x + x1].fill(true);
        }
    }

    pub fn mark_all(&mut self) {
        self.dirty.fill(true);
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.contains(&true)
    }

    pub fn all_dirty(&self) -> bool {
        !self.dirty.contains(&false)
    }

    pub fn clear(&mut self) {
        self.dirty.fill(false);
    }

    /// Copy `src` over `dst` (both `width` wide, the bitset's geometry) and
    /// mark exactly the tiles that differ. A source that redraws its whole
    /// picture every time — the Tauri mock, avct_dvc's blit — gets exact
    /// damage this way without tracking what it changed.
    pub fn diff_from(&mut self, dst: &mut [u32], src: &[u32], width: usize) {
        debug_assert_eq!(width, self.width);
        debug_assert_eq!(dst.len(), self.width * self.height);
        debug_assert_eq!(src.len(), dst.len());
        for ty in 0..self.tiles_y {
            for tx in 0..self.tiles_x {
                let x0 = tx * TILE;
                let x1 = (x0 + TILE).min(width);
                let mut changed = false;
                for y in ty * TILE..((ty + 1) * TILE).min(self.height) {
                    let row = y * width;
                    let (d, s) = (&mut dst[row + x0..row + x1], &src[row + x0..row + x1]);
                    if d != s {
                        d.copy_from_slice(s);
                        changed = true;
                    }
                }
                if changed {
                    self.dirty[ty * self.tiles_x + tx] = true;
                }
            }
        }
    }

    /// The dirty tiles, by tile coordinate.
    pub fn dirty_tiles(&self) -> Vec<(usize, usize)> {
        (0..self.dirty.len()).filter(|&i| self.dirty[i]).map(|i| (i % self.tiles_x, i / self.tiles_x)).collect()
    }

    /// Dirty tiles merged into row runs, then runs with the same x extent in
    /// consecutive tile rows merged into rectangles, clamped to the frame.
    pub fn rects(&self) -> Vec<Rect> {
        let mut done = Vec::new();
        // Open rectangles in tile units: x0, x1, y0, y1.
        let mut open: Vec<(usize, usize, usize, usize)> = Vec::new();
        for ty in 0..self.tiles_y {
            let row = &self.dirty[ty * self.tiles_x..(ty + 1) * self.tiles_x];
            let mut still_open = Vec::new();
            let mut tx = 0;
            while tx < self.tiles_x {
                if !row[tx] {
                    tx += 1;
                    continue;
                }
                let start = tx;
                while tx < self.tiles_x && row[tx] {
                    tx += 1;
                }
                match open.iter().position(|o| o.0 == start && o.1 == tx) {
                    Some(i) => {
                        let mut o = open.swap_remove(i);
                        o.3 = ty + 1;
                        still_open.push(o);
                    }
                    None => still_open.push((start, tx, ty, ty + 1)),
                }
            }
            done.append(&mut open);
            open = still_open;
        }
        done.append(&mut open);
        done.sort_by_key(|o| (o.2, o.0));
        done.into_iter()
            .map(|(x0, x1, y0, y1)| {
                let (x, y) = (x0 * TILE, y0 * TILE);
                Rect { x, y, w: (x1 * TILE).min(self.width) - x, h: (y1 * TILE).min(self.height) - y }
            })
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The client-texture replay (Tauri spec, "Damage tracking"): a client
    /// copy that only ever receives the pixels inside the damage rectangles,
    /// checked against the decoder after every step. Comparing final pictures
    /// alone cannot catch a missed mark that a later full frame painted over.
    #[derive(Default)]
    pub struct Replay {
        pub client: Vec<u32>,
        pub width: usize,
        pub height: usize,
        /// Steps whose damage was partial (not every tile).
        pub partial: usize,
    }

    /// What a reallocated client holds before it paints: never a decoder colour.
    const POISON: u32 = 0xFF00_FF00;

    impl Replay {
        /// Take the decoder's damage, paint it into the client copy, and
        /// assert the two agree.
        pub fn step(&mut self, d: &mut crate::ast2100::Decoder, what: &str) -> Option<Damage> {
            let dmg = d.take_dirty();
            if let Some(dmg) = &dmg {
                if (d.width, d.height) != (self.width, self.height) {
                    assert!(dmg.resized, "{what}: geometry changed without RESIZED");
                }
                if dmg.resized {
                    (self.width, self.height) = (d.width, d.height);
                    self.client = vec![POISON; d.width * d.height];
                }
                if !dmg.full {
                    self.partial += 1;
                }
                for r in &dmg.rects {
                    for y in r.y..r.y + r.h {
                        let row = y * d.width;
                        self.client[row + r.x..row + r.x + r.w].copy_from_slice(&d.framebuffer[row + r.x..row + r.x + r.w]);
                    }
                }
            }
            assert_eq!((self.width, self.height), (d.width, d.height), "{what}");
            if let Some(i) = self.client.iter().zip(&d.framebuffer).position(|(a, b)| a != b) {
                panic!("{what}: client differs at ({}, {})", i % d.width, i / d.width);
            }
            dmg
        }
    }

    pub fn covered(r: &[Rect], x: usize, y: usize) -> usize {
        r.iter().filter(|r| x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h).count()
    }

    /// Every dirty tile covered exactly once, nothing else covered, and
    /// nothing outside the frame. Rects are tile-aligned, ending on a tile
    /// boundary or the frame's edge, so counting per tile is exact.
    pub fn assert_exact_cover(t: &Tiles) {
        let (w, h) = t.size();
        let (tw, th) = (w.div_ceil(TILE), h.div_ceil(TILE));
        let mut count = vec![0u32; tw * th];
        for r in t.rects() {
            assert!(r.w > 0 && r.h > 0 && r.x + r.w <= w && r.y + r.h <= h, "{r:?} leaves the {w}x{h} frame");
            assert!(r.x % TILE == 0 && r.y % TILE == 0, "{r:?} is not tile-aligned");
            assert!((r.x + r.w) % TILE == 0 || r.x + r.w == w, "{r:?} ends inside a tile");
            assert!((r.y + r.h) % TILE == 0 || r.y + r.h == h, "{r:?} ends inside a tile");
            for ty in r.y / TILE..(r.y + r.h).div_ceil(TILE) {
                for tx in r.x / TILE..(r.x + r.w).div_ceil(TILE) {
                    count[ty * tw + tx] += 1;
                }
            }
        }
        let mut dirty = vec![0u32; tw * th];
        for (tx, ty) in t.dirty_tiles() {
            dirty[ty * tw + tx] = 1;
        }
        assert_eq!(count, dirty);
    }

    #[test]
    fn diff_finds_exactly_the_changed_tiles() {
        let mut t = Tiles::new(200, 100); // 7x4 tiles, the last column and row partial
        let mut px = vec![0u32; 200 * 100];
        let mut next = px.clone();
        for (x, y) in [(0, 0), (40, 5), (199, 99), (100, 64), (101, 70)] {
            next[y * 200 + x] = 0x00ff_ffff;
        }
        t.diff_from(&mut px, &next, 200);
        assert_eq!(t.dirty_tiles(), vec![(0, 0), (1, 0), (3, 2), (6, 3)]);
        assert_eq!(px, next);
        // The same picture again changes nothing.
        t.clear();
        t.diff_from(&mut px, &next, 200);
        assert!(!t.is_dirty());
    }

    #[test]
    fn merged_rects_cover_every_dirty_tile_once() {
        let mut t = Tiles::new(330, 250);
        // An L shape, a lone tile, a block straddling the partial edge tiles.
        t.mark(0, 0, 96, 32);
        t.mark(0, 32, 32, 64);
        t.mark(160, 32, 1, 1);
        t.mark(250, 200, 80, 50);
        t.mark(64, 128, 96, 96);
        assert_exact_cover(&t);
        let rects = t.rects();
        // Every pixel at most once: no overlap.
        for y in 0..250 {
            for x in 0..330 {
                assert!(covered(&rects, x, y) <= 1);
            }
        }
    }

    #[test]
    fn full_frame_is_one_rect() {
        let mut t = Tiles::new(1024, 768);
        t.mark_all();
        assert!(t.all_dirty());
        assert_eq!(t.rects(), vec![Rect { x: 0, y: 0, w: 1024, h: 768 }]);
    }

    #[test]
    fn tiles_on_odd_sizes() {
        for (w, h) in [(1, 1), (31, 33), (1920, 1080), (4096, 4096)] {
            let mut t = Tiles::new(w, h);
            assert!(t.rects().is_empty());
            t.mark(w - 1, h - 1, 1, 1);
            t.mark(0, 0, 1, 1);
            // A mark running off the frame, and one entirely outside it.
            t.mark(w / 2, h / 2, usize::MAX, usize::MAX);
            t.mark(w, h, 10, 10);
            assert_exact_cover(&t);
            // A checkerboard is the worst case for merging.
            let mut c = Tiles::new(w, h);
            for ty in 0..h.div_ceil(TILE) {
                for tx in (ty % 2..w.div_ceil(TILE)).step_by(2) {
                    c.mark(tx * TILE, ty * TILE, 1, 1);
                }
            }
            assert_exact_cover(&c);
            c.mark_all();
            assert_eq!(c.rects(), vec![Rect { x: 0, y: 0, w, h }]);
        }
    }
}
