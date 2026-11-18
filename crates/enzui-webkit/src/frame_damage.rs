//! Conservative physical-pixel damage between consecutive compositor contents.

/// An outward integer bounding rectangle clipped to the source image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DamageRect {
    /// Left edge in physical pixels.
    pub x: u32,
    /// Top edge in physical pixels.
    pub y: u32,
    /// Horizontal extent in physical pixels.
    pub width: u32,
    /// Vertical extent in physical pixels.
    pub height: u32,
}

/// A bounded region or a conservative full-image fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDamage {
    /// Unknown history, invalid metadata, first content or changed geometry.
    Full,
    /// Bounding union of all recorded changes since the preceding content.
    Region(DamageRect),
}

impl FrameDamage {
    #[cfg(any(feature = "wpe", test))]
    pub(crate) fn from_rectangles(
        extent: (u32, u32),
        rectangles: impl IntoIterator<Item = (i32, i32, i32, i32)>,
    ) -> Self {
        let mut bounds: Option<DamageRect> = None;
        let mut count = 0;
        for (x, y, width, height) in rectangles {
            count += 1;
            if count > 64 || width <= 0 || height <= 0 {
                return Self::Full;
            }
            let left = i64::from(x).clamp(0, i64::from(extent.0));
            let top = i64::from(y).clamp(0, i64::from(extent.1));
            let right = (i64::from(x) + i64::from(width)).clamp(0, i64::from(extent.0));
            let bottom = (i64::from(y) + i64::from(height)).clamp(0, i64::from(extent.1));
            if right <= left || bottom <= top {
                continue;
            }
            let rect = DamageRect {
                x: left as u32,
                y: top as u32,
                width: (right - left) as u32,
                height: (bottom - top) as u32,
            };
            bounds = Some(bounds.map_or(rect, |old| union(old, rect)));
        }
        bounds.map_or(Self::Full, Self::Region)
    }

    #[cfg(any(feature = "wpe", test))]
    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::Region(a), Self::Region(b)) => Self::Region(union(a, b)),
            _ => Self::Full,
        }
    }
}

#[cfg(any(feature = "wpe", test))]
fn union(a: DamageRect, b: DamageRect) -> DamageRect {
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    DamageRect {
        x,
        y,
        width: (a.x + a.width).max(b.x + b.width) - x,
        height: (a.y + a.height).max(b.y + b.height) - y,
    }
}

/// Content identity and damage history independent of reusable GPU allocations.
///
/// Damage alone does not authorize partial presentation. The host must preserve
/// destination contents and include its own transforms, exposure and filtering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameContentInfo {
    stream: u64,
    serial: u64,
    predecessor: u64,
    extent: (u32, u32),
    damage: FrameDamage,
}

impl FrameContentInfo {
    #[cfg(any(feature = "wpe", test))]
    pub(crate) fn new(stream: u64, serial: u64, extent: (u32, u32), damage: FrameDamage) -> Self {
        Self {
            stream,
            serial,
            predecessor: serial.saturating_sub(1),
            extent,
            damage: if serial <= 1 {
                FrameDamage::Full
            } else {
                damage
            },
        }
    }

    /// Monotonic content serial within the source stream, independent of allocation reuse.
    pub fn serial(self) -> u64 {
        self.serial
    }

    /// Physical source image dimensions.
    pub fn extent(self) -> (u32, u32) {
        self.extent
    }

    /// Damage relative to content the host actually consumed.
    ///
    /// Missing, discontinuous, foreign or differently sized history returns full damage.
    pub fn damage_since(self, previous: Option<Self>) -> FrameDamage {
        match previous {
            Some(previous)
                if self.stream != 0
                    && self.stream == previous.stream
                    && self.extent == previous.extent
                    && self.predecessor == previous.serial =>
            {
                self.damage
            }
            _ => FrameDamage::Full,
        }
    }

    #[cfg(any(feature = "wpe", test))]
    pub(crate) fn accumulate(&mut self, discarded: Self) {
        if self.stream == discarded.stream
            && self.extent == discarded.extent
            && self.predecessor == discarded.serial
        {
            self.predecessor = discarded.predecessor;
            self.damage = self.damage.union(discarded.damage);
        } else {
            self.damage = FrameDamage::Full;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_damage_is_bounded_and_accumulates_without_serial_gaps() {
        assert_eq!(
            FrameDamage::from_rectangles(
                (100, 80),
                [(-5, -7, 15, 17), (90, 70, i32::MAX, i32::MAX)]
            ),
            FrameDamage::Region(DamageRect {
                x: 0,
                y: 0,
                width: 100,
                height: 80
            })
        );
        for rects in [
            vec![],
            vec![(1, 1, 0, 4)],
            vec![(1, 1, 1, 1); 65],
            vec![(200, 200, 4, 4)],
        ] {
            assert_eq!(
                FrameDamage::from_rectangles((100, 80), rects),
                FrameDamage::Full
            );
        }

        {
            let small = FrameDamage::from_rectangles((100, 80), [(2, 3, 4, 5)]);
            let far = FrameDamage::from_rectangles((100, 80), [(60, 50, 10, 10)]);
            let old = FrameContentInfo::new(8, 4, (100, 80), small);
            let skipped = FrameContentInfo::new(8, 5, (100, 80), small);
            let mut latest = FrameContentInfo::new(8, 6, (100, 80), far);
            assert_eq!(latest.damage_since(Some(old)), FrameDamage::Full);
            latest.accumulate(skipped);
            assert_eq!(
                latest.damage_since(Some(old)),
                FrameDamage::Region(DamageRect {
                    x: 2,
                    y: 3,
                    width: 68,
                    height: 57
                })
            );
            assert_eq!(latest.damage_since(None), FrameDamage::Full);
            assert_eq!(
                latest.damage_since(Some(FrameContentInfo::new(9, 4, (100, 80), small))),
                FrameDamage::Full
            );
            assert_eq!(
                latest.damage_since(Some(FrameContentInfo::new(8, 4, (101, 80), small))),
                FrameDamage::Full
            );
            assert_eq!(
                FrameContentInfo::new(8, 1, (100, 80), small)
                    .damage_since(Some(FrameContentInfo::new(8, 0, (100, 80), small))),
                FrameDamage::Full
            );
        }
    }
}
