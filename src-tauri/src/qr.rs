//! QR codes as an import source.
//!
//! Every capture path — a screenshot, a picture from disk, a frame from the
//! camera — narrows down to a greyscale plane here, and whatever the codes
//! carry goes on to `add_links`, exactly as if it had been pasted into the box.
//! Nothing in this module knows which platform produced the pixels, which is
//! why the same file serves the Tauri build and the native Windows one: it is
//! one file copied into both crates, and it has to stay one.

use crate::error::{AppError, Result};

/// Above this many pixels a frame is halved before detection. Detection walks
/// every pixel several times over, and a 4K screenshot is eight megapixels of
/// mostly empty desktop; a code small enough to be lost at half resolution is
/// already too small to read reliably at full.
const HALVE_ABOVE: usize = 4_000_000;

/// Ceilings for a picture that came from outside the app. Wide enough for a
/// panoramic screenshot, narrow enough that a lie in the header cannot ask for
/// more memory than the machine has.
const MAX_SIDE: u32 = 20_000;
const MAX_ALLOC: u64 = 512 * 1024 * 1024;

/// Read every QR code visible in a greyscale plane, `width * height` bytes,
/// row-major, 0 = black.
///
/// Returns the payloads in detection order, deduplicated — a screen may well
/// show the same code twice (a page and its preview), and it may show several
/// different ones.
pub fn decode_luma(width: usize, height: usize, luma: &[u8]) -> Vec<String> {
    if width == 0 || height == 0 || luma.len() < width * height {
        return Vec::new();
    }

    let found = scan(width, height, |x, y| luma[y * width + x]);
    if !found.is_empty() {
        return found;
    }

    // Light modules on a dark card: panels with a dark theme render plenty of
    // those, and the detector only ever looks for dark modules on light.
    let found = scan(width, height, |x, y| 255 - luma[y * width + x]);
    if !found.is_empty() {
        return found;
    }

    if width * height > HALVE_ABOVE {
        let (w, h, small) = halve(width, height, luma);
        let found = scan(w, h, |x, y| small[y * w + x]);
        if !found.is_empty() {
            return found;
        }
        return scan(w, h, |x, y| 255 - small[y * w + x]);
    }
    Vec::new()
}

/// Flatten a packed colour frame into the plane `decode_luma` wants.
///
/// Every capture path produces one of these and none of them agree on the
/// details: GDI hands out BGRA rows packed tight, a GdkPixbuf has three or four
/// channels and a row stride of its own, and a camera sample is whatever the
/// driver felt like. `None` means the numbers and the buffer disagree — a
/// truncated frame is dropped, never read past.
///
/// Nothing calls this on a phone: there is no screen to capture there, and the
/// camera frames arrive from the page as a luminance plane already. This one
/// file serves both crates verbatim, so the exception is stated here rather
/// than fenced off per platform.
#[allow(dead_code)]
pub fn luma_from_pixels(
    width: usize,
    height: usize,
    stride: usize,
    channels: usize,
    pixels: &[u8],
    blue_first: bool,
) -> Option<Vec<u8>> {
    if width == 0 || height == 0 || !(3..=4).contains(&channels) || stride < width * channels {
        return None;
    }
    if pixels.len() < (height - 1) * stride + width * channels {
        return None;
    }
    let (ri, bi) = if blue_first { (2, 0) } else { (0, 2) };
    let mut luma = Vec::with_capacity(width * height);
    for y in 0..height {
        let row = &pixels[y * stride..];
        for x in 0..width {
            let pixel = &row[x * channels..];
            luma.push(grey(pixel[ri], pixel[1], pixel[bi]));
        }
    }
    Some(luma)
}

/// Read every QR code out of an encoded picture — whatever the user picked in
/// the file dialog, or dropped in from a phone screenshot.
///
/// The decoder is capped: a picture arrives from outside the app, and a header
/// claiming a hundred thousand pixels a side costs nothing to write and a great
/// deal to allocate.
pub fn decode_image_file(bytes: &[u8]) -> Result<Vec<String>> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_ALLOC);

    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| AppError::msg(format!("не удалось прочитать изображение: {e}")))?;
    reader.limits(limits);
    let picture = reader
        .decode()
        .map_err(|e| AppError::msg(format!("не удалось прочитать изображение: {e}")))?
        .to_luma8();

    let (w, h) = (picture.width() as usize, picture.height() as usize);
    Ok(decode_luma(w, h, picture.as_raw()))
}

/// BT.601 luma in integer arithmetic — the same weights every camera pipeline
/// uses, and the detector never needs more precision than a byte.
#[allow(dead_code)]
#[inline]
fn grey(r: u8, g: u8, b: u8) -> u8 {
    ((77 * r as u32 + 150 * g as u32 + 29 * b as u32) >> 8) as u8
}

fn scan<F>(width: usize, height: usize, fill: F) -> Vec<String>
where
    F: FnMut(usize, usize) -> u8,
{
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, fill);
    let mut out: Vec<String> = Vec::new();
    for grid in prepared.detect_grids() {
        // A grid is only a candidate: three finder patterns in the right
        // arrangement can also be a table or an icon row, and those fail here.
        let Ok((_, text)) = grid.decode() else { continue };
        let text = text.trim().to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push(text);
        }
    }
    out
}

/// Box filter down to half the size. Averaging rather than dropping pixels: a
/// module thinned by anti-aliasing survives the average and disappears from a
/// plain sample.
fn halve(width: usize, height: usize, luma: &[u8]) -> (usize, usize, Vec<u8>) {
    let w = width / 2;
    let h = height / 2;
    let mut out = Vec::with_capacity(w * h);
    for y in 0..h {
        let top = 2 * y * width;
        let bottom = top + width;
        for x in 0..w {
            let i = 2 * x;
            let sum = luma[top + i] as u32
                + luma[top + i + 1] as u32
                + luma[bottom + i] as u32
                + luma[bottom + i + 1] as u32;
            out.push((sum / 4) as u8);
        }
    }
    (w, h, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the tests scan for: a share link short enough to fit the smallest
    /// code there is (version 1, 21×21, ECC level L). The finished module
    /// matrix is checked in rather than a .png, so the fixture stays reviewable
    /// and the tests need no encoder of their own.
    const PAYLOAD: &str = "vless://x@a.b:443";

    fn modules() -> Vec<Vec<bool>> {
        const ROWS: [&str; 21] = [
            "#######...#...#######",
            "#.....#.....#.#.....#",
            "#.###.#..#..#.#.###.#",
            "#.###.#.##.##.#.###.#",
            "#.###.#.##.#..#.###.#",
            "#.....#..##.#.#.....#",
            "#######.#.#.#.#######",
            ".....................",
            "##...###.#......##...",
            ".#####..####.#...#...",
            "#.#...#.#...####..##.",
            "####.#..#.#..#.####.#",
            "...####.#..##....#..#",
            "........#.....#.#####",
            "#######.##.##..#.###.",
            "#.....#.##...##..####",
            "#.###.#..#.#...###...",
            "#.###.#..##....##.##.",
            "#.###.#..########..##",
            "#.....#.##.###.####..",
            "#######.###.#.##.#.#.",
        ];
        ROWS.iter()
            .map(|row| row.chars().map(|c| c == '#').collect())
            .collect()
    }

    /// Blow the module matrix up to `scale` pixels per module and pad it with
    /// the quiet zone the standard requires — without it no detector finds
    /// anything, which is itself worth pinning down.
    fn render(modules: &[Vec<bool>], scale: usize, quiet: usize) -> (usize, usize, Vec<u8>) {
        let side = modules.len();
        let w = (side + 2 * quiet) * scale;
        let mut pixels = vec![255u8; w * w];
        for (my, row) in modules.iter().enumerate() {
            for (mx, dark) in row.iter().enumerate() {
                if !dark {
                    continue;
                }
                for dy in 0..scale {
                    let y = (my + quiet) * scale + dy;
                    let from = y * w + (mx + quiet) * scale;
                    pixels[from..from + scale].fill(0);
                }
            }
        }
        (w, w, pixels)
    }

    #[test]
    fn reads_a_code_from_a_greyscale_plane() {
        let (w, h, luma) = render(&modules(), 8, 4);
        assert_eq!(decode_luma(w, h, &luma), vec![PAYLOAD.to_string()]);
    }

    /// Dark-themed panels draw the code light-on-dark, and the detector only
    /// ever looks for dark modules — so the second pass has to exist.
    #[test]
    fn reads_an_inverted_code() {
        let (w, h, luma) = render(&modules(), 8, 4);
        let inverted: Vec<u8> = luma.iter().map(|v| 255 - v).collect();
        assert_eq!(decode_luma(w, h, &inverted), vec![PAYLOAD.to_string()]);
    }

    /// The shape GDI produces: four bytes a pixel, blue first, rows packed.
    #[test]
    fn reads_a_code_out_of_a_four_byte_frame() {
        let (w, h, luma) = render(&modules(), 8, 4);
        // Blue is doubled so a channel order read the wrong way round would
        // change the luminance instead of quietly matching.
        let bgra: Vec<u8> = luma
            .iter()
            .flat_map(|&v| [v.saturating_mul(2), v, v, 255])
            .collect();
        let flat = luma_from_pixels(w, h, w * 4, 4, &bgra, true).expect("a whole frame");
        assert_eq!(decode_luma(w, h, &flat), vec![PAYLOAD.to_string()]);
    }

    /// The shape a GdkPixbuf produces: three channels and rows padded out to a
    /// stride the caller does not choose.
    #[test]
    fn reads_a_code_out_of_padded_three_channel_rows() {
        let (w, h, luma) = render(&modules(), 8, 4);
        let stride = w * 3 + 7;
        let mut rgb = vec![0u8; stride * h];
        for y in 0..h {
            for x in 0..w {
                let v = luma[y * w + x];
                rgb[y * stride + x * 3..y * stride + x * 3 + 3].copy_from_slice(&[v, v, v]);
            }
        }
        let flat = luma_from_pixels(w, h, stride, 3, &rgb, false).expect("a whole frame");
        assert_eq!(decode_luma(w, h, &flat), vec![PAYLOAD.to_string()]);
    }

    /// The screen case: a small code somewhere on a large, textured desktop.
    #[test]
    fn finds_a_code_on_a_busy_desktop() {
        let side = 1200usize;
        let mut screen = vec![0u8; side * side];
        for y in 0..side {
            for x in 0..side {
                screen[y * side + x] = 190 + ((x / 7 + y / 11) % 40) as u8;
            }
        }
        let (qw, _, code) = render(&modules(), 4, 4);
        for y in 0..qw {
            screen[(300 + y) * side + 700..(300 + y) * side + 700 + qw]
                .copy_from_slice(&code[y * qw..(y + 1) * qw]);
        }
        assert_eq!(decode_luma(side, side, &screen), vec![PAYLOAD.to_string()]);
    }

    /// A page and its own preview put the same code on screen twice; the
    /// import must be offered once, not three times.
    #[test]
    fn repeats_of_one_code_collapse() {
        let (qw, _, code) = render(&modules(), 5, 4);
        let w = qw * 3;
        let mut sheet = vec![255u8; w * qw];
        for slot in 0..3 {
            for y in 0..qw {
                let from = y * w + slot * qw;
                sheet[from..from + qw].copy_from_slice(&code[y * qw..(y + 1) * qw]);
            }
        }
        assert_eq!(decode_luma(w, qw, &sheet), vec![PAYLOAD.to_string()]);
    }

    #[test]
    fn empty_desktop_yields_nothing() {
        assert!(decode_luma(64, 64, &vec![200u8; 64 * 64]).is_empty());
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_read_past() {
        assert!(decode_luma(64, 64, &[0u8; 10]).is_empty());
        assert!(decode_luma(0, 0, &[]).is_empty());
        assert!(luma_from_pixels(64, 64, 64 * 4, 4, &[0u8; 10], false).is_none());
        // A stride that cannot hold the row it claims to.
        assert!(luma_from_pixels(64, 64, 60, 4, &[0u8; 64 * 64 * 4], false).is_none());
        // Neither RGB nor RGBA.
        assert!(luma_from_pixels(64, 64, 64 * 2, 2, &[0u8; 64 * 64 * 2], false).is_none());
    }

    #[test]
    fn a_picture_that_is_not_a_picture_is_an_error_not_a_panic() {
        assert!(decode_image_file(b"not an image at all").is_err());
    }
}
