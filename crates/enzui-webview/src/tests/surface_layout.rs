// The surface's measured width cap and loading placeholder extent are
// pixel/geometry claims read from real layout and rendering. Builder-field
// assertions cannot detect the `Length::Fill` trap or a fixed child inside a
// derived-height parent.
//
// `include!`d by `web_view/tests.rs` - same module, unchanged test paths.

// ---------------------------------------------------------------------------
// 5. The surface width is capped - measured in laid-out pixels.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Placeholder extent: the loading placeholder fills the box it reserves.
// ---------------------------------------------------------------------------

#[test]
fn the_loading_placeholder_paints_the_box_it_reserves() {
    // The awaiting placeholder wraps a skeleton in an aspect-ratio
    // frame whose height is derived from the resolved width (800 / (4/3) = 600
    // at the default cap). A fixed-height skeleton painted 120 of those 600 px
    // and left 80 % bare backdrop: a narrow grey bar floating at the top of a
    // large empty rectangle. Measured in painted pixels, not builder fields -
    // a `card_height` assertion is green whether or not anything reaches the
    // renderer.
    const W: u32 = 900;
    const H: u32 = 700;
    let el: Element<'static, ()> = enz_web_view(view(), None, true).title("Example").into();
    let (px, box_rect, bg) = render(el, W, H);

    // Calibrate the box first: the ink number below is meaningless unless the
    // placeholder really did reserve a tall, capped frame.
    assert!(
        (box_rect.width - DEFAULT_MAX_SURFACE_WIDTH).abs() < 1.0,
        "expected the placeholder box to be capped at {DEFAULT_MAX_SURFACE_WIDTH}, got {box_rect:?}"
    );
    let expected_h = DEFAULT_MAX_SURFACE_WIDTH / DEFAULT_ASPECT_RATIO;
    assert!(
        (box_rect.height - expected_h).abs() < 1.0,
        "expected a {expected_h}px derived height, got {box_rect:?}; \
         the 80%-empty defect is only meaningful against a derived box"
    );

    let x = (box_rect.x + box_rect.width / 2.0) as u32;
    let y0 = box_rect.y.ceil() as u32;
    let y1 = (box_rect.y + box_rect.height).floor() as u32;
    let ink = painted_rows(&px, W, x, y0, y1, bg);

    // The probe can see ink at all. A column that reports 0 everywhere is
    // a broken probe, not a full placeholder.
    assert!(
        ink > 0,
        "probe saw no skeleton ink at all in {y0}..{y1} — the measurement is blind"
    );

    let coverage = ink as f32 / (y1 - y0) as f32;
    println!(
        "MEASURED awaiting placeholder ink = {ink}/{} rows ({:.1}%)",
        y1 - y0,
        coverage * 100.0
    );
    assert!(
        coverage > 0.95,
        "the loading placeholder paints only {ink} of {} reserved rows ({:.1}%); \
         it must fill the frame it reserves, not leave 80% bare backdrop",
        y1 - y0,
        coverage * 100.0
    );
}

#[test]
fn viewport_resize_cpu_pixels_keep_size_origin_and_clip() {
    for (w, h) in [(640, 400), (180, 150)] {
        let mut rgba = vec![0; 400 * 240 * 4];
        for pixel in rgba.as_chunks_mut::<4>().0 {
            pixel[3] = 255;
        }
        for y in 48..112 {
            for x in 40..104 {
                let start = (y * 400 + x) * 4;
                rgba[start..start + 4].copy_from_slice(&[238, 0, 170, 255]);
            }
        }
        let frame = Rgba8Frame::new(Generation::FIRST, FrameSeq(1), 400, 240, rgba).expect("frame");
        let element = enz_web_view_owned::<()>(view(), frame, true)
            .fill_viewport(true)
            .into();
        let (pixels, bounds, _) = render(element, w, h);
        let mut coordinates = Vec::new();
        for (index, pixel) in pixels.as_chunks::<4>().0.iter().enumerate() {
            if pixel[..3] == [238, 0, 170] {
                coordinates.push((index as u32 % w, index as u32 / w));
            }
        }
        assert_eq!(
            bounds.size(),
            Size::new(w as f32, h as f32),
            "viewport allocation remains full sized"
        );
        assert_eq!(
            coordinates.len(),
            64 * 64,
            "source marker retains its native area"
        );
        assert_eq!(
            coordinates.first(),
            Some(&(40, 48)),
            "source origin stays anchored"
        );
        assert_eq!(
            coordinates.last(),
            Some(&(103, 111)),
            "source extent stays unchanged"
        );
    }
}
