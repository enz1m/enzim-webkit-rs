// Nonzero, position-dependent bytes detect missing, reordered or truncated pixels.
fn patterned_frame(w: u32, h: u32) -> Rgba8Frame {
    let pixels: Vec<u8> = (0..(w as usize * h as usize * 4))
        .map(|i| ((i * 7 + 13) % 255 + 1) as u8)
        .collect();
    Rgba8Frame::new(Generation::FIRST, FrameSeq(1), w, h, pixels)
        .expect("a patterned frame with w*h*4 bytes is valid")
}

/// A frame filled with one opaque colour, for assertions on painted output.
fn solid_frame(w: u32, h: u32, rgb: (u8, u8, u8)) -> Rgba8Frame {
    let mut pixels = Vec::with_capacity(w as usize * h as usize * 4);
    for _ in 0..(w as usize * h as usize) {
        pixels.extend_from_slice(&[rgb.0, rgb.1, rgb.2, 255]);
    }
    Rgba8Frame::new(Generation::FIRST, FrameSeq(1), w, h, pixels)
        .expect("a solid frame with w*h*4 bytes is valid")
}

/// The `Handle::Rgba` parts, or a panic naming the variant that arrived.
///
/// `from_rgba` must produce the decoded-pixel variant; a `Path` or `Bytes`
/// handle would mean the frame was routed through a file or an encoder -- a
/// different and far more expensive presentation path.
fn rgba_parts(handle: &iced_image::Handle) -> (u32, u32, Vec<u8>) {
    match handle {
        iced_image::Handle::Rgba {
            width,
            height,
            pixels,
            ..
        } => (*width, *height, pixels.to_vec()),
        other => panic!(
            "web_frame_handle must mint the decoded-RGBA variant so the \
             renderer uploads our pixels directly; got {other:?}"
        ),
    }
}

#[test]
fn the_frames_own_pixels_reach_the_painted_surface() {
    // End-to-end through the real widget and the real renderer: a frame
    // of a known colour is presented by `EnzWebView`, and that colour is
    // what gets painted. This spans web_frame_handle -> enz_image_handle
    // -> draw, so a break anywhere on that path reddens it.
    //
    // A large uniform block sampled at the centre with a tolerance, on
    // purpose: the surface is Contain-fit and scaled, and this harness
    // resolves a different backend depending on how the suite is invoked
    // GPU filtering can vary, so exact equality on a filtered edge pixel would be
    // backend-dependent. A uniform interior reads the same under either.
    const W: u32 = 200;
    const H: u32 = 200;
    let teal = (0u8, 160u8, 160u8);
    let el: Element<'static, ()> = enz_web_view_owned(view(), solid_frame(64, 64, teal), true)
        .title("Px")
        .into();
    let (px, _root, bg) = render(el, W, H);

    let i = (((H / 2) * W + (W / 2)) * 4) as usize;
    let (r, g, b) = (px[i] as i32, px[i + 1] as i32, px[i + 2] as i32);

    // Positive control: the sampled pixel is not the theme background, so the
    // surface genuinely painted something there.
    let bg8 = (
        (bg.r * 255.0).round() as i32,
        (bg.g * 255.0).round() as i32,
        (bg.b * 255.0).round() as i32,
    );
    assert!(
        (r - bg8.0).abs() + (g - bg8.1).abs() + (b - bg8.2).abs() > 6,
        "the surface centre is still the theme background ({bg8:?}), so no \
         frame was painted at all; got ({r},{g},{b})"
    );

    // The frame's OWN colour, within a tolerance that survives scaling and
    // either renderer backend.
    let want = (teal.0 as i32, teal.1 as i32, teal.2 as i32);
    let dist = (r - want.0).abs() + (g - want.1).abs() + (b - want.2).abs();
    assert!(
        dist <= 30,
        "the painted surface must show the frame's own colour {want:?}; got \
         ({r},{g},{b}), manhattan distance {dist}"
    );
}

/// The same engine frame keeps one renderer identity across host rebuilds; an
/// identical re-snapshot keeps it too; new pixels or a new generation do not.
#[test]
fn a_retained_frame_handle_survives_rebuilds_and_identical_snapshots() {
    let retained = crate::RetainedFrameHandle::default();
    let first = patterned_frame(4, 3);
    let id = retained.handle_for(&first).id();
    for _ in 0..3 {
        assert_eq!(retained.handle_for(&first).id(), id, "an unrelated rebuild");
    }
    let resnap = Rgba8Frame::new(
        Generation::FIRST,
        FrameSeq(2),
        4,
        3,
        first.pixels().to_vec(),
    )
    .expect("valid");
    assert_eq!(
        retained.handle_for(&resnap).id(),
        id,
        "an identical re-snapshot"
    );

    let changed = solid_frame(4, 3, (10, 20, 30));
    let changed = Rgba8Frame::new(
        Generation::FIRST,
        FrameSeq(3),
        4,
        3,
        changed.pixels().to_vec(),
    )
    .expect("valid");
    let changed_id = retained.handle_for(&changed).id();
    assert_ne!(changed_id, id, "new pixels upload once");
    assert_eq!(
        rgba_parts(&retained.handle_for(&changed)).2,
        changed.pixels()
    );

    let regenerated = Rgba8Frame::new(
        Generation::FIRST.next(),
        FrameSeq(3),
        4,
        3,
        changed.pixels().to_vec(),
    )
    .expect("valid");
    assert_ne!(
        retained.handle_for(&regenerated).id(),
        changed_id,
        "a new generation never reuses an old generation's handle"
    );
    let regenerated_id = retained.handle_for(&regenerated).id();
    retained.clear();
    assert_ne!(
        retained.handle_for(&regenerated).id(),
        regenerated_id,
        "cleared"
    );
}
