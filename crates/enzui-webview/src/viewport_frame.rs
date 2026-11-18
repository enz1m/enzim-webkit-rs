use iced::advanced::{
    Layout, image, layout, renderer,
    widget::{Tree, Widget},
};
use iced::{Element, Length, Rectangle, Size, mouse};

pub(super) struct ViewportFrame(image::Handle);

impl ViewportFrame {
    pub(super) fn new(handle: image::Handle) -> Self {
        Self(handle)
    }
}

impl<Message, Theme, Renderer> Widget<Message, Theme, Renderer> for ViewportFrame
where
    Renderer: image::Renderer<Handle = image::Handle>,
{
    fn size(&self) -> Size<Length> {
        Size::new(Length::Fill, Length::Fill)
    }
    fn layout(&mut self, tree: &mut Tree, _renderer: &Renderer, limits: &layout::Limits) {
        layout::Node::new(limits.resolve(Length::Fill, Length::Fill, Size::ZERO)).apply(tree);
    }
    fn draw(
        &self,
        _tree: &Tree,
        renderer: &mut Renderer,
        _theme: &Theme,
        _style: &renderer::Style,
        layout: Layout,
        _cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        let bounds = layout.bounds();
        let Some(clip) = bounds.intersection(viewport) else {
            return;
        };
        let size = renderer.measure_image(&self.0).unwrap_or_default();
        renderer.draw_image(
            image::Image {
                handle: self.0.clone(),
                filter_method: image::FilterMethod::Linear,
                rotation: iced::Radians(0.0),
                border_radius: iced::border::Radius::default(),
                opacity: 1.0,
            },
            Rectangle::new(
                bounds.position(),
                Size::new(size.width as f32, size.height as f32),
            ),
            clip,
        );
    }
}

impl<'a, Message: 'a, Theme: 'a, Renderer> From<ViewportFrame>
    for Element<'a, Message, Theme, Renderer>
where
    Renderer: image::Renderer<Handle = image::Handle> + 'a,
{
    fn from(frame: ViewportFrame) -> Self {
        Self::new(frame)
    }
}
