use super::ExportError;

pub fn rasterize_svg(svg: &str) -> Result<Vec<u8>, ExportError> {
    let mut opt = resvg::usvg::Options::default();
    opt.fontdb_mut().load_system_fonts();
    let tree = resvg::usvg::Tree::from_str(svg, &opt)
        .map_err(|err| ExportError::Rasterize(err.to_string()))?;
    let size = tree.size().to_int_size();
    let mut pixmap = resvg::tiny_skia::Pixmap::new(size.width(), size.height())
        .ok_or_else(|| ExportError::Rasterize("pixmap allocation failed".into()))?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::default(),
        &mut pixmap.as_mut(),
    );
    pixmap
        .encode_png()
        .map_err(|err| ExportError::Rasterize(err.to_string()))
}
