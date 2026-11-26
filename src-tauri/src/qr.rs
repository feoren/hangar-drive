//! The QR code of a pairing offer (ux-concept 5): the module matrix the window's type names
//! (`QrMatrix`) and the same code as an SVG document, which the window shows as an image
//! (`img-src data:` in the CSP), so no markup from the backend is ever put into the page.

use hangar_drive_sync::api::QrMatrix;
use qrcode::render::svg;
use qrcode::{Color, EcLevel, QrCode};

#[derive(Debug, thiserror::Error)]
#[error("the link does not fit a QR code")]
pub struct QrError;

/// Error correction M (15 %): a pairing link of about 400 characters stays a code a webcam
/// reads on a screen.
pub fn encode(link: &str) -> Result<(QrMatrix, String), QrError> {
    let code =
        QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M).map_err(|_| QrError)?;
    let size = u32::try_from(code.width()).map_err(|_| QrError)?;
    let modules: String = code
        .to_colors()
        .iter()
        .map(|c| if *c == Color::Dark { '1' } else { '0' })
        .collect();
    let svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();
    Ok((QrMatrix { size, modules }, svg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matrix_and_the_svg_describe_one_code() {
        let link = format!("hangar-drive://pair#{}", "A".repeat(400));
        let (matrix, svg) = encode(&link).unwrap();
        assert_eq!(matrix.modules.len(), (matrix.size * matrix.size) as usize);
        assert!(matrix.modules.bytes().all(|b| b == b'0' || b == b'1'));
        // The three finder patterns: the top left module is dark.
        assert!(matrix.modules.starts_with("1111111"));
        assert!(svg.contains("<svg"));
        assert!(!svg.contains("<script"));
        assert!(encode(&"A".repeat(5000)).is_err());
    }
}
