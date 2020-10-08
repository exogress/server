use itertools::Itertools;
use typed_headers::{Quality, QualityItem};

pub fn ordered_by_quality<T>(quality_items: &Vec<QualityItem<T>>) -> impl Iterator<Item = &T> {
    quality_items
        .iter()
        .filter(|a| &a.quality > &Quality::from_u16(0))
        .sorted_by(|&a, &b| a.quality.cmp(&b.quality).reverse())
        .map(|qi| &qi.item)
}

pub fn is_mime_match(pattern: &mime::Mime, mime: &mime::Mime) -> bool {
    match (
        pattern.type_().as_str(),
        pattern.subtype().as_str(),
        mime.type_().as_str(),
        mime.subtype().as_str(),
    ) {
        ("*", "*", _, _) => true,
        (pattern_type, "*", mime_type, _) if pattern_type == mime_type => true,
        (pattern_type, pattern_subtype, mime_type, mime_subtype)
            if pattern_type == mime_type && pattern_subtype == mime_subtype =>
        {
            true
        }
        _ => false,
    }
}
