//! detection of image links in text

const IMAGE_EXTENSIONS: &[&str] = &[
    "apng", "avif", "bmp", "gif", "heic", "heif", "ico", "jfif", "jpeg", "jpg", "png", "svg",
    "tif", "tiff", "webp",
];

/// whether the text contains any http(s) url whose path ends in an image file extension
pub fn has_image_url(content: &str) -> bool {
    content.split_whitespace().any(|word| {
        let Some(start) = word.find("https://").or_else(|| word.find("http://")) else {
            return false;
        };
        let candidate = word[start..].trim_end_matches(|c: char| {
            matches!(
                c,
                '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}' | '>' | '"' | '\''
            )
        });

        let Ok(url) = url::Url::parse(candidate) else {
            return false;
        };
        let last_segment = url.path().rsplit('/').next().unwrap_or_default();
        match last_segment.rsplit_once('.') {
            Some((_, ext)) => IMAGE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
            None => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::has_image_url;

    #[test]
    fn detects_images() {
        for text in [
            "https://example.com/cat.png",
            "look: https://i.example.com/a/b/c.JPG?width=100#x",
            "(see http://example.com/x.webp).",
            "multi\nline\nhttps://cdn.example.com/abc.gif\n",
            "text before https://example.com/photo.jpeg, then more",
        ] {
            assert!(has_image_url(text), "should detect: {text}");
        }
    }

    #[test]
    fn ignores_non_images() {
        for text in [
            "",
            "just some words about png files",
            "https://example.com/",
            "https://example.com/page.html",
            "https://example.com/video.mp4",
            "https://png.example.com/thing",
            "example.com/cat.png",
            "https://example.com/?file=cat.png",
        ] {
            assert!(!has_image_url(text), "should not detect: {text}");
        }
    }
}
