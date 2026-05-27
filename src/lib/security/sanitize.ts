import DOMPurify from "dompurify";

/**
 * Безпечні теги для email-контенту (RFC 5322 + типові email-клієнти)
 */
const EMAIL_SAFE_TAGS = [
    // text
    "p",
    "br",
    "hr",
    "div",
    "span",
    "b",
    "i",
    "u",
    "em",
    "strong",
    "small",
    "sub",
    "sup",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    // list
    "ul",
    "ol",
    "li",
    // table
    "table",
    "thead",
    "tbody",
    "tr",
    "td",
    "th",
    // format
    "pre",
    "code",
    "blockquote",
    "cite",
    // image
    "a",
    "img",
];

const EMAIL_SAFE_ATTR = [
    "href",
    "title",
    "alt",
    "width",
    "height",
    "class",
    "rel",
    // images
    "src",
    "srcset",
];

/**
 * Очищує HTML від шкідливого вмісту (захист від EFAIL/XSS).
 * Викликається в Content Script ПЕРЕД вставкою в DOM.
 */
export function sanitizeDecryptedHtml(rawHtml: string): string {
    const clean = DOMPurify.sanitize(rawHtml, {
        ALLOWED_TAGS: EMAIL_SAFE_TAGS,
        ALLOWED_ATTR: [
            "href",
            "title",
            "alt",
            "width",
            "height",
            "class",
            "rel",
            "src",
            "srcset",
            "target",
        ],
        ALLOW_DATA_ATTR: false,
        ALLOW_ARIA_ATTR: false,
        ALLOW_UNKNOWN_PROTOCOLS: false,
        ADD_ATTR: ["target"],
        FORBID_ATTR: ["onerror", "onload", "onclick", "onmouseover"],
        RETURN_DOM: false,
        RETURN_DOM_FRAGMENT: false,
        WHOLE_DOCUMENT: false,
    });

    const parser = new DOMParser();
    const doc = parser.parseFromString(clean, "text/html");

    doc.querySelectorAll('a[target="_blank"]').forEach((link) => {
        const existingRel = link.getAttribute("rel") || "";
        const relValues = new Set(existingRel.toLowerCase().split(/\s+/));

        relValues.add("noopener");
        relValues.add("noreferrer");

        link.setAttribute("rel", Array.from(relValues).join(" "));
    });

    doc.querySelectorAll("[style]").forEach((el) => {
        el.removeAttribute("style");
    });

    return doc.body.innerHTML;
}

/**
 * Для plain text (без HTML) — екрануємо, щоб уникнути injection
 */
export function sanitizePlainText(text: string): string {
    return DOMPurify.sanitize(text, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
    });
}
