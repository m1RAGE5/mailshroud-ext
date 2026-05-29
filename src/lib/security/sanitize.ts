import DOMPurify, { type Config } from "dompurify";

// ─────────────────────────────────────────────────────────────
//  EFAIL / XSS Protection Config
// ─────────────────────────────────────────────────────────────

/**
 * Безпечні HTML-теги для email-контенту.
 * Виключено: <style>, <script>, <iframe>, <object>, <embed>, <form>, <input>,
 * <meta>, <link>, <base> — усі вони є векторами EFAIL-атак.
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
    // lists
    "ul",
    "ol",
    "li",
    // tables
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
    "caption",
    "colgroup",
    "col",
    // formatting
    "pre",
    "code",
    "blockquote",
    "cite",
    "figure",
    "figcaption",
    // links & media
    "a",
    "img",
] as const;

/**
 * Дозволені атрибути.
 * Виключено: on* (event handlers), style (CSS exfiltration),
 * background (EFAIL), dynsrc/lowsrc (IE legacy vectors).
 */
const EMAIL_SAFE_ATTR = [
    "href",
    "title",
    "alt",
    "width",
    "height",
    "class",
    "rel",
    "target",
    "src",
    "srcset",
    "sizes",
    // table attributes
    "colspan",
    "rowspan",
    "scope",
    "align",
    "valign",
    // list attributes
    "type",
    "start",
] as const;

/** Спільна конфігурація DOMPurify для HTML email */
const PURIFY_HTML_CONFIG: Config = {
    ALLOWED_TAGS: [...EMAIL_SAFE_TAGS],
    ALLOWED_ATTR: [...EMAIL_SAFE_ATTR],
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    // Безпечні протоколи для href/src (блокує javascript:, vbscript:, data:)
    ALLOWED_URI_REGEXP:
        /^(?:(?:https?|mailto|ftp|tel|sms):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
    ADD_ATTR: ["target", "rel"],
    FORBID_ATTR: [
        "style",
        "background",
        "dynsrc",
        "lowsrc",
        "srcdoc",
        "onerror",
        "onload",
        "onclick",
        "onmouseover",
        "onfocus",
        "onblur",
    ],
    FORBID_TAGS: [
        "style",
        "script",
        "iframe",
        "object",
        "embed",
        "form",
        "input",
        "meta",
        "link",
        "base",
    ],
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    WHOLE_DOCUMENT: false,
} as const;

// ─────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
    if (node.tagName === "A") {
        node.setAttribute("target", "_blank");
        node.setAttribute("rel", "noopener noreferrer");

        // Блокування підозрілих mailto
        const href = node.getAttribute("href") ?? "";
        if (
            href.toLowerCase().startsWith("mailto:") &&
            /[?&](body|cc|bcc)=/i.test(href)
        ) {
            node.removeAttribute("href");
            node.setAttribute("title", "[Blocked: suspicious mailto link]");
        }
    }
    // Видалення трекінгових пікселів
    if (node.tagName === "IMG") {
        const src = node.getAttribute("src") ?? "";
        if (!src || src.trim().toLowerCase().startsWith("data:")) {
            node.remove();
        }
    }
});

export function sanitizeDecryptedHtml(rawHtml: string): string {
    if (!rawHtml || typeof rawHtml !== "string") return "";
    // Тепер одного виклику достатньо, хук зробить решту
    return DOMPurify.sanitize(rawHtml, PURIFY_HTML_CONFIG);
}

/**
 * Очищує plain text від будь-яких HTML-тегів.
 * Використовується коли email має text/plain MIME-тип.
 */
export function sanitizePlainText(text: string): string {
    if (!text || typeof text !== "string") return "";

    return DOMPurify.sanitize(text, {
        ALLOWED_TAGS: [], // Тільки текст, жодних тегів
        ALLOWED_ATTR: [],
    });
}
