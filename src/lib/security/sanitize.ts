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
    ADD_ATTR: ["target"],
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

/**
 * Очищує розшифрований HTML від шкідливого вмісту.
 * Захист від EFAIL-атак (CSS exfiltration, CFB malleability) та XSS.
 *
 * ВИКЛИКАЄТЬСЯ В CONTENT SCRIPT ПЕРЕД ВСТАВКОЮ В DOM.
 */
export function sanitizeDecryptedHtml(rawHtml: string): string {
    if (!rawHtml || typeof rawHtml !== "string") return "";

    const clean = DOMPurify.sanitize(rawHtml, PURIFY_HTML_CONFIG);

    // Додатковий pass: примусово додаємо rel="noopener noreferrer" до всіх зовнішніх посилань
    const parser = new DOMParser();
    const doc = parser.parseFromString(clean, "text/html");

    doc.querySelectorAll("a").forEach((link) => {
        // Безпечний target для всіх посилань
        link.setAttribute("target", "_blank");

        // Об'єднати існуючі rel-значення з noopener/noreferrer
        const existingRel = link.getAttribute("rel") ?? "";
        const relValues = new Set(
            existingRel.toLowerCase().split(/\s+/).filter(Boolean),
        );
        relValues.add("noopener");
        relValues.add("noreferrer");
        link.setAttribute("rel", Array.from(relValues).join(" "));

        // Блокувати mailto: з body/cc/bcc параметрами (potential exfiltration vector)
        const href = link.getAttribute("href") ?? "";
        if (
            href.toLowerCase().startsWith("mailto:") &&
            /[?&](body|cc|bcc)=/i.test(href)
        ) {
            link.removeAttribute("href");
            link.setAttribute("title", "[Blocked: suspicious mailto link]");
        }
    });

    // Видалити img без src або з data: URI (tracking pixels)
    doc.querySelectorAll("img").forEach((img) => {
        const src = img.getAttribute("src") ?? "";
        if (!src || src.trim().toLowerCase().startsWith("data:")) {
            img.remove();
        }
    });

    return doc.body.innerHTML;
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
