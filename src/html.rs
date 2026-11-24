use axum::response::Html;

use crate::client_ip::escape_html;

pub fn render_page(title: &str, body_html: &str) -> Html<String> {
    let title = escape_html(title);
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{ max-width: 96ch; }}
pre {{ overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
textarea {{ width: 100%; max-width: 90ch; box-sizing: border-box; }}
input[type="url"], input[type="text"] {{ width: 100%; max-width: 70ch; box-sizing: border-box; }}
.tools {{ border-collapse: collapse; }}
.tools th, .tools td {{ padding: 0.25em 0; text-align: left; vertical-align: top; }}
.tools th {{ padding-right: 1.5em; font-weight: normal; }}
</style>
</head>
<body>
<nav>
<a href="/trace">/trace</a> |
<a href="/ports">/ports</a> |
<a href="/hook">/hook</a> |
<a href="/httpbin">/httpbin</a> |
<a href="/newlines">/newlines</a> |
<a href="/whois">/whois</a> |
<a href="/">Info</a>
</nav>
<hr>
<h1>{title}</h1>
{body_html}
</body>
</html>
"#
    ))
}
