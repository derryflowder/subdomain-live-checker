from src.techdetect import detect_technologies


def _find(techs, name):
    return next((t for t in techs if t.name == name), None)


def test_detects_nginx_version_from_server_header():
    techs = detect_technologies("", {"server": "nginx/1.24.0"})
    nginx = _find(techs, "nginx")
    assert nginx is not None
    assert nginx.version == "1.24.0"


def test_detects_wordpress_version_from_generator():
    html = '<meta name="generator" content="WordPress 6.4.2">'
    techs = detect_technologies(html, {})
    wp = _find(techs, "WordPress")
    assert wp is not None
    assert wp.version == "6.4.2"


def test_detects_jquery_version_from_html():
    html = '<script src="/js/jquery-3.6.0.min.js"></script>'
    techs = detect_technologies(html, {})
    jq = _find(techs, "jQuery")
    assert jq is not None
    assert jq.version == "3.6.0"


def test_html_version_overrides_versionless_header():
    headers = {"x-drupal-cache": "HIT"}
    html = '<meta name="generator" content="Drupal 9 (https://www.drupal.org)">'
    techs = detect_technologies(html, headers)
    drupal = _find(techs, "Drupal")
    assert drupal is not None
    assert drupal.version == "9"


def test_existing_version_is_kept_when_new_is_versionless():
    headers = {"server": "nginx/1.24.0"}
    html = '<meta name="generator" content="nginx">'
    techs = detect_technologies(html, headers)
    nginx = _find(techs, "nginx")
    assert nginx is not None
    assert nginx.version == "1.24.0"


def test_wordpress_not_duplicated_from_html_rules():
    html = (
        '<meta name="generator" content="WordPress 6.4.2">'
        '<link href="/wp-content/themes/style.css">'
    )
    techs = detect_technologies(html, {})
    wps = [t for t in techs if t.name == "WordPress"]
    assert len(wps) == 1
    assert wps[0].version == "6.4.2"


def test_display_helper():
    from src.models import TechDetection

    assert TechDetection(name="nginx", version="1.24.0").display() == "nginx/1.24.0"
    assert TechDetection(name="nginx").display() == "nginx"


def test_no_technologies_detected():
    assert detect_technologies("", {}) == []