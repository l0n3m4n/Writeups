-- ----------------------------
--  Table structure for "rite_banlists"
-- ----------------------------
DROP TABLE IF EXISTS "rite_banlists";
CREATE TABLE "rite_banlists" (name varchar(255) NOT NULL default '', list text NOT NULL);

-- ----------------------------
--  Records of "rite_banlists"
-- ----------------------------
BEGIN;
INSERT INTO "rite_banlists" VALUES ('user_agents', '');
INSERT INTO "rite_banlists" VALUES ('ips', '');
INSERT INTO "rite_banlists" VALUES ('words', '');
COMMIT;

-- ----------------------------
--  Table structure for "rite_gcb"
-- ----------------------------
DROP TABLE IF EXISTS "rite_gcb";
CREATE TABLE "rite_gcb" (id INTEGER PRIMARY KEY AUTOINCREMENT, title varchar(255) NOT NULL default '', content text NOT NULL, content_formatting tinyint(4) default '0');

-- ----------------------------
--  Table structure for "rite_menus"
-- ----------------------------
DROP TABLE IF EXISTS "rite_menus";
CREATE TABLE "rite_menus" (id INTEGER PRIMARY KEY AUTOINCREMENT, menu varchar(255) NOT NULL default '', sequence int(11) NOT NULL default '1', name varchar(255) NOT NULL default '', title varchar(255) NOT NULL default '', link varchar(255) NOT NULL default '', section varchar(255) NOT NULL default '', accesskey varchar(255) NOT NULL default '',submenu varchar(255) NOT NULL default '');

-- ----------------------------
--  Records of "rite_menus"
-- ----------------------------
BEGIN;
INSERT INTO "rite_menus" VALUES (1, 'main_menu', 1, 'Home', 'Home', '', 'home', 0,'');
INSERT INTO "rite_menus" VALUES (2, 'main_menu', 2, 'news', 'news', 'news', 'news', '','');
INSERT INTO "rite_menus" VALUES (3, 'main_menu', 4, 'contact', 'contact', 'contact', 'contact', '','');
INSERT INTO "rite_menus" VALUES (4, 'main_menu', 3, 'blog', 'blog', 'blog', 'blog', '','');
COMMIT;

-- ----------------------------
--  Table structure for "rite_news"
-- ----------------------------
DROP TABLE IF EXISTS "rite_news";
CREATE TABLE "rite_news" ("id" INTEGER PRIMARY KEY  NOT NULL , "page_id" INTEGER, "time" INTEGER, "title" VARCHAR NOT NULL , "teaser" TEXT, "text" TEXT, "text_formatting" INTEGER, "linkname" VARCHAR);

-- ----------------------------
--  Table structure for "rite_notes"
-- ----------------------------
DROP TABLE IF EXISTS "rite_notes";
CREATE TABLE "rite_notes" (id INTEGER PRIMARY KEY AUTOINCREMENT, note_section varchar(255) NOT NULL default '', sequence int(11) NOT NULL default '1', time int(11) NOT NULL default '0', title varchar(255) NOT NULL default '', text TEXT NOT NULL, text_formatting tinyint(4) default '0', link varchar(255) NOT NULL default '', linkname varchar(255) NOT NULL default '', "teaser" TEXT);

-- ----------------------------
--  Table structure for "rite_pages"
-- ----------------------------
DROP TABLE IF EXISTS "rite_pages";
CREATE TABLE "rite_pages" (id INTEGER PRIMARY KEY AUTOINCREMENT, page varchar(255) NOT NULL default '', author int(11) NOT NULL default '0', type varchar(255) NOT NULL default '', type_addition varchar(255) NOT NULL default '', time int(11) NOT NULL default '0', display_time tinyint(4) default '0', last_modified int(11) NOT NULL default '0', last_modified_by int(11) NOT NULL default '0', title varchar(255) NOT NULL default '', page_title varchar(255) NOT NULL default '', description varchar(255) NOT NULL default '', keywords varchar(255) NOT NULL default '', page_info varchar(255) NOT NULL default '' , language_file varchar(255) NOT NULL default '', breadcrumbs varchar(255) NOT NULL default '', sections varchar(255) NOT NULL default '', include_page int(11) NOT NULL default '0', include_order int(11) NOT NULL default '0', include_rss int(11) NOT NULL default '0', include_sitemap int(11) NOT NULL default '0', link_name varchar(255) NOT NULL default '', menu_1 varchar(255) NOT NULL default '', menu_2 varchar(255) NOT NULL default '', menu_3 varchar(255) NOT NULL default '', gcb_1 int(11) NOT NULL default '0', gcb_2 int(11) NOT NULL default '0', gcb_3 int(11) NOT NULL default '0', template varchar(255) NOT NULL default '',template_mobile varchar(255) NOT NULL default '', content_type varchar(255) NOT NULL default '', charset varchar(255) NOT NULL default '', headline varchar(255) NOT NULL default '', teaser_headline varchar(255) NOT NULL default '', teaser TEXT, teaser_formatting tinyint(4) default '0', teaser_img varchar(255) NOT NULL default '', content TEXT, content_formatting tinyint(4) default '0', sidebar_1 TEXT, sidebar_1_formatting tinyint(4) default '0', sidebar_2 TEXT, sidebar_2_formatting tinyint(4) default '0', sidebar_3 TEXT, sidebar_3_formatting tinyint(4) default '0', inline_style TEXT,page_notes TEXT, edit_permission varchar(255) NOT NULL default '', edit_permission_general tinyint(4) default '0', custom_values varchar(255) NOT NULL default '', status tinyint(4) default '2', views int(11) NOT NULL default '0', "include_news" INTEGER DEFAULT 0, "category" VARCHAR);

-- ----------------------------
--  Records of "rite_pages"
-- ----------------------------
BEGIN;
INSERT INTO "rite_pages" VALUES (1, 'index', 1, 'default', '', 1230768000, 0, 1376531630, 1, 'Home', 'A simple &amp; lightweight CMS', 'phpSQLiteCMS - a simple and lightweight open source web content management system based on PHP and SQLite', 'CMS, content management system, php, sqlite, simple, lightweight', '', '', '', 'home', 0, 0, 0, 6, 'more...', 'main_menu', '', '', 0, 0, 0, 'default.tpl', '', '', '', '', '', 1, '', '<h1>Welcome!</h1>

<p><em>phpSQLiteCMS</em> is a simple and lightweight open source web content management system (CMS) based on <a class="extern" href="http://php.net/">PHP</a> and <a class="extern" href="http://www.sqlite.org/">SQLite</a>. It''s licensed under the <a class="extern" href="http://www.gnu.org/copyleft/gpl.html">GNU General Public License</a>.</p>

<p><em>phpSQLiteCMS</em> is good if you want to quickly set up a small website without needing to spend a lot of time studying, installing and configuring (as SQLite is file-based, it just runs "out of the box"). But note that it is no large scale content management system - it''s a tiny and simple one!</p>

<h2>Features</h2>

<ul>

<li>Simple and lightweight</li>

<li>Runs out of the box (no database setup required)</li>

<li>Optional caching to save server performance</li>

<li>Supports news, overview and commentable pages, photo galleries, search function, RSS feeds and XML sitemaps</li>

</ul>', 0, '<div class="sidebarbox">

<h3>It works!</h3>

<p>If you see this, <em>phpSQLiteCMS</em> seems to work! First thing to do is [[cms/index.php|log in]] and [[cms/index.php?mode=users&amp;edit=1|change the password]] (the default username and password is <em>admin</em>).</p>

</div>

<div class="sidebarbox subbox">

<h3>Search</h3>

<form id="search" action="search" method="post">

<p><label for="searchfield">Search this website:</label><br /> <input id="searchfield" maxlength="200" name="q" size="22" type="text" value="" /> <input alt="&raquo;" name="" src="templates/images/submit.png" type="image" /></p>

</form></div>', 0, '', 0, '', 0, '','<p>Here you can write down notes. These notes will not be published.</p>', '', 1, '', 2, 0, 0, '');
INSERT INTO "rite_pages" VALUES (2, 'news', 1, 'simple_news', '', 1376531118, 0, 1376531118, 1, 'news', '', '', '', '', '', '', 'news', 0, 0, 0, 0, 'more...', 'main_menu', '', '', 0, 0, 0, 'default.tpl', '', '', '', '', '', 1, '', '', 0, '', 0, '', 0, '', 0, '','', '', 0, '', 2, 0, 0, '');
INSERT INTO "rite_pages" VALUES (3, 'contact', 1, 'formmailer', 'me@company.com', 1376531049, 0, 1376531049, 1, 'contact', '', '', '', '', '', '', 'contact', 0, 0, 0, 0, 'more...', 'main_menu', '', '', 0, 0, 0, 'default.tpl', '', '', '', '', '', 1, '', '<p>contact us</p>', 0, '', 0, '', 0, '', 0, '','', '', 0, '', 2, 0, 0, '');
INSERT INTO "rite_pages" VALUES (4, 'search', 1, 'search', '', 1271160054, 0, 1274165940, 1, 'Search', '', '', '', '', '', '', '', 0, 0, 0, 0, 'mehr …', 'main_menu', '', '', 0, 0, 0, 'default.tpl', '', '', 'Search', '', '', 1, '', '', 0, '', 0, '', 0, '', 0, '','', '', 0, '', 1, 0, null, null);
INSERT INTO "rite_pages" VALUES (5, 404, 1, 'default', '', 1230764400, 0, 1274166958, 1, 'Not Found', '404 Not Found', '', '', '', '', '', '', 0, 0, 0, 0, 'mehr...', 'main_menu', '', '', 0, 0, 0, 'default.tpl', '', '', 'Not Found', '', '', 1, '', 'The requested URL was not found on this server.', 1, '<div class="sidebarbox">

<h3>Search</h3>

<form id="search" action="search" method="post">

<p><input id="searchfield" type="text" name="q" value="" size="22" maxlength="200" />

<input type="image" name="" src="templates/images/submit.png" alt="&raquo;" /></p>

</form>

</div>', 0, '', 0, '', 0, '','', '', 0, '', 1, 0, null, null);
INSERT INTO "rite_pages" VALUES (6, 'sitemap.xml', 1, 'sitemap', '', 1164830100, 0, 1272119111, 1, 'XML Sitemap', '', '', '', '', '', '', '', 0, 0, 0, 0, 'more...', '', '', '', 0, 0, 0, 'default.tpl', '', '', '', '', '', 1, '', '', 1, '', 1, '', 1, '', 1, '','', '', 0, '', 1, 0, 0, null);
INSERT INTO "rite_pages" VALUES (7, 'robots.txt', 1, 'default', '', 1166383500, 0, 1272120011, 1, 'robots.txt', '', '', '', '', '', '', '', 0, 0, 0, 0, 'more...', '', '', '', 0, 0, 0, 'plain.tpl', 'text/plain', '', '', '', '', 1, '', 'User-agent: *
Disallow:', 0, '', 1, '', 1, '', 1, '', '', 0, '', 1, 0, 0, null);
INSERT INTO "rite_pages" VALUES (8, 'rss', 1, 'rss', '', 1274189635, 0, 1274189635, 1, 'RSS Feed', '', 'Demo RSS Feed', '', '', '', '', '', 0, 0, 0, 0, 'mehr …', '', '', '', 0, 0, 0, 'default.tpl', '', '', '', '', '', 1, '', '', 0, '', 0, '', 0, '', 0, '','', '', 0, '', 2, 0, null, null);
INSERT INTO "rite_pages" VALUES (37, 'blog', 1, 'news', 'blog', 1376532579, 0, 1376532703, 1, 'blog', '', '', '', '', '', '', 'blog', 0, 0, 0, 0, 'more...', 'main_menu', '', '', 0, 0, 0, 'default.tpl', '', '', '', '', '', 1, '', '<p>blog</p>', 0, '', 0, '', 0, '', 0, '','', '', 0, '', 2, 0, 0, '');
COMMIT;

-- ----------------------------
--  Table structure for "rite_photos"
-- ----------------------------
DROP TABLE IF EXISTS "rite_photos";
CREATE TABLE "rite_photos" (id INTEGER PRIMARY KEY AUTOINCREMENT, gallery varchar(255) NOT NULL default '', sequence int(11) NOT NULL default '1', photo_thumbnail varchar(255) NOT NULL default '', photo_normal varchar(255) NOT NULL default '', photo_large varchar(255) NOT NULL default '', photo_xlarge varchar(255) NOT NULL default '', width int(11) NOT NULL default '0', height int(11) NOT NULL default '0', large_width int(11) NOT NULL default '0', large_height int(11) NOT NULL default '0', title varchar(255) NOT NULL default '', subtitle varchar(255) NOT NULL default '', description TEXT NOT NULL, description_formatting tinyint(4) default '0', template varchar(255) NOT NULL default '', photos_per_row tinyint(4) NOT NULL default '4');

-- ----------------------------
--  Table structure for "rite_settings"
-- ----------------------------
DROP TABLE IF EXISTS "rite_settings";
CREATE TABLE "rite_settings" (name varchar(255) NOT NULL default '', value varchar(255) NOT NULL default '');

-- ----------------------------
--  Records of "rite_settings"
-- ----------------------------
BEGIN;
INSERT INTO "rite_settings" VALUES ('index_page', 'index');
INSERT INTO "rite_settings" VALUES ('error_page', 404);
INSERT INTO "rite_settings" VALUES ('comment_order', 1);
INSERT INTO "rite_settings" VALUES ('comments_per_page', 10);
INSERT INTO "rite_settings" VALUES ('default_page_language_file', 'English.lang.php');
INSERT INTO "rite_settings" VALUES ('website_title', 'RiteCMS');
INSERT INTO "rite_settings" VALUES ('website_subtitle', 'A simple & lightweight CMS');
INSERT INTO "rite_settings" VALUES ('website_footnote_1', '');
INSERT INTO "rite_settings" VALUES ('website_footnote_2', '&copy; 2013 &hellip;');
INSERT INTO "rite_settings" VALUES ('news_per_page', 10);
INSERT INTO "rite_settings" VALUES ('email', 'me@example.com');
INSERT INTO "rite_settings" VALUES ('comment_notification', 0);
INSERT INTO "rite_settings" VALUES ('comment_maxlength', 1000);
INSERT INTO "rite_settings" VALUES ('word_maxlength', 30);
INSERT INTO "rite_settings" VALUES ('name_maxlength', 50);
INSERT INTO "rite_settings" VALUES ('email_hp_maxlength', 100);
INSERT INTO "rite_settings" VALUES ('default_image_class', 'teaser');
INSERT INTO "rite_settings" VALUES ('default_thumbnail_class', 'teaser');
INSERT INTO "rite_settings" VALUES ('default_gallery_image_class', 'thumbnail');
INSERT INTO "rite_settings" VALUES ('image_classes', 'float-left, float-right, thumbnail');
INSERT INTO "rite_settings" VALUES ('photos_commentable', 0);
INSERT INTO "rite_settings" VALUES ('count_views', 0);
INSERT INTO "rite_settings" VALUES ('default_template', 'default.tpl');
INSERT INTO "rite_settings" VALUES ('default_photo_template', 'photo.tpl');
INSERT INTO "rite_settings" VALUES ('default_slideshow_template', 'slideshow.tpl');
INSERT INTO "rite_settings" VALUES ('location_maxlength', 50);
INSERT INTO "rite_settings" VALUES ('admin_entries_per_page', 20);
INSERT INTO "rite_settings" VALUES ('resize', 640);
INSERT INTO "rite_settings" VALUES ('resize_xy', 'x');
INSERT INTO "rite_settings" VALUES ('compression', 80);
INSERT INTO "rite_settings" VALUES ('session_prefix', 'phpsqlitecms_');
INSERT INTO "rite_settings" VALUES ('default_menu', 'main_menu');
INSERT INTO "rite_settings" VALUES ('smiley_directory', 'images/smilies');
INSERT INTO "rite_settings" VALUES ('comment_smilies', 1);
INSERT INTO "rite_settings" VALUES ('comment_auto_link', 1);
INSERT INTO "rite_settings" VALUES ('content_smilies', 0);
INSERT INTO "rite_settings" VALUES ('content_auto_link', 0);
INSERT INTO "rite_settings" VALUES ('default_description', '');
INSERT INTO "rite_settings" VALUES ('default_keywords', '');
INSERT INTO "rite_settings" VALUES ('akismet_key', '');
INSERT INTO "rite_settings" VALUES ('rss_maximum_items', 20);
INSERT INTO "rite_settings" VALUES ('search_results_per_page', 20);
INSERT INTO "rite_settings" VALUES ('counter_last_resetted', 1249183456);
INSERT INTO "rite_settings" VALUES ('notes_per_page', 10);
INSERT INTO "rite_settings" VALUES ('entries_show_email', 0);
INSERT INTO "rite_settings" VALUES ('mail_parameter', '');
INSERT INTO "rite_settings" VALUES ('base_url', '');
INSERT INTO "rite_settings" VALUES ('default_photos_per_row', 4);
INSERT INTO "rite_settings" VALUES ('version', 2.0);
INSERT INTO "rite_settings" VALUES ('caching', 0);
INSERT INTO "rite_settings" VALUES ('breadcrumbs', 5);
INSERT INTO "rite_settings" VALUES ('slideshow', 0);
INSERT INTO "rite_settings" VALUES ('base_path', '');
INSERT INTO "rite_settings" VALUES ('admin_language_file', 'English.admin.lang.php');
INSERT INTO "rite_settings" VALUES ('default_formatting', 0);
INSERT INTO "rite_settings" VALUES ('akismet_entry_check', 0);
INSERT INTO "rite_settings" VALUES ('akismet_mail_check', 0);
INSERT INTO "rite_settings" VALUES ('prevent_repeated_posts_minutes', 2);
INSERT INTO "rite_settings" VALUES ('comment_remove_blank_lines', 1);
INSERT INTO "rite_settings" VALUES ('admin_auto_clear_cache', 1);
INSERT INTO "rite_settings" VALUES ('check_access_permission', 0);
INSERT INTO "rite_settings" VALUES ('wysiwyg_editor', 1);
INSERT INTO "rite_settings" VALUES ('time_zone', '');
INSERT INTO "rite_settings" VALUES ('simple_news_per_page', 10);
INSERT INTO "rite_settings" VALUES ('global_content_blocks', 1);
INSERT INTO "rite_settings" VALUES ('include_news_items', 3);
INSERT INTO "rite_settings" VALUES ('content_functions', 0);
INSERT INTO "rite_settings" VALUES ('rss_feed', 'rss');
INSERT INTO "rite_settings" VALUES ('email_subject_maxlength', 100);
INSERT INTO "rite_settings" VALUES ('email_text_maxlength', 10000);
INSERT INTO "rite_settings" VALUES ('enable_fullfeeds', 1);
INSERT INTO "rite_settings" VALUES ('pingback_title_maxlength', 60);
INSERT INTO "rite_settings" VALUES ('pingbacks_enabled', 0);
INSERT INTO "rite_settings" VALUES ('lightbox_enabled', 0);
INSERT INTO "rite_settings" VALUES ('thumbnail_compression', 70);
INSERT INTO "rite_settings" VALUES ('thumbnail_postfix', '_thumbnail');
INSERT INTO "rite_settings" VALUES ('thumbnail_prefix', '');
INSERT INTO "rite_settings" VALUES ('thumbnail_resize', 150);
INSERT INTO "rite_settings" VALUES ('thumbnail_resize_xy', 'x');
INSERT INTO "rite_settings" VALUES ('mobile', 'yes');
INSERT INTO "rite_settings" VALUES ('admin_articles_per_page', 20);
INSERT INTO "rite_settings" VALUES ('version_psc', '2.0.4');
COMMIT;
