CREATE TABLE `virustotals` (
      `id` int(11) NOT NULL auto_increment,
      `shasum` varchar(64) NOT NULL,
      `url` text,
      `timestamp` datetime NOT NULL,
      `permalink` varchar(120) NOT NULL,
      PRIMARY KEY  (`id`),
      KEY `virustotals_shasum` (`shasum`)
) ;

CREATE TABLE `virustotalscans` (
      `id` int(11) NOT NULL auto_increment,
      `scan_id` int(11) NOT NULL,
      `scanner` varchar( 32 ) NOT NULL,
      `result` varchar(64),
      PRIMARY KEY  (`id`),
      FOREIGN KEY (`scan_id`) REFERENCES virustotals (`id`),
      KEY `virustotalscans_scan_id` (`scan_id`),
      KEY `virustotalscans_scanner` (`scanner`),
      KEY `virustotalscans_result`  (`result`)
) ;
