CREATE TABLE `auth` (
  `id` int(11) NOT NULL auto_increment,
  `session` char(32) NOT NULL,
  `success` tinyint(1) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE `clients` (
  `id` int(4) NOT NULL auto_increment,
  `version` varchar(50) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE `input` (
  `id` int(11) NOT NULL auto_increment,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `realm` varchar(50) default NULL,
  `success` tinyint(1) default NULL,
  `input` text NOT NULL,
  PRIMARY KEY  (`id`),
  KEY `session` (`session`,`timestamp`,`realm`)
) ;

CREATE TABLE `sensors` (
  `id` int(11) NOT NULL auto_increment,
  `ip` varchar(15) NOT NULL,
  PRIMARY KEY  (`id`)
) ;

CREATE TABLE `sessions` (
  `id` char(32) NOT NULL,
  `starttime` datetime NOT NULL,
  `endtime` datetime default NULL,
  `sensor` int(4) NOT NULL,
  `ip` varchar(15) NOT NULL default '',
  `termsize` varchar(7) default NULL,
  `client` int(4) default NULL,
  PRIMARY KEY  (`id`),
  KEY `starttime` (`starttime`,`sensor`)
) ;

CREATE TABLE `downloads` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR( 32 ) NOT NULL,
  `timestamp` datetime NOT NULL,
  `url` text NOT NULL,
  `outfile` text NOT NULL,
  `shasum` varchar(64) default NULL,
  PRIMARY KEY  (`id`),
  KEY `session` (`session`,`timestamp`)
) ;

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
