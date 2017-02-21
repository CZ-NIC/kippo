DROP TABLE IF EXISTS downloads;
DROP TABLE IF EXISTS sensors;
DROP TABLE IF EXISTS input;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS auth;
DROP TABLE IF EXISTS sessions;

CREATE TABLE IF NOT EXISTS auth (
  id BIGSERIAL PRIMARY KEY NOT NULL,
  session char(32) NOT NULL,
  success smallint NOT NULL,
  username varchar(100) NOT NULL,
  password varchar(256) NOT NULL,
  timestamp timestamp NOT NULL
) ;

CREATE TABLE IF NOT EXISTS clients (
  id SERIAL NOT NULL PRIMARY KEY,
  version varchar(50) NOT NULL
) ;

CREATE TABLE IF NOT EXISTS sessions (
  ord_id BIGSERIAL PRIMARY KEY NOT NULL,
  id char(32) NOT NULL UNIQUE,
  starttime timestamp NOT NULL,
  endtime timestamp default NULL,
  sensor smallint NOT NULL,
  ip inet NULL default NULL,
  termsize varchar(7) default NULL,
  client smallint default NULL,
  port INTEGER NULL DEFAULT NULL
) ;

CREATE INDEX sessions_ord_id_i
ON sessions (ord_id);

CREATE INDEX sessions_starttime_i
ON sessions (starttime);

CREATE TABLE IF NOT EXISTS input (
  id BIGSERIAL PRIMARY KEY NOT NULL,
  session char(32) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  timestamp timestamp NOT NULL,
  realm varchar(50) default NULL,
  success smallint default NULL,
  input text NOT NULL
) ;

CREATE INDEX input_session_i
ON input(session);

CREATE INDEX input_timestamp_i
ON input(timestamp);

CREATE TABLE IF NOT EXISTS sensors (
  id SERIAL PRIMARY KEY NOT NULL,
  ip varchar(15) NOT NULL
) ;

CREATE TABLE IF NOT EXISTS downloads (
  id BIGSERIAL PRIMARY KEY NOT NULL,
  session CHAR( 32 ) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  timestamp timestamp NOT NULL,
  url text NOT NULL,
  outfile text NOT NULL,
  shasum varchar(64) default NULL
) ;

CREATE INDEX downloads_session_i
ON downloads(session);

CREATE INDEX downloads_timestamp_i
ON downloads(timestamp);
