-- Logoff event triggers
CREATE TABLE user_logoffs(id serial, who text);
GRANT SELECT ON user_logoffs TO public;
CREATE FUNCTION on_logoff_proc() RETURNS event_trigger AS $$
BEGIN
  INSERT INTO user_logoffs (who) VALUES (SESSION_USER);
END;
$$ LANGUAGE plpgsql;
CREATE EVENT TRIGGER on_logoff_trigger ON logoff EXECUTE FUNCTION on_logoff_proc();
ALTER EVENT TRIGGER on_logoff_trigger ENABLE ALWAYS;
\c
-- Is it enough to wait 100ms to let the logoff event trigger execute?
SELECT pg_sleep(0.1);
SELECT COUNT(*) FROM user_logoffs;
\c
SELECT pg_sleep(0.1);
SELECT COUNT(*) FROM user_logoffs;

-- Check dathaslogoffevt in system catalog
SELECT dathaslogoffevt FROM pg_database WHERE datname = :'DBNAME';

-- Cleanup
DROP TABLE user_logoffs;
DROP EVENT TRIGGER on_logoff_trigger;
DROP FUNCTION on_logoff_proc();
\c
