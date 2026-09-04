-- Run as a PostgreSQL superuser once.  The application role owns only its DB;
-- it has no cluster-wide role-management, replication or bypass-RLS rights.
CREATE ROLE vulnerability_lookup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE vulnerability_lookup OWNER vulnerability_lookup
  ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE vulnerability_lookup FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE vulnerability_lookup TO vulnerability_lookup;

