-- Extracted CTI schema from your export. For EMPTY databases only.
CREATE TABLE public.actor_campaign (
    actor_id integer NOT NULL,
    campaign_id integer NOT NULL
);

CREATE TABLE public.attachment_hashes (
    incident_id integer NOT NULL,
    attach_no integer NOT NULL,
    hash character varying(255) NOT NULL
);

CREATE TABLE public.attachments (
    incident_id integer NOT NULL,
    attach_no integer NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(100),
    size integer
);

CREATE TABLE public.campaign_objectives (
    campaign_id integer NOT NULL,
    objective text NOT NULL
);

CREATE TABLE public.campaigns (
    campaign_id integer NOT NULL,
    name character varying(150) NOT NULL,
    start_date date,
    end_date date,
    CONSTRAINT campaigns_check CHECK (((end_date IS NULL) OR (end_date >= start_date)))
);

CREATE SEQUENCE public.campaigns_campaign_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.campaigns_campaign_id_seq OWNED BY public.campaigns.campaign_id;

CREATE TABLE public.data_breach_datatypes (
    incident_id integer NOT NULL,
    data_type character varying(255) NOT NULL
);

CREATE TABLE public.data_breaches (
    incident_id integer NOT NULL,
    records_affected bigint,
    data_types text
);

CREATE TABLE public.incident_ioc (
    incident_id integer NOT NULL,
    ioc_id integer NOT NULL
);

CREATE TABLE public.incident_vuln (
    incident_id integer NOT NULL,
    vuln_id integer NOT NULL
);

CREATE TABLE public.incidents (
    incident_id integer NOT NULL,
    incident_type character varying(50) NOT NULL,
    detected_at timestamp without time zone NOT NULL,
    status character varying(30) DEFAULT 'Open'::character varying,
    description text
);

CREATE SEQUENCE public.incidents_incident_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.incidents_incident_id_seq OWNED BY public.incidents.incident_id;

CREATE TABLE public.iocs (
    ioc_id integer NOT NULL,
    type character varying(50) NOT NULL,
    raw_data text NOT NULL,
    encoding_type character varying(50),
    first_seen timestamp without time zone,
    last_seen timestamp without time zone,
    threat_id integer,
    source_id integer
);

CREATE SEQUENCE public.iocs_ioc_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iocs_ioc_id_seq OWNED BY public.iocs.ioc_id;

CREATE TABLE public.m_att_sys (
    incident_id integer NOT NULL,
    sys character varying(255) NOT NULL
);

CREATE TABLE public.malware_incidents (
    incident_id integer NOT NULL,
    malware_name character varying(150),
    malware_family character varying(100)
);

CREATE TABLE public.permissions (
    perm_id integer NOT NULL,
    perm_name character varying(100) NOT NULL,
    description text
);

CREATE SEQUENCE public.permissions_perm_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.permissions_perm_id_seq OWNED BY public.permissions.perm_id;

CREATE TABLE public.roles (
    role_id integer NOT NULL,
    role_name character varying(50) NOT NULL,
    description text
);

CREATE SEQUENCE public.roles_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.roles_role_id_seq OWNED BY public.roles.role_id;

CREATE TABLE public.security_incidents (
    incident_id integer NOT NULL,
    security_category character varying(100),
    severity character varying(20)
);

CREATE TABLE public.source_urls (
    source_id integer NOT NULL,
    url text NOT NULL
);

CREATE TABLE public.sources (
    source_id integer NOT NULL,
    source_name character varying(150) NOT NULL,
    source_type character varying(50),
    reliability_score integer,
    CONSTRAINT sources_reliability_score_check CHECK (((reliability_score >= 0) AND (reliability_score <= 100)))
);

CREATE SEQUENCE public.sources_source_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.sources_source_id_seq OWNED BY public.sources.source_id;

CREATE TABLE public.targets (
    actor_id integer NOT NULL,
    campaign_id integer NOT NULL,
    source_id integer NOT NULL
);

CREATE TABLE public.threat_actor_aliases (
    actor_id integer NOT NULL,
    alias character varying(150) NOT NULL
);

CREATE TABLE public.threat_actors (
    actor_id integer NOT NULL,
    actor_name character varying(150) NOT NULL,
    origin character varying(100)
);

CREATE SEQUENCE public.threat_actors_actor_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.threat_actors_actor_id_seq OWNED BY public.threat_actors.actor_id;

CREATE TABLE public.threats (
    threat_id integer NOT NULL,
    name character varying(150) NOT NULL,
    description text,
    risk_score integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT threats_risk_score_check CHECK (((risk_score >= 0) AND (risk_score <= 100)))
);

CREATE SEQUENCE public.threats_threat_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.threats_threat_id_seq OWNED BY public.threats.threat_id;

CREATE TABLE public.user_phones (
    user_id integer NOT NULL,
    phone character varying(20) NOT NULL
);

CREATE TABLE public.user_role (
    user_id integer NOT NULL,
    role_id integer NOT NULL
);

CREATE TABLE public.users (
    user_id integer NOT NULL,
    name character varying(100) NOT NULL,
    email character varying(150) NOT NULL,
    phone character varying(20),
    first_name character varying(50),
    last_name character varying(50),
    login character varying(100) NOT NULL
);

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;

CREATE TABLE public.vulnerabilities (
    vuln_id integer NOT NULL,
    cve_id character varying(30),
    description text,
    severity character varying(20)
);

CREATE SEQUENCE public.vulnerabilities_vuln_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.vulnerabilities_vuln_id_seq OWNED BY public.vulnerabilities.vuln_id;

ALTER TABLE ONLY public.campaigns ALTER COLUMN campaign_id SET DEFAULT nextval('public.campaigns_campaign_id_seq'::regclass);

ALTER TABLE ONLY public.incidents ALTER COLUMN incident_id SET DEFAULT nextval('public.incidents_incident_id_seq'::regclass);

ALTER TABLE ONLY public.iocs ALTER COLUMN ioc_id SET DEFAULT nextval('public.iocs_ioc_id_seq'::regclass);

ALTER TABLE ONLY public.permissions ALTER COLUMN perm_id SET DEFAULT nextval('public.permissions_perm_id_seq'::regclass);

ALTER TABLE ONLY public.roles ALTER COLUMN role_id SET DEFAULT nextval('public.roles_role_id_seq'::regclass);

ALTER TABLE ONLY public.sources ALTER COLUMN source_id SET DEFAULT nextval('public.sources_source_id_seq'::regclass);

ALTER TABLE ONLY public.threat_actors ALTER COLUMN actor_id SET DEFAULT nextval('public.threat_actors_actor_id_seq'::regclass);

ALTER TABLE ONLY public.threats ALTER COLUMN threat_id SET DEFAULT nextval('public.threats_threat_id_seq'::regclass);

ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);

ALTER TABLE ONLY public.vulnerabilities ALTER COLUMN vuln_id SET DEFAULT nextval('public.vulnerabilities_vuln_id_seq'::regclass);

ALTER TABLE ONLY public.actor_campaign
    ADD CONSTRAINT actor_campaign_pkey PRIMARY KEY (actor_id, campaign_id);

ALTER TABLE ONLY public.attachment_hashes
    ADD CONSTRAINT attachment_hashes_pkey PRIMARY KEY (incident_id, attach_no, hash);

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_pkey PRIMARY KEY (incident_id, attach_no);

ALTER TABLE ONLY public.campaign_objectives
    ADD CONSTRAINT campaign_objectives_pkey PRIMARY KEY (campaign_id, objective);

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_name_key UNIQUE (name);

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_pkey PRIMARY KEY (campaign_id);

ALTER TABLE ONLY public.data_breach_datatypes
    ADD CONSTRAINT data_breach_datatypes_pkey PRIMARY KEY (incident_id, data_type);

ALTER TABLE ONLY public.data_breaches
    ADD CONSTRAINT data_breaches_pkey PRIMARY KEY (incident_id);

ALTER TABLE ONLY public.incident_ioc
    ADD CONSTRAINT incident_ioc_pkey PRIMARY KEY (incident_id, ioc_id);

ALTER TABLE ONLY public.incident_vuln
    ADD CONSTRAINT incident_vuln_pkey PRIMARY KEY (incident_id, vuln_id);

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (incident_id);

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT iocs_pkey PRIMARY KEY (ioc_id);

ALTER TABLE ONLY public.m_att_sys
    ADD CONSTRAINT m_att_sys_pkey PRIMARY KEY (incident_id, sys);

ALTER TABLE ONLY public.malware_incidents
    ADD CONSTRAINT malware_incidents_pkey PRIMARY KEY (incident_id);

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_perm_name_key UNIQUE (perm_name);

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (perm_id);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (role_name);

ALTER TABLE ONLY public.security_incidents
    ADD CONSTRAINT security_incidents_pkey PRIMARY KEY (incident_id);

ALTER TABLE ONLY public.source_urls
    ADD CONSTRAINT source_urls_pkey PRIMARY KEY (source_id, url);

ALTER TABLE ONLY public.sources
    ADD CONSTRAINT sources_pkey PRIMARY KEY (source_id);

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (actor_id, campaign_id, source_id);

ALTER TABLE ONLY public.threat_actor_aliases
    ADD CONSTRAINT threat_actor_aliases_pkey PRIMARY KEY (actor_id, alias);

ALTER TABLE ONLY public.threat_actors
    ADD CONSTRAINT threat_actors_actor_name_key UNIQUE (actor_name);

ALTER TABLE ONLY public.threat_actors
    ADD CONSTRAINT threat_actors_pkey PRIMARY KEY (actor_id);

ALTER TABLE ONLY public.threats
    ADD CONSTRAINT threats_pkey PRIMARY KEY (threat_id);

ALTER TABLE ONLY public.user_phones
    ADD CONSTRAINT user_phones_pkey PRIMARY KEY (user_id, phone);

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_pkey PRIMARY KEY (user_id, role_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_login_key UNIQUE (login);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_cve_id_key UNIQUE (cve_id);

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (vuln_id);

ALTER TABLE ONLY public.threat_actor_aliases
    ADD CONSTRAINT fk_actor_alias FOREIGN KEY (actor_id) REFERENCES public.threat_actors(actor_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.actor_campaign
    ADD CONSTRAINT fk_actor_campaign_actor FOREIGN KEY (actor_id) REFERENCES public.threat_actors(actor_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.actor_campaign
    ADD CONSTRAINT fk_actor_campaign_campaign FOREIGN KEY (campaign_id) REFERENCES public.campaigns(campaign_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.attachment_hashes
    ADD CONSTRAINT fk_attachment_hash FOREIGN KEY (incident_id, attach_no) REFERENCES public.attachments(incident_id, attach_no) ON DELETE CASCADE;

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT fk_attachment_incident FOREIGN KEY (incident_id) REFERENCES public.incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.data_breach_datatypes
    ADD CONSTRAINT fk_breach_datatype FOREIGN KEY (incident_id) REFERENCES public.data_breaches(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.campaign_objectives
    ADD CONSTRAINT fk_campaign_objective FOREIGN KEY (campaign_id) REFERENCES public.campaigns(campaign_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.data_breaches
    ADD CONSTRAINT fk_data_breach_incident FOREIGN KEY (incident_id) REFERENCES public.incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.incident_ioc
    ADD CONSTRAINT fk_incident_ioc_incident FOREIGN KEY (incident_id) REFERENCES public.incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.incident_ioc
    ADD CONSTRAINT fk_incident_ioc_ioc FOREIGN KEY (ioc_id) REFERENCES public.iocs(ioc_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.incident_vuln
    ADD CONSTRAINT fk_incident_vuln_incident FOREIGN KEY (incident_id) REFERENCES public.incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.incident_vuln
    ADD CONSTRAINT fk_incident_vuln_vulnerability FOREIGN KEY (vuln_id) REFERENCES public.vulnerabilities(vuln_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT fk_ioc_source FOREIGN KEY (source_id) REFERENCES public.sources(source_id) ON DELETE SET NULL;

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT fk_ioc_threat FOREIGN KEY (threat_id) REFERENCES public.threats(threat_id) ON DELETE SET NULL;

ALTER TABLE ONLY public.m_att_sys
    ADD CONSTRAINT fk_m_att_sys_incident FOREIGN KEY (incident_id) REFERENCES public.malware_incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.malware_incidents
    ADD CONSTRAINT fk_malware_incident FOREIGN KEY (incident_id) REFERENCES public.incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.security_incidents
    ADD CONSTRAINT fk_security_incident FOREIGN KEY (incident_id) REFERENCES public.incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.source_urls
    ADD CONSTRAINT fk_source_url FOREIGN KEY (source_id) REFERENCES public.sources(source_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT fk_targets_actor FOREIGN KEY (actor_id) REFERENCES public.threat_actors(actor_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT fk_targets_campaign FOREIGN KEY (campaign_id) REFERENCES public.campaigns(campaign_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT fk_targets_source FOREIGN KEY (source_id) REFERENCES public.sources(source_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_phones
    ADD CONSTRAINT fk_user_phone FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;
