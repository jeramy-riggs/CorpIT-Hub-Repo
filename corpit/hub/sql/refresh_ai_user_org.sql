-- Rebuild ai_user_org: attribute every email seen in AI cost data to an org node.
--
-- POPULATION WIDENED 2026-09-03. This used to key off claude_user_cost_daily alone,
-- i.e. people who have actually spent. ai_user_org is now also the table every
-- SCOPED view filters through, and a seat-holder with no spend yet is still a member
-- the page lists - so under the old population they were invisible to their own
-- manager while remaining visible to org-wide viewers. Seat roster and the CSV import
-- are unioned in. Attribution is unchanged: the roll-up still reconciles to the
-- invoice, because a zero-spend member contributes zero.
-- NB every branch of the union must alias the column as `email`; without the alias
-- it is named LOWER(email) and any derived-table reference to p.email fails.
-- Tier 1: direct hit in hr_roster.
-- Tier 2: climb entra manager_upn until we land on someone in hr_roster; inherit their leader.
-- Tier 3: unresolved (surfaced, never silently dropped).
START TRANSACTION;
DELETE FROM ai_user_org;

-- Tier 1 --------------------------------------------------------------------
INSERT INTO ai_user_org
  (email, display_name, department, dept_code, manager_email, manager_name,
   leader_email, leader_name, is_contingent, resolution, climb_hops)
-- Email aliasing (2026-09-21): AI data is keyed on the Entra UPN; the HR export may carry the
-- same person under their primary SMTP address (Entra `mail`). Match HR on the UPN first,
-- else on that account's mail. The row is inserted under the canonical (UPN) key.
SELECT p.email, r.employee_name, r.department, r.dept_code,
       r.manager_email, r.manager_name, r.leader_email, r.leader_name,
       r.is_contingent, 'hr', 0
FROM (SELECT DISTINCT LOWER(email) AS email FROM claude_user_cost_daily WHERE email IS NOT NULL AND email<>''
        UNION SELECT DISTINCT LOWER(email) AS email FROM claude_member   WHERE email IS NOT NULL AND email<>''
        UNION SELECT DISTINCT LOWER(email) AS email FROM ai_usage_member WHERE platform='claude' AND email IS NOT NULL AND email<>'') AS p
JOIN hr_roster r
  ON r.email = COALESCE((SELECT r2.email FROM hr_roster r2 WHERE r2.email = p.email LIMIT 1),
                        (SELECT LOWER(e.mail) FROM entra_users e
                          WHERE LOWER(e.user_principal_name) = p.email AND e.mail IS NOT NULL AND e.mail<>'' LIMIT 1));

-- Tier 2 --------------------------------------------------------------------
INSERT INTO ai_user_org
  (email, display_name, department, dept_code, manager_email, manager_name,
   leader_email, leader_name, is_contingent, resolution, climb_hops)
WITH RECURSIVE targets AS (
  SELECT p.email FROM (SELECT DISTINCT LOWER(email) AS email FROM claude_user_cost_daily WHERE email IS NOT NULL AND email<>''
        UNION SELECT DISTINCT LOWER(email) AS email FROM claude_member   WHERE email IS NOT NULL AND email<>''
        UNION SELECT DISTINCT LOWER(email) AS email FROM ai_usage_member WHERE platform='claude' AND email IS NOT NULL AND email<>'') AS p
  WHERE p.email NOT IN (SELECT email FROM ai_user_org)
),
climb AS (
  SELECT t.email AS root, LOWER(n.manager_upn) AS cur, 1 AS hops
  FROM targets t
  JOIN entra_users n ON LOWER(n.user_principal_name)=t.email
  WHERE n.manager_upn IS NOT NULL AND n.manager_upn<>''
  UNION ALL
  SELECT c.root, LOWER(n2.manager_upn), c.hops+1
  FROM climb c
  JOIN entra_users n2 ON LOWER(n2.user_principal_name)=c.cur
  WHERE c.hops < 8
    AND NOT EXISTS (SELECT 1 FROM hr_roster hr WHERE hr.email=c.cur)
    AND n2.manager_upn IS NOT NULL AND n2.manager_upn<>''
),
best AS (
  SELECT c.root, MIN(c.hops) AS hops
  FROM climb c JOIN hr_roster hr ON hr.email=c.cur
  WHERE hr.leader_email IS NOT NULL AND hr.leader_email<>''
  GROUP BY c.root
)
SELECT b.root,
       MAX(COALESCE(NULLIF(en.display_name,''), b.root)),
       MAX(COALESCE(NULLIF(en.department,''), anc.department)),
       MAX(COALESCE(NULLIF(SUBSTRING_INDEX(TRIM(en.department),' ',1),''), anc.dept_code)),
       MAX(LOWER(en.manager_upn)), MAX(anc.employee_name),
       MAX(anc.leader_email), MAX(anc.leader_name),
       0, 'entra-climb', MAX(b.hops)
FROM best b
JOIN climb c   ON c.root=b.root AND c.hops=b.hops
JOIN hr_roster anc ON anc.email=c.cur
LEFT JOIN entra_users en ON LOWER(en.user_principal_name)=b.root
GROUP BY b.root;

-- Tier 3 --------------------------------------------------------------------
INSERT INTO ai_user_org (email, display_name, resolution)
SELECT p.email,
       COALESCE(NULLIF(MAX(m.display_name),''), NULLIF(MAX(c.display_name),''), p.email),
       'unresolved'
FROM (SELECT DISTINCT LOWER(email) AS email FROM claude_user_cost_daily WHERE email IS NOT NULL AND email<>''
        UNION SELECT DISTINCT LOWER(email) AS email FROM claude_member   WHERE email IS NOT NULL AND email<>''
        UNION SELECT DISTINCT LOWER(email) AS email FROM ai_usage_member WHERE platform='claude' AND email IS NOT NULL AND email<>'') AS p
LEFT JOIN claude_member m          ON LOWER(m.email)=p.email
LEFT JOIN claude_user_cost_daily c ON LOWER(c.email)=p.email
WHERE p.email NOT IN (SELECT email FROM ai_user_org)
GROUP BY p.email;

COMMIT;
