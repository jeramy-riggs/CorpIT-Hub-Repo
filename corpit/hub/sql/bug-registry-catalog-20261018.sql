-- DEV catalog metadata reconciliation; no bug submission or permission changes.
START TRANSACTION;
UPDATE app_registry SET app_name='Asset Inventory',app_url='/IT_Inventory_App.html' WHERE app_key='inventory';
INSERT INTO app_registry (app_key,app_name,app_url,current_version,description,category,is_active) VALUES ('patch-status','Intune Health','/patch-status.html','','Review Windows updates, Defender, reboot needs, app failures and Intune device health.','Dashboards',1);
UPDATE app_registry SET app_name='People & Devices',app_url='/identity-diag.html' WHERE app_key='identity-diag';
INSERT INTO app_registry (app_key,app_name,app_url,current_version,description,category,is_active) VALUES ('access-portal','Access Portal','https://dev-accessportal.nrpi.local/','','Submit access, AI-tool and security-exception requests.','Identity',1);
INSERT INTO app_registry (app_key,app_name,app_url,current_version,description,category,is_active) VALUES ('ai-usage-credits','AI Usage & Credits','https://dev-reporting.nrpi.local/ai-usage-credits.html','','Track shared AI service usage, credit balances & per-user spend.','Dashboards',1);
UPDATE app_registry SET app_name='Okta–Entra Migration',app_url='/okta-entra-migration.html' WHERE app_key='okta-entra-migration';
INSERT INTO app_registry (app_key,app_name,app_url,current_version,description,category,is_active) VALUES ('ai-governance','AI Governance','/ai-governance.html','','Review AI inventory, usage, ownership, access, risks and governance work.','Dashboards',1);
UPDATE app_registry SET app_name='Network Operations',app_url='/network-health.html' WHERE app_key='network-health';
UPDATE app_registry SET app_name='Server Health',app_url='https://dev-subadmin.nrpi.local/operations' WHERE app_key='server-health';
UPDATE app_registry SET app_name='Service Desk Portal',app_url='/service-desk-portal.html' WHERE app_key='service-desk-portal';
INSERT INTO app_registry (app_key,app_name,app_url,current_version,description,category,is_active) VALUES ('it-command-quickstart','IT Quick Start','/it-command-quickstart.html','','What each tool does & when to use it.','Platform',1);
COMMIT;
